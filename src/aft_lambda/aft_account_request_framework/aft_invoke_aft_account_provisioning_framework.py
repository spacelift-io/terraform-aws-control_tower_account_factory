# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
import inspect
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List

from aft_common import ddb
from aft_common.account_provisioning_framework import ProvisionRoles
from aft_common.account_request_framework import (
    build_account_customization_payload,
    get_account_request_record,
)
from aft_common.aft_utils import (
    invoke_step_function,
    is_aft_supported_controltower_event,
    sanitize_input_for_logging,
)
from aft_common.auth import AuthClient
from aft_common.constants import (
    SSM_PARAM_AFT_CUSTOMIZATION_TRIGGERS,
    SSM_PARAM_AFT_DDB_META_TABLE,
    SSM_PARAM_AFT_DDB_REQ_TABLE,
    SSM_PARAM_AFT_SFN_NAME,
    TRIGGER_TOKEN_MAP,
)
from aft_common.logger import configure_aft_logger
from aft_common.notifications import send_lambda_failure_sns_message
from aft_common.organizations import OrganizationsAgent
from aft_common.ssm import get_ssm_parameter_value
from boto3.session import Session

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
else:
    LambdaContext = object

configure_aft_logger()
logger = logging.getLogger("aft")


def detect_customization_triggers(
    aft_management_session: Session,
    event_name: str,
    account_id: str,
    account_email: str,
    new_parent_id: str,
) -> List[Any]:
    """Detect OU changes and return list of triggered tokens with context."""
    try:
        if event_name != "UpdateManagedAccount":
            return []

        if not new_parent_id:
            return []

        triggers_param = get_ssm_parameter_value(
            aft_management_session,
            SSM_PARAM_AFT_CUSTOMIZATION_TRIGGERS,
        )
        configured_triggers = json.loads(triggers_param) if triggers_param else []
        if not configured_triggers:
            return []

        # Check if account_move is in the configured triggers list
        account_move_token = TRIGGER_TOKEN_MAP.get("ManagedOrganizationalUnit")
        if account_move_token is None or account_move_token not in configured_triggers:
            return []

        metadata_table_name = get_ssm_parameter_value(
            aft_management_session, SSM_PARAM_AFT_DDB_META_TABLE
        )
        metadata_item = ddb.get_ddb_item(
            session=aft_management_session,
            table_name=metadata_table_name,
            primary_key={"id": account_id},
        )
        if metadata_item is None:
            return []

        old_parent_ou = metadata_item.get("parent_ou", "")
        if old_parent_ou == new_parent_id:
            return []

        request_table_name = get_ssm_parameter_value(
            aft_management_session, SSM_PARAM_AFT_DDB_REQ_TABLE
        )
        request_item = ddb.get_ddb_item(
            session=aft_management_session,
            table_name=request_table_name,
            primary_key={"id": account_email},
        )
        if request_item:
            skip = request_item.get("account_skip_customization_triggers", "false")
            if str(skip).lower() == "true":
                return []

        logger.info(
            f"OU change detected for {sanitize_input_for_logging(account_id)}: "
            f"{sanitize_input_for_logging(old_parent_ou)} -> {sanitize_input_for_logging(new_parent_id)}"
        )
        return [
            {
                "type": account_move_token,
                "old_parent": old_parent_ou,
                "new_parent": new_parent_id,
            }
        ]

    except Exception as e:
        logger.warning(
            f"Trigger detection failed, proceeding without triggers: "
            f"{sanitize_input_for_logging(str(e))}"
        )
        return []


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> None:
    auth = AuthClient()

    try:
        aft_management_session = auth.get_aft_management_session()
        ct_management_session = auth.get_ct_management_session(
            role_name=ProvisionRoles.SERVICE_ROLE_NAME
        )
        orgs_agent = OrganizationsAgent(ct_management_session)

        control_tower_event = (
            {}
        )  # Unused by AFT, kept for backwards compability for use by aft-account-provisioning-customizations
        if is_aft_supported_controltower_event(event):
            control_tower_event = event

            logger.info("Control Tower Event Detected")

            # Get account ID from CT event
            # Different CT events have different data structures - map them for easier access
            event_name_to_event_detail_key_map = {
                "CreateManagedAccount": "createManagedAccountStatus",
                "UpdateManagedAccount": "updateManagedAccountStatus",
            }
            event_name = event["detail"]["eventName"]
            account_id = event["detail"]["serviceEventDetails"][
                event_name_to_event_detail_key_map[event_name]
            ]["account"]["accountId"]

            # CT events do not contain email, which is PK of DDB table
            account_email = orgs_agent.get_account_email_from_id(account_id=account_id)
            account_request = get_account_request_record(
                aft_management_session, account_email
            )

        elif "account_request" in event:
            logger.info("Account Customizations Event Detected")

            # Customization-only event does not contain ID
            # Contains OU, and if OU-move was requested, would be completed
            # by this step, so can optimize with OU-only search
            account_request = event["account_request"]
            account_ou = account_request["control_tower_parameters"][
                "ManagedOrganizationalUnit"
            ]
            account_id = orgs_agent.get_account_id_from_email(
                email=event["account_request"][
                    "id"
                ],  # `id` field of ddb table is the account email
                ou_name=account_ou,
            )

        else:
            raise RuntimeError("Invoked with unrecognized event type")

        account_customization_payload = build_account_customization_payload(
            ct_management_session=ct_management_session,
            account_id=account_id,
            account_request=account_request,
            control_tower_event=control_tower_event,
        )

        # Detect OU change and enrich payload with customization triggers
        if is_aft_supported_controltower_event(event):
            new_parent_id = (
                account_customization_payload.get("account_info", {})  # type: ignore[call-overload]
                .get("account", {})
                .get("parent_id", "")
            )

            customization_triggers = detect_customization_triggers(
                aft_management_session=aft_management_session,
                event_name=event_name,
                account_id=account_id,
                account_email=account_email,
                new_parent_id=new_parent_id,
            )

            if customization_triggers:
                account_customization_payload["customization_triggers"] = (
                    customization_triggers
                )

        invoke_step_function(
            aft_management_session,
            get_ssm_parameter_value(aft_management_session, SSM_PARAM_AFT_SFN_NAME),
            json.dumps(account_customization_payload),
        )

    except Exception as error:
        send_lambda_failure_sns_message(
            session=aft_management_session,
            message=str(error),
            context=context,
            subject="AFT account request failed",
        )
        message = {
            "FILE": __file__.split("/")[-1],
            "METHOD": inspect.stack()[0][3],
            "EXCEPTION": str(error),
        }
        logger.exception(message)
        raise
