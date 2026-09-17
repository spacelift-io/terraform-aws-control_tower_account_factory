# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict

from aft_common import ddb
from aft_common.aft_utils import sanitize_input_for_logging
from aft_common.auth import AuthClient
from aft_common.constants import SSM_PARAM_AFT_DDB_CUSTOMIZATIONS_AUDIT_TABLE
from aft_common.logger import configure_aft_logger, customization_request_logger
from aft_common.ssm import get_ssm_parameter_value

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
else:
    LambdaContext = object

configure_aft_logger()
logger = logging.getLogger("aft")


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Write an audit record for each aft-invoke-customizations SFN execution."""
    auth = AuthClient()
    try:
        session = auth.get_aft_management_session()

        table_name = get_ssm_parameter_value(
            session, SSM_PARAM_AFT_DDB_CUSTOMIZATIONS_AUDIT_TABLE
        )

        execution_id = event.get("get_execution_id", {}).get("execution_id", "unknown")
        targets = event.get("targets", {})
        target_accounts = targets.get("pending_accounts", [])
        bypass_steps = event.get("bypass_steps", [])
        customization_triggers = event.get("customization_triggers", [])
        customization_request_id = event.get("customization_request_id", "")

        if customization_triggers:
            trigger_source = "account_move"
        elif bypass_steps:
            trigger_source = "manual"
        else:
            trigger_source = "account_request"

        item = {
            "execution_id": execution_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_accounts": target_accounts,
            "bypass_steps": bypass_steps,
            "customization_triggers": customization_triggers,
            "trigger_source": trigger_source,
            "customization_request_id": customization_request_id,
        }

        ddb.put_ddb_item(session, table_name, item)

        # Log the bridge: links customization_request_id to this SFN execution
        if customization_request_id:
            target_account_id = target_accounts[0] if target_accounts else "unknown"
            req_logger = customization_request_logger(
                aws_account_id=target_account_id,
                customization_request_id=customization_request_id,
            )
            req_logger.info(
                f"Customizations SFN execution {sanitize_input_for_logging(execution_id)} "
                f"linked to provisioning request {sanitize_input_for_logging(customization_request_id)} "
                f"(trigger: {trigger_source})"
            )

        return {"status": "recorded", "execution_id": execution_id}

    except Exception as e:
        logger.warning(f"Audit record failed: {sanitize_input_for_logging(str(e))}")
        return {"status": "skipped", "error": str(e)}
