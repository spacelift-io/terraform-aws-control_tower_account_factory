#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import io
import os
import time

import boto3
import terraform_client as terraform


def setup_and_run_workspace(
    organization_name,
    workspace_name,
    assume_role_arn,
    role_session_name,
    api_token,
    project_name,
    hcp_oidc_enabled,
    hcp_oidc_audience,
):
    workspace_id = setup_workspace(
        organization_name,
        workspace_name,
        assume_role_arn,
        role_session_name,
        api_token,
        project_name,
        hcp_oidc_enabled,
        hcp_oidc_audience,
    )
    run_id = stage_run(
        workspace_id, assume_role_arn, role_session_name, api_token, hcp_oidc_enabled
    )
    return run_id


def setup_workspace(
    organization_name,
    workspace_name,
    assume_role_arn,
    role_session_name,
    api_token,
    project_name,
    hcp_oidc_enabled,
    hcp_oidc_audience,
):
    workspace_id = terraform.create_workspace(
        organization_name, workspace_name, api_token, project_name
    )
    print(
        "Successfully created workspace {} with ID {}".format(
            workspace_name, workspace_id
        )
    )

    if hcp_oidc_enabled:
        set_oidc_configuration(
            workspace_id, assume_role_arn, api_token, hcp_oidc_audience
        )
        print("Successfully enabled OIDC on workspace for {}".format(assume_role_arn))
    else:
        set_aws_credentials(workspace_id, assume_role_arn, role_session_name, api_token)
        print(
            "Successfully placed AWS credentials on workspace for {}".format(
                assume_role_arn
            )
        )

    return workspace_id


def stage_run(
    workspace_id, assume_role_arn, role_session_name, api_token, hcp_oidc_enabled
):
    cv_id, upload_url = terraform.create_configuration_version(workspace_id, api_token)
    print("Successfully created a new configuration version: {}".format(cv_id))
    with open(LOCAL_CONFIGURATION_PATH, "rb") as file:
        data = file.read()
    terraform.upload_configuration_content(data, upload_url)
    print(
        "Successfully uploaded configuration content to upload URL: {}".format(
            upload_url
        )
    )
    terraform.wait_to_stabilize(
        "configuration-versions", cv_id, ["uploaded"], api_token
    )

    # When OIDC is enabled we do not need to set workspaces vars with STS creds
    if not hcp_oidc_enabled:
        set_aws_credentials(workspace_id, assume_role_arn, role_session_name, api_token)
        print(
            "Successfully placed AWS credentials on workspace for {}".format(
                assume_role_arn
            )
        )

    run_id = terraform.create_run(workspace_id, cv_id, api_token)
    print("Successfully created run: {}".format(run_id))
    terraform.wait_to_stabilize(
        "runs",
        run_id,
        [
            "applied",
            "planned_and_finished",
            "errored",
            "discarded",
            "canceled",
        ],
        api_token,
    )
    return run_id


def set_oidc_configuration(workspace_id, assume_role_arn, api_token, hcp_oidc_audience):
    current_vars = terraform.get_workspace_vars(workspace_id, api_token)
    transformed_current_vars_dict = __transform_workspace_vars(current_vars)

    # Cleanup unwanted vars if enabling OIDC for first time
    for secret_var in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ]:

        if secret_var in transformed_current_vars_dict:
            terraform.delete_environment_variable(
                transformed_current_vars_dict[secret_var],
                workspace_id,
                api_token,
            )
            print("OIDC enabled, removed var {}".format(secret_var))

    if "TFC_AWS_PROVIDER_AUTH" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["TFC_AWS_PROVIDER_AUTH"],
            "TFC_AWS_PROVIDER_AUTH",
            "true",  # enable OIDC
            "Enable OIDC",
            workspace_id,
            False,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "TFC_AWS_PROVIDER_AUTH",
            "true",  # enable OIDC
            "Enable OIDC",
            workspace_id,
            False,
            "env",
            api_token,
        )

    if "TFC_AWS_WORKLOAD_IDENTITY_AUDIENCE" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["TFC_AWS_WORKLOAD_IDENTITY_AUDIENCE"],
            "TFC_AWS_WORKLOAD_IDENTITY_AUDIENCE",
            hcp_oidc_audience,
            "AWS Identity Audience",
            workspace_id,
            False,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "TFC_AWS_WORKLOAD_IDENTITY_AUDIENCE",
            hcp_oidc_audience,
            "AWS Identity Audience",
            workspace_id,
            False,
            "env",
            api_token,
        )

    if "TFC_AWS_RUN_ROLE_ARN" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["TFC_AWS_RUN_ROLE_ARN"],
            "TFC_AWS_RUN_ROLE_ARN",
            assume_role_arn,  # OIDC role
            "AWS run role arn",
            workspace_id,
            False,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "TFC_AWS_RUN_ROLE_ARN",
            assume_role_arn,  # OIDC role
            "AWS run role arn",
            workspace_id,
            False,
            "env",
            api_token,
        )


def set_aws_credentials(workspace_id, assume_role_arn, role_session_name, api_token):
    role_credentials = __assume_role(assume_role_arn, role_session_name)
    current_vars = terraform.get_workspace_vars(workspace_id, api_token)
    transformed_current_vars_dict = __transform_workspace_vars(current_vars)

    # Cleanup unwanted vars if disabling OIDC
    for secret_var in [
        "TFC_AWS_PROVIDER_AUTH",
        "TFC_AWS_RUN_ROLE_ARN",
        "TFC_AWS_WORKLOAD_IDENTITY_AUDIENCE",
    ]:

        if secret_var in transformed_current_vars_dict:
            terraform.delete_environment_variable(
                transformed_current_vars_dict[secret_var],
                workspace_id,
                api_token,
            )
            print("OIDC not enabled, removed var {}".format(secret_var))

    if "AWS_ACCESS_KEY_ID" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["AWS_ACCESS_KEY_ID"],
            "AWS_ACCESS_KEY_ID",
            role_credentials["AccessKeyId"],
            "AWS access key",
            workspace_id,
            False,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "AWS_ACCESS_KEY_ID",
            role_credentials["AccessKeyId"],
            "AWS access key",
            workspace_id,
            False,
            "env",
            api_token,
        )

    if "AWS_SECRET_ACCESS_KEY" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["AWS_SECRET_ACCESS_KEY"],
            "AWS_SECRET_ACCESS_KEY",
            role_credentials["SecretAccessKey"],
            "AWS secret access key",
            workspace_id,
            True,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "AWS_SECRET_ACCESS_KEY",
            role_credentials["SecretAccessKey"],
            "AWS secret access key",
            workspace_id,
            True,
            "env",
            api_token,
        )

    if "AWS_SESSION_TOKEN" in transformed_current_vars_dict:
        terraform.update_environment_variable(
            transformed_current_vars_dict["AWS_SESSION_TOKEN"],
            "AWS_SESSION_TOKEN",
            role_credentials["SessionToken"],
            "AWS session token",
            workspace_id,
            True,
            "env",
            api_token,
        )
    else:
        terraform.set_environment_variable(
            "AWS_SESSION_TOKEN",
            role_credentials["SessionToken"],
            "AWS session token",
            workspace_id,
            True,
            "env",
            api_token,
        )


def set_terraform_variables(workspace_id, input_variables, api_token):
    if input_variables is None:
        return
    current_vars = terraform.get_workspace_vars(workspace_id, api_token)
    transformed_current_vars_dict = __transform_workspace_vars(current_vars)
    print(input_variables)
    for key in input_variables:
        value = input_variables[key]
        print("Processing terraform variable {} with value {}".format(key, value))
        if key not in transformed_current_vars_dict:
            terraform.set_environment_variable(
                key,
                value,
                "Terraform input variable set by AFT",
                workspace_id,
                False,
                "terraform",
                api_token,
            )
        else:
            terraform.update_environment_variable(
                transformed_current_vars_dict[key],
                key,
                value,
                "Terraform input variable set by AFT",
                workspace_id,
                False,
                "terraform",
                api_token,
            )


def stage_destroy(
    workspace_id, assume_role_arn, assume_role_session_name, api_token, hcp_oidc_enabled
):
    # When OIDC is enabled we do not need to set workspaces vars with STS creds
    if not hcp_oidc_enabled:
        set_aws_credentials(
            workspace_id, assume_role_arn, assume_role_session_name, api_token
        )

    run_id = terraform.create_destroy_run(workspace_id, api_token)
    # If in a Run there is no resource change, after execution it will be 'planned_and_finished', which can be a stabilized state
    terraform.wait_to_stabilize(
        "runs",
        run_id,
        ["applied", "planned_and_finished", "errored", "discarded", "canceled"],
        api_token,
    )
    return run_id


def delete_workspace(
    organization_name,
    workspace_name,
    assume_role_arn,
    assume_role_session_name,
    api_token,
    hcp_oidc_enabled,
):
    workspace_id = terraform.check_workspace_exists(
        organization_name, workspace_name, api_token
    )
    if workspace_id:
        stage_destroy(
            workspace_id,
            assume_role_arn,
            assume_role_session_name,
            api_token,
            hcp_oidc_enabled,
        )
        terraform.delete_workspace(workspace_id, api_token)
    else:
        print(
            "Selected workspace {} doesnot exist. Deletion of workspace not completed".format(
                workspace_name
            )
        )


def __assume_role(assume_role_arn, role_session_name):
    sts = boto3.client("sts")
    response = sts.assume_role(
        RoleArn=assume_role_arn, RoleSessionName=role_session_name
    )
    return response["Credentials"]


def __transform_workspace_vars(workspace_vars):
    vars_dict = {}
    for var in workspace_vars:
        vars_dict[var["attributes"]["key"]] = var["id"]
    return vars_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script to create a new workspace with valid AWS credentials in the specified organization"
    )
    parser.add_argument("--operation", type=str, help="Name of the method to call")
    parser.add_argument(
        "--organization_name",
        type=str,
        help="Name of the organization in which the workspace should be created",
    )
    parser.add_argument(
        "--workspace_name", type=str, help="Name of the workspace to be created"
    )
    parser.add_argument(
        "--assume_role_arn", type=str, help="IAM Role ARN to be used by the workspace"
    )
    parser.add_argument(
        "--assume_role_session_name",
        type=str,
        help="IAM Role ARN to be used by the workspace",
    )
    parser.add_argument("--api_endpoint", type=str, help="Terraform API endpoint")
    parser.add_argument("--api_token", type=str, help="Terraform API token")
    parser.add_argument("--terraform_version", type=str, help="Terraform Version")
    parser.add_argument("--config_file", type=str, help="Terraform Config File")
    parser.add_argument("--project_name", type=str, help="Name of the TFE project name")
    parser.add_argument("--hcp_oidc_enabled", type=str, help="HCP OIDC is enabled")
    parser.add_argument("--hcp_oidc_audience", type=str, help="HCP OIDC audience")

    args = parser.parse_args()

    TERRAFORM_API_ENDPOINT = args.api_endpoint
    LOCAL_CONFIGURATION_PATH = args.config_file
    TERRAFORM_VERSION = args.terraform_version

    terraform.init(TERRAFORM_API_ENDPOINT, TERRAFORM_VERSION, LOCAL_CONFIGURATION_PATH)

    if args.operation == "delete":
        delete_workspace(
            args.organization_name,
            args.workspace_name,
            args.assume_role_arn,
            args.assume_role_session_name,
            args.api_token,
            (args.hcp_oidc_enabled == "true"),
        )
    elif args.operation == "deploy":
        setup_and_run_workspace(
            args.organization_name,
            args.workspace_name,
            args.assume_role_arn,
            args.assume_role_session_name,
            args.api_token,
            args.project_name,
            (args.hcp_oidc_enabled == "true"),
            args.hcp_oidc_audience,
        )
