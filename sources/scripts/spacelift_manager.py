#!/usr/bin/python
# Copyright Spacelift, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import logging
import os
import spacelift_client as spacelift

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def ensure_space_exists(space_name, parent_space_id):
    """
    Check if space exists by name. If not exists, create it.
    Returns space ID.
    """
    space_id = spacelift.get_space_by_name(space_name, parent_space_id)
    if space_id:
        logger.info("Space %s already exists with ID %s", space_name, space_id)
        return space_id

    space_id = spacelift.create_space(
        space_name, parent_space_id, description="AFT-managed space for account provisioning"
    )
    logger.info("Successfully created space %s with ID %s", space_name, space_id)
    return space_id


def ensure_aws_integration_exists(
    space_id,
    integration_name,
    role_arn,
    duration_seconds=3600
):
    """
    Check if AWS integration exists by name. If not exists, create it.
    Returns integration ID.
    """
    integration_id = spacelift.get_aws_integration_by_name(integration_name, space_id)
    if integration_id:
        logger.info("AWS integration %s already exists with ID %s (space_id=%s)", 
                   integration_name, integration_id, space_id)
        return integration_id
    
    integration_id = spacelift.create_aws_integration(
        space_id=space_id,
        name=integration_name,
        role_arn=role_arn,
        duration_seconds=duration_seconds
    )
    logger.info("Successfully created AWS integration %s with ID %s (space_id=%s)", 
               integration_name, integration_id, space_id)
    return integration_id


def ensure_stack_exists(
    space_id,
    stack_name,
    repository,
    namespace,
    branch,
    project_root,
    vendor,
    provider,
    description=None,
    integration_id=None,
):
    """
    Check if stack exists. If not exists, create it pointing to external Git repository.
    Returns stack_id.
    
    Args:
        space_id: ID of the space to create stack in
        stack_name: Name for the stack
        repository: Git repository name (e.g., "aft-account-request")
        namespace: Git namespace/owner (e.g., "my-org" or AWS account ID for CodeCommit)
        branch: Git branch to track
        project_root: Project root path within repo
        vendor: IaC vendor (TERRAFORM_FOSS or OPEN_TOFU)
        provider: VCS provider (GITHUB, GITLAB, BITBUCKET_CLOUD, CODECOMMIT, etc.)
        description: Optional stack description
        integration_id: Optional AWS integration ID to attach to stack
    
    Returns:
        stack_id: ID of the stack
    """
    stack_id = spacelift.get_stack_by_name(stack_name, space_id)
    if stack_id:
        logger.info("Stack %s already exists with ID %s (space_id=%s)", stack_name, stack_id, space_id)
        if integration_id:
            spacelift.attach_aws_integration_to_stack(stack_id, integration_id)
            logger.info("Attached AWS integration %s to existing stack %s", integration_id, stack_id)
        return stack_id

    logger.info("Creating stack %s in space %s (provider=%s, vendor=%s)", 
               stack_name, space_id, provider, vendor)
    stack_id = spacelift.create_stack(
        name=stack_name,
        space_id=space_id,
        repository=repository,
        namespace=namespace,
        branch=branch,
        project_root=project_root,
        vendor=vendor,
        provider=provider,
        description=description,
    )
    logger.info("Successfully created stack %s with ID %s (space_id=%s)", stack_name, stack_id, space_id)
    
    if integration_id:
        spacelift.attach_aws_integration_to_stack(stack_id, integration_id)
        logger.info("Attached AWS integration %s to stack %s", integration_id, stack_id)
    
    return stack_id


def ensure_vcs_and_stack_exists(
    space_id,
    vcs_name,
    stack_name,
    terraform_files_dir,
    commit_message,
    commit_author,
    project_root,
    vendor,
    description=None,
    integration_id=None,
    env_vars=None,
):
    """
    Create or get Spacelift VCS repo, commit Terraform files to it, and create stack.
    Returns (vcs_id, stack_id, commit_sha).
    """
    vcs_id = spacelift.get_vcs_by_name(vcs_name, space_id)
    vcs_is_new = False
    if vcs_id:
        logger.info("VCS repo %s already exists with ID %s (space_id=%s)", vcs_name, vcs_id, space_id)
    else:
        logger.info("Creating VCS repo %s in space %s", vcs_name, space_id)
        vcs_id = spacelift.create_vcs_repo(
            space_id=space_id,
            name=vcs_name,
            description="AFT-managed VCS repository for account provisioning"
        )
        vcs_is_new = True
        logger.info("Successfully created VCS repo %s with ID %s (space_id=%s)", vcs_name, vcs_id, space_id)
    
    # If VCS repo was just created, commit a blank file to initialize the main branch
    # This is required because Spacelift stacks cannot be created pointing to a non-existent branch
    if vcs_is_new:
        logger.info("Initializing main branch in new VCS repo %s by committing .gitkeep", vcs_id)
        spacelift.commit_files(
            vcs_id=vcs_id,
            message="Initialize repository",
            author_name=commit_author,
            files=[{"path": ".gitkeep", "content": "git keep"}]
        )
        logger.info("Successfully initialized main branch in VCS repo %s", vcs_id)
    
    # Create stack BEFORE committing real files so Spacelift can detect the commit as a trigger
    stack_id = spacelift.get_stack_by_name(stack_name, space_id)
    if stack_id:
        logger.info("Stack %s already exists with ID %s (space_id=%s)", stack_name, stack_id, space_id)
        if integration_id:
            spacelift.attach_aws_integration_to_stack(stack_id, integration_id)
            logger.info("Attached AWS integration %s to existing stack %s", integration_id, stack_id)
    else:
        logger.info("Creating stack %s in space %s (provider=SPACELIFT, vendor=%s)", 
                   stack_name, space_id, vendor)
        stack_id = spacelift.create_stack(
            name=stack_name,
            space_id=space_id,
            provider="SPACELIFT",
            spacelift_vcs_id=vcs_id,
            branch="main",
            project_root=project_root,
            vendor=vendor,
            description=description,
        )
        logger.info("Successfully created stack %s with ID %s (space_id=%s)", stack_name, stack_id, space_id)
        
        if integration_id:
            spacelift.attach_aws_integration_to_stack(stack_id, integration_id)
            logger.info("Attached AWS integration %s to stack %s", integration_id, stack_id)
    
    # Set environment variables if provided
    if env_vars:
        spacelift.set_stack_env_vars(stack_id, env_vars)
    
    # Now commit files - this will trigger Spacelift to detect the new commit
    files = []
    for root, dirs, filenames in os.walk(terraform_files_dir):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, terraform_files_dir)

            with open(file_path, 'r') as f:
                content = f.read()

            files.append({
                "path": relative_path,
                "content": content
            })
    
    if not files:
        raise Exception("No Terraform files found in {}".format(terraform_files_dir))
    
    # Log file list and calculate total size
    logger.debug("Files prepared for VCS commit (space_id=%s):", space_id)
    total_size = 0
    for file in files:
        file_size = len(file["content"].encode('utf-8'))
        total_size += file_size
        logger.debug("  - %s (%d bytes)", file["path"], file_size)
    
    logger.info("Committing %d files to VCS repo %s (space_id=%s), total size: %d bytes", 
               len(files), vcs_id, space_id, total_size)
    commit_sha = spacelift.commit_files(
        vcs_id=vcs_id,
        message=commit_message,
        author_name=commit_author,
        files=files
    )
    logger.info("Successfully committed files with SHA: %s (vcs_id=%s)", commit_sha, vcs_id)
    
    return (vcs_id, stack_id, commit_sha)


def trigger_and_wait(stack_id, commit_sha=None, wait_for_vcs=False):
    """
    Trigger a run on a stack and wait for completion, or wait for VCS-triggered run.
    Returns run_id and final state.
    
    Args:
        stack_id: ID of the stack to trigger run on
        commit_sha: Optional specific commit SHA to run against
        wait_for_vcs: If True, wait for VCS-triggered run instead of manually triggering
    
    Returns:
        (run_id, final_state): Tuple of run ID and final state
    """
    if wait_for_vcs:
        logger.info("Waiting for VCS-triggered run on stack %s", stack_id)
        result = spacelift.wait_for_stack_run(stack_id)
        if result is None:
            logger.error("Timeout waiting for VCS-triggered run on stack %s", stack_id)
            raise Exception("Timeout waiting for VCS-triggered run on stack {}".format(stack_id))
        run_id, final_state = result
        logger.info("Run %s completed with state: %s (stack_id=%s)", run_id, final_state, stack_id)
        return (run_id, final_state)
    else:
        logger.info("Triggering run on stack %s (commit_sha=%s)", stack_id, commit_sha or "latest")
        run_id = spacelift.trigger_run(stack_id, commit_sha)
        logger.info("Successfully triggered run %s on stack %s", run_id, stack_id)

        final_state = spacelift.wait_for_run(stack_id, run_id)
        logger.info("Run %s completed with state: %s (stack_id=%s)", run_id, final_state, stack_id)

        return (run_id, final_state)


def setup_and_run_stack(
    space_name,
    parent_space_id,
    stack_name,
    repository,
    namespace,
    branch,
    project_root,
    vendor,
    provider,
    commit_sha=None,
    terraform_files_dir=None,
    integration_role_arn=None,
    integration_name=None,
    manual_trigger=False,
    env_vars=None,
):
    """
    Orchestrates: ensure_space -> (ensure_integration) -> (ensure_stack OR ensure_vcs_and_stack) -> trigger_and_wait.
    
    If terraform_files_dir is provided, uses Spacelift VCS workflow.
    Otherwise, uses external Git workflow.
    
    If integration parameters are provided, ensures AWS integration exists and attaches to stack.
    
    By default, waits for VCS-triggered runs (autodeploy). Set manual_trigger=True to force manual triggering.
    """
    space_id = ensure_space_exists(space_name, parent_space_id)
    
    integration_id = None
    if integration_role_arn and integration_name:
        integration_id = ensure_aws_integration_exists(
            space_id=space_id,
            integration_name=integration_name,
            role_arn=integration_role_arn,
        )
    
    if terraform_files_dir:
        vcs_name = "{}-vcs".format(stack_name)
        vcs_id, stack_id, commit_sha = ensure_vcs_and_stack_exists(
            space_id=space_id,
            vcs_name=vcs_name,
            stack_name=stack_name,
            terraform_files_dir=terraform_files_dir,
            commit_message="AFT account provisioning",
            commit_author="AFT CodeBuild",
            project_root=project_root,
            vendor=vendor,
            description="AFT-managed account provisioning stack",
            integration_id=integration_id,
            env_vars=env_vars,
        )
        wait_for_vcs = not manual_trigger
    else:
        stack_id = ensure_stack_exists(
            space_id=space_id,
            stack_name=stack_name,
            repository=repository,
            namespace=namespace,
            branch=branch,
            project_root=project_root,
            vendor=vendor,
            provider=provider,
            description="AFT-managed account provisioning stack",
            integration_id=integration_id,
        )
        wait_for_vcs = not manual_trigger
    
    run_id, final_state = trigger_and_wait(stack_id, commit_sha, wait_for_vcs=wait_for_vcs)
    return (run_id, final_state)


def delete_stack_only(stack_id):
    """
    Delete a stack.
    
    Args:
        stack_id: ID of the stack to delete
    """
    logger.info("Deleting stack %s", stack_id)
    spacelift.delete_stack(stack_id)
    logger.info("Successfully deleted stack %s", stack_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Spacelift orchestration layer for managing stacks"
    )
    parser.add_argument(
        "--operation",
        type=str,
        required=True,
        choices=["deploy", "delete"],
        help="Operation to perform: deploy or delete",
    )
    parser.add_argument(
        "--space_name",
        type=str,
        required=True,
        help="Name of the space to create or use",
    )
    parser.add_argument(
        "--parent_space_id",
        type=str,
        default="root",
        help="Parent space ID (default: root)",
    )
    parser.add_argument(
        "--stack_name",
        type=str,
        required=True,
        help="Name of the stack to create or use",
    )
    parser.add_argument(
        "--repository",
        type=str,
        help="Git repository name (e.g., 'aft-account-request'). Not required if --terraform_files_dir is provided.",
    )
    parser.add_argument(
        "--namespace",
        type=str,
        help="Git repository namespace/owner (e.g., 'my-org' or AWS account ID). Not required if --terraform_files_dir is provided.",
    )
    parser.add_argument(
        "--terraform_files_dir",
        type=str,
        help="Directory containing Terraform files to commit to Spacelift VCS. If provided, uses Spacelift VCS workflow instead of external Git.",
    )
    parser.add_argument(
        "--api_endpoint",
        type=str,
        required=True,
        help="Spacelift API endpoint",
    )
    parser.add_argument(
        "--api_key_id",
        type=str,
        required=True,
        help="Spacelift API key ID",
    )
    parser.add_argument(
        "--api_key_secret",
        type=str,
        required=True,
        help="Spacelift API key secret",
    )
    parser.add_argument(
        "--branch",
        type=str,
        default="main",
        help="Git branch to track (default: main)",
    )
    parser.add_argument(
        "--project_root",
        type=str,
        default="/",
        help="Project root path in repository (default: /)",
    )
    parser.add_argument(
        "--vendor",
        type=str,
        default="TERRAFORM_FOSS",
        choices=["TERRAFORM_FOSS", "OPEN_TOFU"],
        help="Terraform vendor to use (default: TERRAFORM_FOSS)",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="GITHUB",
        choices=["GITHUB", "GITLAB", "BITBUCKET_CLOUD", "BITBUCKET_DATACENTER", 
                 "GITHUB_ENTERPRISE", "AZURE_DEVOPS", "GIT"],
        help="VCS provider type (default: GITHUB). Not required if --terraform_files_dir is provided.",
    )
    parser.add_argument(
        "--commit_sha",
        type=str,
        help="Optional specific commit SHA to run against",
    )
    parser.add_argument(
        "--integration_role_arn",
        type=str,
        help="IAM role ARN for AWS integration",
    )
    parser.add_argument(
        "--integration_name",
        type=str,
        help="Name for AWS integration",
    )
    parser.add_argument(
        "--manual_trigger",
        action="store_true",
        default=False,
        help="Manually trigger runs instead of waiting for VCS-triggered runs (default: False)",
    )
    parser.add_argument(
        "--env",
        action="append",
        help="Environment variable in format NAME=VALUE (can be used multiple times)"
    )

    args = parser.parse_args()

    if args.operation == "deploy":
        if not args.terraform_files_dir and (not args.repository or not args.namespace):
            parser.error("Either --terraform_files_dir OR both --repository and --namespace must be provided for deploy operation")

    spacelift.init(args.api_endpoint, args.api_key_id, args.api_key_secret)

    if args.operation == "deploy":
        logger.info("Starting deployment: space=%s, stack=%s, parent_space=%s", 
                   args.space_name, args.stack_name, args.parent_space_id)
        
        # Parse environment variables
        env_vars = {}
        if args.env:
            for env_str in args.env:
                if '=' in env_str:
                    name, value = env_str.split('=', 1)
                    env_vars[name] = value
                else:
                    logger.warning("Ignoring invalid env var format: %s (expected NAME=VALUE)", env_str)
        
        run_id, final_state = setup_and_run_stack(
            space_name=args.space_name,
            parent_space_id=args.parent_space_id,
            stack_name=args.stack_name,
            repository=args.repository,
            namespace=args.namespace,
            branch=args.branch,
            project_root=args.project_root,
            vendor=args.vendor,
            provider=args.provider,
            commit_sha=args.commit_sha,
            terraform_files_dir=args.terraform_files_dir,
            integration_role_arn=args.integration_role_arn,
            integration_name=args.integration_name,
            manual_trigger=args.manual_trigger,
            env_vars=env_vars,
        )
        
        logger.info("Deployment completed with run ID: %s", run_id)
        logger.info("Final state: %s", final_state)
        
        # Exit with error code if run failed
        if final_state not in ["FINISHED"]:
            logger.error("Deployment failed: run %s ended in state %s", run_id, final_state)
            exit(1)

    elif args.operation == "delete":
        logger.info("Starting deletion: space=%s, stack=%s, parent_space=%s", 
                   args.space_name, args.stack_name, args.parent_space_id)
        
        # Find stack by name
        space_id = spacelift.get_space_by_name(args.space_name, args.parent_space_id)
        if not space_id:
            logger.error("Space %s not found under parent %s", args.space_name, args.parent_space_id)
            exit(1)
        
        stack_id = spacelift.get_stack_by_name(args.stack_name, space_id)
        if not stack_id:
            logger.error("Stack %s not found in space %s", args.stack_name, space_id)
            exit(1)

        delete_stack_only(stack_id)
        logger.info("Deletion completed successfully")
