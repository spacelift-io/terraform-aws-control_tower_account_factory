#!/usr/bin/python
# Copyright Spacelift, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import spacelift_client as spacelift


def ensure_space_exists(space_name, parent_space_id):
    """
    Check if space exists by name. If not exists, create it.
    Returns space ID.
    """
    space_id = spacelift.get_space_by_name(space_name, parent_space_id)
    if space_id:
        print("Space {} already exists with ID {}".format(space_name, space_id))
        return space_id

    space_id = spacelift.create_space(
        space_name, parent_space_id, description="AFT-managed space for account provisioning"
    )
    print("Successfully created space {} with ID {}".format(space_name, space_id))
    return space_id


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
    
    Returns:
        stack_id: ID of the stack
    """
    stack_id = spacelift.get_stack_by_name(stack_name, space_id)
    if stack_id:
        print("Stack {} already exists with ID {}".format(stack_name, stack_id))
        return stack_id

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
    print("Successfully created stack {} with ID {}".format(stack_name, stack_id))
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
):
    """
    Create or get Spacelift VCS repo, commit Terraform files to it, and create stack.
    Returns (vcs_id, stack_id, commit_sha).
    """
    vcs_id = spacelift.get_vcs_by_name(vcs_name, space_id)
    if vcs_id:
        print("VCS repo {} already exists with ID {}".format(vcs_name, vcs_id))
    else:
        vcs_id = spacelift.create_vcs_repo(
            space_id=space_id,
            name=vcs_name,
            description="AFT-managed VCS repository for account provisioning"
        )
        print("Successfully created VCS repo {} with ID {}".format(vcs_name, vcs_id))
    
    files = []
    for root, dirs, filenames in os.walk(terraform_files_dir):
        for filename in filenames:
            if filename.endswith((".tf", ".tfvars")):
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
    
    print("Committing {} files to VCS repo {}".format(len(files), vcs_id))
    commit_sha = spacelift.commit_files(
        vcs_id=vcs_id,
        message=commit_message,
        author_name=commit_author,
        files=files
    )
    print("Successfully committed files with SHA: {}".format(commit_sha))
    
    stack_id = spacelift.get_stack_by_name(stack_name, space_id)
    if stack_id:
        print("Stack {} already exists with ID {}".format(stack_name, stack_id))
    else:
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
        print("Successfully created stack {} with ID {}".format(stack_name, stack_id))
    
    return (vcs_id, stack_id, commit_sha)


def trigger_and_wait(stack_id, commit_sha=None):
    """
    Trigger a run on a stack and wait for completion.
    Returns run_id and final state.
    
    Args:
        stack_id: ID of the stack to trigger run on
        commit_sha: Optional specific commit SHA to run against
    
    Returns:
        (run_id, final_state): Tuple of run ID and final state
    """
    run_id = spacelift.trigger_run(stack_id, commit_sha)
    print("Successfully triggered run {} on stack {}".format(run_id, stack_id))

    final_state = spacelift.wait_for_run(run_id)
    print("Run {} completed with state: {}".format(run_id, final_state))

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
):
    """
    Orchestrates: ensure_space -> (ensure_stack OR ensure_vcs_and_stack) -> trigger_and_wait.
    
    If terraform_files_dir is provided, uses Spacelift VCS workflow.
    Otherwise, uses external Git workflow.
    """
    space_id = ensure_space_exists(space_name, parent_space_id)
    
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
        )
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
        )
    
    run_id, final_state = trigger_and_wait(stack_id, commit_sha)
    return (run_id, final_state)


def delete_stack_only(stack_id):
    """
    Delete a stack.
    
    Args:
        stack_id: ID of the stack to delete
    """
    spacelift.delete_stack(stack_id)
    print("Successfully deleted stack {}".format(stack_id))


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

    args = parser.parse_args()

    if args.operation == "deploy":
        if not args.terraform_files_dir and (not args.repository or not args.namespace):
            parser.error("Either --terraform_files_dir OR both --repository and --namespace must be provided for deploy operation")

    spacelift.init(args.api_endpoint, args.api_key_id, args.api_key_secret)

    if args.operation == "deploy":
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
        )
        
        print("Deployment completed with run ID: {}".format(run_id))
        print("Final state: {}".format(final_state))
        
        # Exit with error code if run failed
        if final_state not in ["FINISHED"]:
            exit(1)

    elif args.operation == "delete":
        # Find stack by name
        space_id = spacelift.get_space_by_name(args.space_name, args.parent_space_id)
        if not space_id:
            print("Error: Space {} not found under parent {}".format(
                args.space_name, args.parent_space_id))
            exit(1)
        
        stack_id = spacelift.get_stack_by_name(args.stack_name, space_id)
        if not stack_id:
            print("Error: Stack {} not found in space {}".format(
                args.stack_name, space_id))
            exit(1)

        delete_stack_only(stack_id)
        print("Deletion completed successfully")
