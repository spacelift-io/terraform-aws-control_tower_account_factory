#!/usr/bin/python
# Copyright Spacelift, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import time
from typing import Any, Dict, List, Optional

import requests

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

SPACELIFT_API_ENDPOINT = ""
SPACELIFT_API_TOKEN = ""

TERMINAL_STATES = ["FINISHED", "FAILED", "CANCELED", "DISCARDED"]


class SpaceliftError(Exception):
    """Exception for Spacelift API errors"""

    def __init__(self, message, status_code=None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


def get_jwt_token(api_endpoint, api_key_id, api_key_secret):
    """Exchange API key credentials for JWT token"""
    mutation = """
    mutation GetSpaceliftToken($keyId: ID!, $keySecret: String!) {
        apiKeyUser(id: $keyId, secret: $keySecret) {
            id
            jwt
        }
    }
    """
    
    headers = {
        "Content-Type": "application/json",
    }
    
    payload = {
        "query": mutation,
        "variables": {
            "keyId": api_key_id,
            "keySecret": api_key_secret
        }
    }
    
    response = requests.post(api_endpoint, headers=headers, json=payload)
    
    if response.status_code != 200:
        raise SpaceliftError(
            "Failed to exchange API key for JWT token: {}".format(response.text),
            response.status_code
        )
    
    data = response.json()
    
    if "errors" in data and data["errors"]:
        error_messages = [error.get("message", str(error)) for error in data["errors"]]
        raise SpaceliftError(
            "Failed to authenticate with Spacelift: {}".format("; ".join(error_messages))
        )
    
    jwt_token = data.get("data", {}).get("apiKeyUser", {}).get("jwt")
    if not jwt_token:
        raise SpaceliftError("No JWT token returned from Spacelift API")
    
    return jwt_token


def init(api_endpoint, api_key_id, api_key_secret):
    global SPACELIFT_API_ENDPOINT
    global SPACELIFT_API_TOKEN
    
    logger.info("Initializing Spacelift client: endpoint=%s", api_endpoint)
    SPACELIFT_API_ENDPOINT = api_endpoint
    SPACELIFT_API_TOKEN = get_jwt_token(api_endpoint, api_key_id, api_key_secret)
    logger.info("Successfully authenticated with Spacelift")


def __build_headers() -> Dict[str, str]:
    """Build HTTP headers for Spacelift API requests"""
    return {
        "Authorization": "Bearer {}".format(SPACELIFT_API_TOKEN),
        "Content-Type": "application/json",
    }


def __execute_query(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a GraphQL query or mutation against Spacelift API"""
    headers = __build_headers()
    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    logger.debug("Executing GraphQL query: %s", query[:100] + "..." if len(query) > 100 else query)
    if variables:
        logger.debug("GraphQL variables: %s", variables)

    response = requests.post(SPACELIFT_API_ENDPOINT, headers=headers, json=payload)

    if response.status_code != 200:
        raise SpaceliftError(
            "API request failed: {}".format(response.text), response.status_code
        )

    data = response.json()

    if "errors" in data and data["errors"]:
        error_messages = [error.get("message", str(error)) for error in data["errors"]]
        logger.error("GraphQL error response: %s", data["errors"])
        raise SpaceliftError("GraphQL error: {}".format("; ".join(error_messages)))

    logger.debug("GraphQL response: %s", data.get("data", {}))
    return data.get("data", {})


def check_space_exists(space_id: str) -> bool:
    """Check if a space exists by ID"""
    query = """
    query GetSpace($id: ID!) {
        space(id: $id) {
            id
        }
    }
    """
    try:
        result = __execute_query(query, {"id": space_id})
        return result.get("space") is not None
    except SpaceliftError:
        return False


def get_space_by_name(name: str, parent_space_id: str) -> Optional[str]:
    """Get space ID by name under a parent space.
    
    Note: The Spacelift GraphQL API does not support filtering spaces by parent
    or name directly. This function queries all spaces and filters client-side.
    """
    query = """
    query GetSpaces {
        spaces {
            id
            name
            parentSpace
        }
    }
    """
    result = __execute_query(query)
    spaces = result.get("spaces", [])

    # Filter client-side by parent and name
    for space in spaces:
        space_parent = space.get("parentSpace")
        space_name = space.get("name")
        
        # Match on name and parent space
        if space_name == name and space_parent == parent_space_id:
            return space["id"]

    return None


def create_space(name: str, parent_space_id: str, description: Optional[str] = None) -> str:
    """Create a new space"""
    mutation = """
    mutation CreateSpace($input: SpaceInput!) {
        spaceCreate(input: $input) {
            id
        }
    }
    """
    input_data = {
        "name": name,
        "parentSpace": parent_space_id,
        "inheritEntities": False,
        "description": description or "",
    }

    result = __execute_query(mutation, {"input": input_data})
    return result["spaceCreate"]["id"]


def check_stack_exists(stack_id: str) -> bool:
    """Check if a stack exists by ID"""
    query = """
    query GetStack($id: ID!) {
        stack(id: $id) {
            id
        }
    }
    """
    try:
        result = __execute_query(query, {"id": stack_id})
        return result.get("stack") is not None
    except SpaceliftError:
        return False


def get_stack_by_name(name: str, space_id: str) -> Optional[str]:
    """Get stack ID by name in a space.
    
    Note: The Spacelift GraphQL API does not support filtering stacks by space
    via predicates. This function searches by name and filters client-side by space.
    """
    query = """
    query SearchStacks($input: SearchInput!) {
        searchStacks(input: $input) {
            edges {
                node {
                    id
                    name
                    space
                }
            }
        }
    }
    """
    
    input_data = {
        "first": 100,
        "predicates": [
            {
                "field": "name",
                "constraint": {
                    "stringMatches": [name]
                }
            }
        ]
    }
    
    result = __execute_query(query, {"input": input_data})
    edges = result.get("searchStacks", {}).get("edges", [])

    for edge in edges:
        node = edge.get("node", {})
        if node.get("name") == name and node.get("space") == space_id:
            return node["id"]

    return None


def create_stack(
    name: str,
    space_id: str,
    repository: Optional[str] = None,
    namespace: Optional[str] = None,
    branch: str = "main",
    project_root: Optional[str] = None,
    autodeploy: bool = True,
    vendor: str = "TERRAFORM_FOSS",
    provider: str = "GITHUB",
    description: Optional[str] = None,
    repository_url: Optional[str] = None,
    spacelift_vcs_id: Optional[str] = None,
) -> str:
    """Create a new stack pointing to a Git repository or Spacelift VCS.
    
    For SPACELIFT provider: spacelift_vcs_id is required.
    For GIT provider: repository_url is required.
    For other providers (GITHUB, GITLAB, etc.): repository and namespace are required.
    """
    mutation = """
    mutation CreateStack($input: StackInput!, $manageState: Boolean!) {
        stackCreate(input: $input, manageState: $manageState) {
            id
        }
    }
    """
    
    input_data = {
        "name": name,
        "space": space_id,
        "branch": branch,
        "autodeploy": autodeploy,
        "provider": provider,
        "administrative": False,
        "autoretry": False,
        "localPreviewEnabled": False,
        "enableWellKnownSecretMasking": False,
        "enableSensitiveOutputUpload": True,
        "githubActionDeploy": True,
        "protectFromDeletion": False,
    }
    
    if provider == "SPACELIFT" and spacelift_vcs_id:
        input_data["vcsIntegrationId"] = spacelift_vcs_id
        input_data["repository"] = spacelift_vcs_id
        input_data["namespace"] = "spacelift"
        input_data["repositoryURL"] = "https://spacelift.io"
    else:
        if repository:
            input_data["repository"] = repository
        if namespace:
            input_data["namespace"] = namespace
        if repository_url:
            input_data["repositoryURL"] = repository_url
    
    if project_root:
        input_data["projectRoot"] = project_root
    
    if description:
        input_data["description"] = description
    
    if vendor in ["TERRAFORM_FOSS", "OPEN_TOFU"]:
        input_data["vendorConfig"] = {
            "terraform": {
                "workflowTool": vendor
            }
        }

    variables = {
        "input": input_data,
        "manageState": True
    }

    result = __execute_query(mutation, variables)
    return result["stackCreate"]["id"]


def set_stack_env_vars(stack_id: str, env_vars: Dict[str, str]) -> None:
    """Set environment variables on a Spacelift stack
    
    Args:
        stack_id: ID of the stack
        env_vars: Dictionary of environment variable names to values
    """
    if not env_vars:
        return
    
    logger.info("Setting %d environment variables on stack %s", len(env_vars), stack_id)
    
    for name, value in env_vars.items():
        mutation = """
        mutation SetEnvVar($stack: ID!, $config: ConfigInput!) {
            stackConfigAdd(stack: $stack, config: $config) {
                id
            }
        }
        """
        
        variables = {
            "stack": stack_id,
            "config": {
                "id": name,
                "value": value,
                "type": "ENVIRONMENT_VARIABLE",
                "writeOnly": False
            }
        }
        
        logger.debug("Setting env var %s on stack %s", name, stack_id)
        __execute_query(mutation, variables)
        logger.info("Set environment variable %s on stack %s", name, stack_id)


def trigger_run(stack_id: str, commit_sha: Optional[str] = None) -> str:
     """Trigger a run on a stack"""
     mutation = """
     mutation TriggerRun($stack: ID!, $commitSha: String) {
         runTrigger(stack: $stack, commitSha: $commitSha) {
             id
             state
         }
     }
     """
     variables = {"stack": stack_id}
     if commit_sha:
         variables["commitSha"] = commit_sha

     result = __execute_query(mutation, variables)
     return result["runTrigger"]["id"]


def get_run_state(stack_id: str, run_id: str) -> str:
    """Get the current state of a run
    
    Args:
        stack_id: ID of the stack the run belongs to
        run_id: ID of the run to query
        
    Returns:
        Current state of the run (e.g., FINISHED, RUNNING, FAILED)
    """
    query = """
    query GetRunState($stackId: ID!, $runId: ID!) {
        stack(id: $stackId) {
            run(id: $runId) {
                state
            }
        }
    }
    """
    result = __execute_query(query, {"stackId": stack_id, "runId": run_id})
    return result["stack"]["run"]["state"]


def wait_for_run(
    stack_id: str, 
    run_id: str, 
    terminal_states: Optional[List[str]] = None, 
    poll_interval: int = 10
) -> str:
    """Wait for a run to reach a terminal state
    
    Args:
        stack_id: ID of the stack the run belongs to
        run_id: ID of the run to wait for
        terminal_states: Optional list of states considered terminal
        poll_interval: Seconds to wait between polls
        
    Returns:
        Final state of the run
    """
    if terminal_states is None:
        terminal_states = TERMINAL_STATES

    logger.info("Waiting for run %s to complete (stack_id=%s)", run_id, stack_id)
    start_time = time.time()
    
    while True:
        state = get_run_state(stack_id, run_id)
        elapsed = int(time.time() - start_time)
        
        if state in terminal_states:
            logger.info("Run %s completed with state: %s (elapsed: %ds)", run_id, state, elapsed)
            return state
        
        logger.info("[%ds] Polling run %s: state=%s", elapsed, run_id, state)
        time.sleep(poll_interval)


def delete_stack(stack_id: str) -> None:
    """Delete a stack"""
    mutation = """
    mutation DeleteStack($id: ID!) {
        stackDelete(id: $id) {
            id
        }
    }
    """
    __execute_query(mutation, {"id": stack_id})


def check_vcs_exists(vcs_id: str) -> bool:
    """Check if a Spacelift VCS repository exists by ID"""
    query = """
    query GetVCS($id: ID!) {
        spaceliftVCS(id: $id) {
            id
        }
    }
    """
    try:
        result = __execute_query(query, {"id": vcs_id})
        return result.get("spaceliftVCS") is not None
    except SpaceliftError:
        return False


def get_vcs_by_name(name: str, space_id: str) -> Optional[str]:
    """Get Spacelift VCS repository ID by name in a space."""
    query = """
    query ListVCS($spaceID: ID!) {
        spaceliftVCSes(spaceID: $spaceID, first: 50) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
    """
    result = __execute_query(query, {"spaceID": space_id})
    edges = result.get("spaceliftVCSes", {}).get("edges", [])
    
    for edge in edges:
        node = edge.get("node", {})
        if node.get("name") == name:
            return node["id"]
    
    return None


def create_vcs_repo(
    space_id: str,
    name: str,
    description: Optional[str] = None,
    labels: Optional[List[str]] = None
) -> str:
    """Create a new Spacelift-hosted VCS repository"""
    mutation = """
    mutation CreateVCS($input: SpaceliftVCSCreateInput!) {
        spaceliftVCSCreate(input: $input) {
            id
            name
        }
    }
    """
    
    input_data = {
        "spaceID": space_id,
        "name": name,
    }
    
    if description:
        input_data["description"] = description
    
    if labels:
        input_data["labels"] = labels
    
    result = __execute_query(mutation, {"input": input_data})
    return result["spaceliftVCSCreate"]["id"]


def commit_files(
    vcs_id: str,
    message: str,
    author_name: str,
    files: List[Dict[str, str]],
    author_email: Optional[str] = None
) -> str:
    """Commit files to a Spacelift VCS repository.
    
    Args:
        vcs_id: The VCS repository ID
        message: Commit message
        author_name: Author name for the commit
        files: List of file dicts with 'path' and 'content' keys
        author_email: Optional author email
        
    Returns:
        The commit SHA
    """
    mutation = """
    mutation CommitFiles($input: SpaceliftVCSCommitInput!) {
        spaceliftVCSCommitFiles(input: $input) {
            sha
        }
    }
    """
    
    # Log preparation phase
    logger.info("Preparing to commit %d files to VCS repo %s", len(files), vcs_id)
    
    # Calculate total size and log each file
    total_size = 0
    for file in files:
        file_size = len(file["content"].encode('utf-8'))
        total_size += file_size
        logger.debug("  - %s (%d bytes)", file["path"], file_size)
    
    logger.info("Total commit size: %d bytes", total_size)
    
    file_inputs = []
    for file in files:
        file_input = {
            "path": file["path"],
            "content": file["content"]
        }
        file_inputs.append(file_input)
    
    input_data = {
        "vcsID": vcs_id,
        "message": message,
        "authorName": author_name,
        "files": file_inputs
    }
    
    if author_email:
        input_data["authorEmail"] = author_email
    
    # Log mutation execution
    logger.debug("Executing VCS commit mutation for vcs_id=%s, message='%s', author=%s", 
                vcs_id, message, author_name)
    logger.debug("VCS commit includes %d files", len(file_inputs))
    
    # Execute with error handling
    start_time = time.time()
    try:
        result = __execute_query(mutation, {"input": input_data})
        elapsed = time.time() - start_time
        
        commit_sha = result["spaceliftVCSCommitFiles"]["sha"]
        logger.info("Successfully committed %d files to VCS repo %s, commit SHA: %s", 
                   len(files), vcs_id, commit_sha)
        logger.debug("VCS commit completed in %.2fs", elapsed)
        
        return commit_sha
    except SpaceliftError as e:
        elapsed = time.time() - start_time
        # Log detailed error context
        logger.error("Failed to commit files to VCS repo %s:", vcs_id)
        logger.error("  VCS ID: %s", vcs_id)
        logger.error("  Files attempted: %d", len(files))
        
        # Log first 5 file paths
        file_paths = [f["path"] for f in files[:5]]
        if len(files) > 5:
            file_paths.append("... and {} more".format(len(files) - 5))
        logger.error("  Files: %s", ", ".join(file_paths))
        
        logger.error("  Commit message: '%s'", message)
        logger.error("  Author: %s", author_name)
        logger.error("  Error: %s", str(e))
        logger.error("  Elapsed time: %.2fs", elapsed)
        
        raise


def get_aws_integration_by_name(name: str, space_id: str) -> Optional[str]:
    """Get AWS integration ID by name in a space.
    
    Note: The Spacelift GraphQL API does not support filtering integrations by space.
    This function queries all integrations and filters client-side.
    """
    query = """
    query ListAWSIntegrations {
        awsIntegrations {
            id
            name
            space
        }
    }
    """
    result = __execute_query(query)
    integrations = result.get("awsIntegrations", [])
    
    for integration in integrations:
        if integration.get("name") == name and integration.get("space") == space_id:
            return integration["id"]
    
    return None


def create_aws_integration(
    space_id: str,
    name: str,
    role_arn: str,
    external_id: Optional[str] = None,
    duration_seconds: int = 3600,
    generate_credentials_in_worker: bool = False
) -> str:
    """Create a new AWS integration.
    
    Args:
        space_id: ID of the space to create integration in
        name: Name for the integration
        role_arn: ARN of the IAM role to assume
        external_id: External ID for role assumption (default: None, uses Spacelift default pattern)
        duration_seconds: Session duration in seconds (default: 3600)
        generate_credentials_in_worker: Whether to generate credentials in worker (default: False)
        
    Returns:
        integration_id: ID of the created integration
    """
    mutation = """
    mutation CreateAWSIntegration(
        $spaceId: ID!,
        $name: String!,
        $roleArn: String!,
        $externalId: String,
        $durationSeconds: Int,
        $generateCredentialsInWorker: Boolean!,
        $labels: [String!]!
    ) {
        awsIntegrationCreate(
            space: $spaceId,
            name: $name,
            roleArn: $roleArn,
            externalID: $externalId,
            durationSeconds: $durationSeconds,
            generateCredentialsInWorker: $generateCredentialsInWorker,
            labels: $labels
        ) {
            id
            name
        }
    }
    """
    
    variables = {
        "spaceId": space_id,
        "name": name,
        "roleArn": role_arn,
        "externalId": external_id,
        "durationSeconds": duration_seconds,
        "generateCredentialsInWorker": generate_credentials_in_worker,
        "labels": []
    }
    
    result = __execute_query(mutation, variables)
    return result["awsIntegrationCreate"]["id"]


def get_stack_integration(stack_id: str) -> Optional[str]:
    """Get the AWS integration ID attached to a stack.
    
    Args:
        stack_id: ID of the stack
        
    Returns:
        Integration ID if attached, None otherwise
    """
    query = """
    query GetStackIntegration($stackId: ID!) {
        stack(id: $stackId) {
            integrations {
                awsV2 {
                    integrationId
                }
            }
        }
    }
    """
    result = __execute_query(query, {"stackId": stack_id})
    integrations = result.get("stack", {}).get("integrations", {}).get("awsV2", [])
    
    if integrations and len(integrations) > 0:
        return integrations[0]["integrationId"]
    return None


def attach_aws_integration_to_stack(stack_id: str, integration_id: str, read: bool = True, write: bool = True) -> None:
    """Attach an AWS integration to a stack.
    
    Args:
        stack_id: ID of the stack
        integration_id: ID of the AWS integration to attach
        read: Whether the integration has read permissions (default: True)
        write: Whether the integration has write permissions (default: True)
    """
    existing_integration = get_stack_integration(stack_id)
    
    if existing_integration == integration_id:
        logger.info("AWS integration %s already attached to stack %s", integration_id, stack_id)
        return
    
    if existing_integration:
        logger.warning("Stack %s already has integration %s. Replacing with %s", 
                      stack_id, existing_integration, integration_id)
    
    mutation = """
    mutation AttachAWSIntegration($stack: ID!, $integration: ID!, $read: Boolean!, $write: Boolean!) {
        awsIntegrationAttach(stack: $stack, id: $integration, read: $read, write: $write) {
            id
        }
    }
    """
    __execute_query(mutation, {
        "stack": stack_id,
        "integration": integration_id,
        "read": read,
        "write": write
    })
    logger.info("Attached AWS integration %s to stack %s", integration_id, stack_id)


def list_aws_integrations(space_id: str) -> List[Dict[str, Any]]:
    """List all AWS integrations in a space.
    
    Note: The Spacelift GraphQL API does not support filtering integrations by space.
    This function queries all integrations and filters client-side.
    
    Args:
        space_id: ID of the space
        
    Returns:
        List of AWS integration dicts with id, name, and roleARN
    """
    query = """
    query ListAWSIntegrations {
        awsIntegrations {
            id
            name
            roleARN
            space
        }
    }
    """
    result = __execute_query(query)
    all_integrations = result.get("awsIntegrations", [])
    
    return [intg for intg in all_integrations if intg.get("space") == space_id]


def get_stack_latest_run(stack_id: str) -> Optional[Dict[str, Any]]:
    """Get the most recent run for a stack.
    
    Args:
        stack_id: ID of the stack
        
    Returns:
        Dict with run id, state, and createdAt, or None if no runs exist
    """
    query = """
    query GetStackLatestRun($stackId: ID!) {
        stack(id: $stackId) {
            runs {
                id
                state
                createdAt
            }
        }
    }
    """
    result = __execute_query(query, {"stackId": stack_id})
    runs = result.get("stack", {}).get("runs", [])
    
    if runs and len(runs) > 0:
        return runs[0]
    return None


def wait_for_stack_run(
    stack_id: str,
    timeout_seconds: int = 300,
    poll_interval: int = 10,
    terminal_states: Optional[List[str]] = None
) -> Optional[tuple]:
    """Wait for a VCS-triggered run to appear on a stack and complete.
    
    This is used when a stack has VCS integration and runs are automatically
    triggered by commits. It polls the stack until a run appears, then waits
    for it to complete.
    
    Args:
        stack_id: ID of the stack to monitor
        timeout_seconds: Maximum seconds to wait for a run to appear
        poll_interval: Seconds to wait between polls
        terminal_states: Optional list of states considered terminal
        
    Returns:
        Tuple of (run_id, final_state) if successful, None if timeout
    """
    if terminal_states is None:
        terminal_states = TERMINAL_STATES
    
    elapsed = 0
    run_id = None
    start_time = time.time()
    
    logger.info("Waiting for VCS-triggered run to appear on stack %s (timeout: %ds)", stack_id, timeout_seconds)
    
    while elapsed < timeout_seconds:
        latest_run = get_stack_latest_run(stack_id)
        elapsed = int(time.time() - start_time)
        remaining = timeout_seconds - elapsed
        
        if latest_run:
            run_id = latest_run["id"]
            current_state = latest_run["state"]
            logger.info("Found run %s in state %s (elapsed: %ds)", run_id, current_state, elapsed)
            break
        
        # Warn if approaching timeout (80% elapsed)
        if elapsed > (timeout_seconds * 0.8):
            logger.warning("[%ds/%ds] No runs found yet, waiting for VCS-triggered run on stack %s", 
                          elapsed, timeout_seconds, stack_id)
        else:
            logger.info("[%ds/%ds] No runs found yet, waiting for VCS-triggered run on stack %s", 
                       elapsed, timeout_seconds, stack_id)
        
        time.sleep(poll_interval)
        elapsed = int(time.time() - start_time)
    
    if not run_id:
        logger.error("Timeout: No run appeared within %ds on stack %s", timeout_seconds, stack_id)
        return None
    
    logger.info("Waiting for run %s to complete (stack_id=%s)", run_id, stack_id)
    final_state = wait_for_run(stack_id, run_id, terminal_states, poll_interval)
    
    return (run_id, final_state)
