#!/usr/bin/python
# Copyright Spacelift, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import time
from typing import Any, Dict, List, Optional

import requests

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
    
    SPACELIFT_API_ENDPOINT = api_endpoint
    SPACELIFT_API_TOKEN = get_jwt_token(api_endpoint, api_key_id, api_key_secret)


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

    response = requests.post(SPACELIFT_API_ENDPOINT, headers=headers, json=payload)

    if response.status_code != 200:
        raise SpaceliftError(
            "API request failed: {}".format(response.text), response.status_code
        )

    data = response.json()

    if "errors" in data and data["errors"]:
        error_messages = [error.get("message", str(error)) for error in data["errors"]]
        raise SpaceliftError("GraphQL error: {}".format("; ".join(error_messages)))

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


def get_run_state(run_id: str) -> str:
    """Get the current state of a run"""
    query = """
    query GetRun($id: ID!) {
        run(id: $id) {
            state
        }
    }
    """
    result = __execute_query(query, {"id": run_id})
    return result["run"]["state"]


def wait_for_run(
    run_id: str, terminal_states: Optional[List[str]] = None, poll_interval: int = 10
) -> str:
    """Wait for a run to reach a terminal state"""
    if terminal_states is None:
        terminal_states = TERMINAL_STATES

    while True:
        state = get_run_state(run_id)
        if state in terminal_states:
            return state
        print("Run {} not yet complete. Current state: {}".format(run_id, state))
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
    
    result = __execute_query(mutation, {"input": input_data})
    return result["spaceliftVCSCommitFiles"]["sha"]
