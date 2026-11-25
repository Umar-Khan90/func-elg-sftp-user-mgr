import azure.functions as func
import json
import logging
import os

from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import LocalUser, PermissionScope
from azure.storage.filedatalake import DataLakeServiceClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

SUBSCRIPTION_ID = os.environ["SFTP_SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["SFTP_RESOURCE_GROUP"]
STORAGE_ACCOUNT = os.environ["SFTP_STORAGE_ACCOUNT"]
CONTAINER_PREFIX = os.environ["SFTP_CONTAINER_PREFIX"]  # e.g. "sftp-elg"


def get_client():
    return StorageManagementClient(DefaultAzureCredential(), SUBSCRIPTION_ID)


def get_dls():
    return DataLakeServiceClient(
        f"https://{STORAGE_ACCOUNT}.dfs.core.windows.net",
        credential=DefaultAzureCredential()
    )


def container_for(username):
    return f"{CONTAINER_PREFIX}-{username}"


def is_managed_user(user) -> bool:
    # Only match users whose container is exactly {PREFIX}-{username}
    # Guarantees we never see or touch existing containers like sftp-elg-catalog
    return bool(
        user.permission_scopes and
        user.permission_scopes[0].resource_name == container_for(user.name)
    )


def get_managed_user(client, username):
    try:
        u = client.local_users.get(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    except ResourceNotFoundError:
        return None
    return u if is_managed_user(u) else None


def audit(action: str, username: str, req: func.HttpRequest):
    caller = req.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", "unknown")
    logging.warning(f"AUDIT action={action} user={username} by={caller}")


def ok(data, status=200):
    return func.HttpResponse(json.dumps(data), status_code=status, mimetype="application/json")


def err(msg, status=400):
    return func.HttpResponse(json.dumps({"error": msg}), status_code=status, mimetype="application/json")


@app.route(route="manager", methods=["GET"])
def serve_manager(req: func.HttpRequest) -> func.HttpResponse:
    path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(path) as f:
        return func.HttpResponse(f.read(), mimetype="text/html")


@app.route(route="users", methods=["GET"])
def list_users(req: func.HttpRequest) -> func.HttpResponse:
    client = get_client()
    users = [u for u in client.local_users.list(RESOURCE_GROUP, STORAGE_ACCOUNT) if is_managed_user(u)]
    result = [{
        "username": u.name,
        "container": container_for(u.name),
        "login": f"{STORAGE_ACCOUNT}.{u.name}",
        "host": f"{STORAGE_ACCOUNT}.blob.core.windows.net",
        "hasPassword": u.has_ssh_password,
    } for u in users]
    return ok(result)


@app.route(route="users", methods=["POST"])
def create_user(req: func.HttpRequest) -> func.HttpResponse:
    body = req.get_json()
    username = body.get("username", "").lower().strip()
    if not username:
        return err("username is required")
    if not username.isalnum():
        return err("username must contain lowercase letters and digits only")
    if len(username) > 50:
        return err("username must be 50 characters or fewer")

    container = container_for(username)
    try:
        dls = get_dls()
        fs_client = dls.get_file_system_client(container)

        # Safety check: if container exists but wasn't created by this app, refuse
        try:
            props = fs_client.get_file_system_properties()
            metadata = props.get("metadata") or {}
            if metadata.get("managed-by") != "sftp-user-manager":
                return err(f"Container {container} already exists and was not created by this app", 409)
        except ResourceNotFoundError:
            # Container doesn't exist — create it and tag it as app-managed
            dls.create_file_system(container, metadata={"managed-by": "sftp-user-manager"})

        client = get_client()
        client.local_users.create_or_update(
            RESOURCE_GROUP, STORAGE_ACCOUNT, username,
            LocalUser(
                home_directory=container,
                allow_acl_authorization=False,
                permission_scopes=[PermissionScope(
                    permissions="rwdlc",
                    service="blob",
                    resource_name=container,
                )],
            ),
        )
        result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
        audit("create", username, req)
        return ok({
            "username": username,
            "container": container,
            "login": f"{STORAGE_ACCOUNT}.{username}",
            "host": f"{STORAGE_ACCOUNT}.blob.core.windows.net",
            "port": 22,
            "password": result.ssh_password,
        }, 201)
    except Exception as e:
        logging.exception("create_user failed")
        return err(str(e), 500)


@app.route(route="users/{username}/reset", methods=["POST"])
def reset_password(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    if not get_managed_user(client, username):
        return err("user not found", 404)
    result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("reset", username, req)
    return ok({"username": username, "login": f"{STORAGE_ACCOUNT}.{username}", "password": result.ssh_password})


@app.route(route="users/{username}/disable", methods=["POST"])
def disable_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    u = get_managed_user(client, username)
    if not u:
        return err("user not found", 404)
    client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    u.ssh_authorized_keys = []
    client.local_users.create_or_update(RESOURCE_GROUP, STORAGE_ACCOUNT, username, u)
    audit("disable", username, req)
    return ok({"username": username, "status": "disabled"})


@app.route(route="users/{username}/enable", methods=["POST"])
def enable_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    if not get_managed_user(client, username):
        return err("user not found", 404)
    result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("enable", username, req)
    return ok({"username": username, "login": f"{STORAGE_ACCOUNT}.{username}", "password": result.ssh_password})


@app.route(route="users/{username}", methods=["DELETE"])
def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    if not get_managed_user(client, username):
        return err("user not found", 404)
    # Deletes only the SFTP local user — container is preserved so pipeline data is not lost
    client.local_users.delete(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("delete", username, req)
    return ok({"username": username, "status": "deleted"})
