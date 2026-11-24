import azure.functions as func
import json
import logging
import os

from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import LocalUser
from azure.storage.filedatalake import DataLakeServiceClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

SUBSCRIPTION_ID = os.environ["SFTP_SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["SFTP_RESOURCE_GROUP"]
STORAGE_ACCOUNT = os.environ["SFTP_STORAGE_ACCOUNT"]
CONTAINER = os.environ["SFTP_CONTAINER"]


def get_client():
    return StorageManagementClient(DefaultAzureCredential(), SUBSCRIPTION_ID)


def is_catalog_user(user) -> bool:
    return bool(user.home_directory and user.home_directory.startswith(f"{CONTAINER}/"))


def get_catalog_user(client, username):
    try:
        u = client.local_users.get(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    except ResourceNotFoundError:
        return None
    return u if is_catalog_user(u) else None


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
    users = [u for u in client.local_users.list(RESOURCE_GROUP, STORAGE_ACCOUNT) if is_catalog_user(u)]
    result = [{
        "username": u.name,
        "folder": u.home_directory.split("/", 1)[1],
        "login": f"{STORAGE_ACCOUNT}.{u.name}",
        "host": f"{STORAGE_ACCOUNT}.blob.core.windows.net",
        "hasPassword": u.has_ssh_password,
    } for u in users]
    return ok(result)


@app.route(route="users", methods=["POST"])
def create_user(req: func.HttpRequest) -> func.HttpResponse:
    body = req.get_json()
    username = body.get("username", "").lower().strip()
    folder = body.get("folder", "").strip()
    if not username or not folder:
        return err("username and folder are required")
    if not username.isalnum():
        return err("username must contain lowercase letters and digits only")
    try:
        # Create folder in sftp-elg-catalog if it doesn't exist
        dls = DataLakeServiceClient(
            f"https://{STORAGE_ACCOUNT}.dfs.core.windows.net",
            credential=DefaultAzureCredential()
        )
        try:
            dls.get_file_system_client(CONTAINER).get_directory_client(folder).create_directory()
        except ResourceExistsError:
            pass  # folder already exists, fine

        client = get_client()
        client.local_users.create_or_update(
            RESOURCE_GROUP, STORAGE_ACCOUNT, username,
            LocalUser(home_directory=f"{CONTAINER}/{folder}", allow_acl_authorization=False),
        )
        result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
        audit("create", username, req)
        return ok({
            "username": username,
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
    if not get_catalog_user(client, username):
        return err("user not found", 404)
    result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("reset", username, req)
    return ok({"username": username, "login": f"{STORAGE_ACCOUNT}.{username}", "password": result.ssh_password})


@app.route(route="users/{username}/disable", methods=["POST"])
def disable_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    u = get_catalog_user(client, username)
    if not u:
        return err("user not found", 404)
    # Silently rotate password so existing credentials stop working; remove any SSH keys
    client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    u.ssh_authorized_keys = []
    client.local_users.create_or_update(RESOURCE_GROUP, STORAGE_ACCOUNT, username, u)
    audit("disable", username, req)
    return ok({"username": username, "status": "disabled"})


@app.route(route="users/{username}/enable", methods=["POST"])
def enable_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    if not get_catalog_user(client, username):
        return err("user not found", 404)
    result = client.local_users.regenerate_password(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("enable", username, req)
    return ok({"username": username, "login": f"{STORAGE_ACCOUNT}.{username}", "password": result.ssh_password})


@app.route(route="users/{username}", methods=["DELETE"])
def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get("username")
    client = get_client()
    if not get_catalog_user(client, username):
        return err("user not found", 404)
    client.local_users.delete(RESOURCE_GROUP, STORAGE_ACCOUNT, username)
    audit("delete", username, req)
    return ok({"username": username, "status": "deleted"})
