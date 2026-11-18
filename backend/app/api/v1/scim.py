"""SCIM 2.0 service provider (RFC 7644) under /api/v1/scim/v2, and its platform-admin configuration.

Errors under /api/v1/scim/v2/ are rendered in SCIM's format by the error handlers (app/api/middleware.py)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from app.api.deps import client_ip, get_container, require_user
from app.container import Container
from app.core.errors import ScimError
from app.core.identity import Principal, Role
from app.models.scim import ScimConfigUpdate
from app.services.scim_service import GROUP_SCHEMA, MAX_COUNT, USER_SCHEMA, ScimService

router = APIRouter(tags=["scim"])
MEDIA = "application/scim+json"


# ---------------------------------------------------------------------- administration (console)
@router.get("/scim/config")
async def get_config(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.scim.admin_view()


@router.put("/scim/config")
async def put_config(body: ScimConfigUpdate, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.scim.update_config(p, body.enabled, body.link_claim, body.groups_authoritative,
                                       body.match_group_display_name)


@router.post("/scim/token")
async def rotate_token(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    """A new bearer token for the identity provider, shown once. The previous token stops working."""
    return await c.scim.rotate_token(p)


@router.delete("/scim/token")
async def revoke_token(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.scim.revoke_token(p)


# ---------------------------------------------------------------------- SCIM protocol (identity provider)
def scim(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    if status == 204:
        return Response(status_code=204)
    return JSONResponse(body, status_code=status, media_type=MEDIA, headers=headers)


async def _svc(request: Request, c: Container = Depends(get_container)) -> ScimService:
    await c.scim.authenticate(request.headers.get("authorization", ""), client_ip(request))
    return c.scim


async def _json(request: Request) -> dict[str, Any]:
    try:
        body = json.loads(await request.body() or b"null")
    except ValueError:
        raise ScimError(400, "the body is not valid JSON", "invalidSyntax") from None
    if not isinstance(body, dict):
        raise ScimError(400, "the body must be a JSON object", "invalidSyntax")
    return body


def _page(request: Request) -> tuple[int, int]:
    try:
        start = int(request.query_params.get("startIndex", "1"))
        count = int(request.query_params.get("count", "100"))
    except ValueError:
        raise ScimError(400, "startIndex and count must be integers", "invalidValue") from None
    return start, min(count, MAX_COUNT)


def _members(request: Request) -> bool:
    excluded = request.query_params.get("excludedAttributes", "").lower()
    attributes = request.query_params.get("attributes", "").lower()
    return "members" not in excluded and (not attributes or "members" in attributes)


def _attr(name: str, type_: str = "string", **kw: Any) -> dict[str, Any]:
    return {"name": name, "type": type_, "multiValued": False, "required": False, "caseExact": False,
            "mutability": "readWrite", "returned": "default", "uniqueness": "none", **kw}


RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
RESOURCE_TYPES = [
    {"schemas": [RESOURCE_TYPE], "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA,
     "meta": {"resourceType": "ResourceType"}},
    {"schemas": [RESOURCE_TYPE], "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": GROUP_SCHEMA,
     "meta": {"resourceType": "ResourceType"}},
]
SCHEMAS = [
    {"id": USER_SCHEMA, "name": "User", "description": "User account", "meta": {"resourceType": "Schema"},
     "attributes": [
         _attr("userName", required=True, uniqueness="server"), _attr("externalId", caseExact=True),
         _attr("displayName"), _attr("active", "boolean"),
         _attr("name", "complex", subAttributes=[_attr("formatted"), _attr("givenName"), _attr("familyName")]),
         _attr("emails", "complex", multiValued=True,
               subAttributes=[_attr("value"), _attr("type"), _attr("primary", "boolean")]),
     ]},
    {"id": GROUP_SCHEMA, "name": "Group", "description": "Group", "meta": {"resourceType": "Schema"},
     "attributes": [
         _attr("displayName", required=True, uniqueness="server"), _attr("externalId", caseExact=True),
         _attr("members", "complex", multiValued=True,
               subAttributes=[_attr("value", mutability="immutable"), _attr("display", mutability="readOnly")]),
     ]},
]


@router.get("/scim/v2/ServiceProviderConfig")
async def service_provider_config(svc: ScimService = Depends(_svc)) -> Response:
    return scim({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "primary": True,
                                   "description": "The token generated under Settings, Provisioning (SCIM)."}],
        "meta": {"resourceType": "ServiceProviderConfig"},
    })


@router.get("/scim/v2/ResourceTypes")
async def resource_types(svc: ScimService = Depends(_svc)) -> Response:
    return scim(svc.list_response(RESOURCE_TYPES, len(RESOURCE_TYPES), 1))


@router.get("/scim/v2/Schemas")
async def schemas(svc: ScimService = Depends(_svc)) -> Response:
    return scim(svc.list_response(SCHEMAS, len(SCHEMAS), 1))


@router.get("/scim/v2/Users")
async def list_users(request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.list_users(request.query_params.get("filter"), *_page(request)))


@router.post("/scim/v2/Users")
async def create_user(request: Request, svc: ScimService = Depends(_svc)) -> Response:
    user = await svc.create_user(await _json(request))
    return scim(user, 201, {"Location": user["meta"]["location"]})


@router.get("/scim/v2/Users/{user_id}")
async def get_user(user_id: str, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.get_user(user_id))


@router.put("/scim/v2/Users/{user_id}")
async def replace_user(user_id: str, request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.replace_user(user_id, await _json(request)))


@router.patch("/scim/v2/Users/{user_id}")
async def patch_user(user_id: str, request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.patch_user(user_id, await _json(request)))


@router.delete("/scim/v2/Users/{user_id}")
async def delete_user(user_id: str, svc: ScimService = Depends(_svc)) -> Response:
    await svc.delete_user(user_id)
    return scim(None, 204)


@router.get("/scim/v2/Groups")
async def list_groups(request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.list_groups(request.query_params.get("filter"), *_page(request), _members(request)))


@router.post("/scim/v2/Groups")
async def create_group(request: Request, svc: ScimService = Depends(_svc)) -> Response:
    group = await svc.create_group(await _json(request))
    return scim(group, 201, {"Location": group["meta"]["location"]})


@router.get("/scim/v2/Groups/{group_id}")
async def get_group(group_id: str, request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.get_group(group_id, _members(request)))


@router.put("/scim/v2/Groups/{group_id}")
async def replace_group(group_id: str, request: Request, svc: ScimService = Depends(_svc)) -> Response:
    return scim(await svc.replace_group(group_id, await _json(request)))


@router.patch("/scim/v2/Groups/{group_id}")
async def patch_group(group_id: str, request: Request, svc: ScimService = Depends(_svc)) -> Response:
    await svc.patch_group(group_id, await _json(request))
    return scim(None, 204)  # RFC 7644 section 3.5.2 allows 204 without a body; Entra ID and Okta accept it


@router.delete("/scim/v2/Groups/{group_id}")
async def delete_group(group_id: str, svc: ScimService = Depends(_svc)) -> Response:
    await svc.delete_group(group_id)
    return scim(None, 204)
