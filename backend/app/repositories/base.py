"""Repository base classes.

Every tenant-owned repository method requires ``tenant_id`` and includes it in the query
(spec §9). Unscoped access exists only through explicitly named ``*_global`` methods.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.errors import ErrorCode, GatewayError
from app.core.ids import new_id, utcnow
from app.db import Database

MAX_PAGE = 200


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        offset = int(json.loads(raw)["o"])
        return max(0, offset)
    except Exception as exc:  # noqa: BLE001
        raise GatewayError(ErrorCode.VALIDATION_FAILED, "Invalid pagination cursor.") from exc


class Page(dict[str, Any]):
    """{'items': [...], 'next_cursor': str|None, 'total': int}"""


def _require_tenant(tenant_id: str | None) -> str:
    if not tenant_id or not isinstance(tenant_id, str):
        raise RuntimeError("tenant_id is required for tenant-scoped repository access")
    return tenant_id


class Repository:
    collection_name: str = ""
    id_prefix: str = "obj"

    def __init__(self, db: Database) -> None:
        self.db = db
        self.col = db[self.collection_name]

    async def _paginate(
        self,
        query: Mapping[str, Any],
        *,
        sort: list[tuple[str, int]] | None = None,
        limit: int = 50,
        cursor: str | None = None,
        projection: Mapping[str, Any] | None = None,
    ) -> Page:
        limit = max(1, min(limit, MAX_PAGE))
        offset = decode_cursor(cursor)
        total = await self.col.count_documents(query)
        find = self.col.find(query, projection).sort(sort or [("created_at", -1)]).skip(offset).limit(limit)
        items = [doc async for doc in find]
        nxt = encode_cursor(offset + limit) if offset + limit < total else None
        return Page(items=items, next_cursor=nxt, total=total)


class GlobalRepository(Repository):
    """For collections that are not tenant-owned (tenants, users, system settings)."""

    async def insert(self, doc: dict[str, Any]) -> dict[str, Any]:
        now = utcnow()
        doc = {"_id": doc.get("_id") or new_id(self.id_prefix), "created_at": now, "updated_at": now, **doc}
        try:
            await self.col.insert_one(doc)
        except DuplicateKeyError as exc:
            raise GatewayError(ErrorCode.CONFLICT, "A record with the same unique key already exists.") from exc
        return doc

    async def get(self, obj_id: str) -> dict[str, Any] | None:
        return await self.col.find_one({"_id": obj_id})

    async def find_one(self, query: Mapping[str, Any]) -> dict[str, Any] | None:
        return await self.col.find_one(query)

    async def list(self, query: Mapping[str, Any] | None = None, **kw: Any) -> Page:
        return await self._paginate(query or {}, **kw)

    async def update(self, obj_id: str, changes: Mapping[str, Any]) -> dict[str, Any] | None:
        return await self.col.find_one_and_update(
            {"_id": obj_id},
            {"$set": {**changes, "updated_at": utcnow()}},
            return_document=ReturnDocument.AFTER,
        )


class TenantScopedRepository(Repository):
    versioned: bool = False

    async def insert(self, tenant_id: str, doc: dict[str, Any]) -> dict[str, Any]:
        tenant_id = _require_tenant(tenant_id)
        now = utcnow()
        base: dict[str, Any] = {"_id": new_id(self.id_prefix), "created_at": now, "updated_at": now}
        if self.versioned:
            base["version"] = 1
        doc = {**base, **{k: v for k, v in doc.items() if k != "tenant_id"}, "tenant_id": tenant_id}
        try:
            await self.col.insert_one(doc)
        except DuplicateKeyError as exc:
            raise GatewayError(ErrorCode.CONFLICT, "A record with the same unique key already exists.") from exc
        return doc

    async def get(self, tenant_id: str, obj_id: str) -> dict[str, Any] | None:
        return await self.col.find_one({"_id": obj_id, "tenant_id": _require_tenant(tenant_id)})

    async def find_one(self, tenant_id: str, query: Mapping[str, Any]) -> dict[str, Any] | None:
        return await self.col.find_one({**query, "tenant_id": _require_tenant(tenant_id)})

    async def find_all(
        self, tenant_id: str, query: Mapping[str, Any] | None = None, limit: int = 5000
    ) -> list[dict[str, Any]]:
        q = {**(query or {}), "tenant_id": _require_tenant(tenant_id)}
        return [d async for d in self.col.find(q).limit(limit)]

    async def list(self, tenant_id: str, query: Mapping[str, Any] | None = None, **kw: Any) -> Page:
        return await self._paginate({**(query or {}), "tenant_id": _require_tenant(tenant_id)}, **kw)

    async def count(self, tenant_id: str, query: Mapping[str, Any] | None = None) -> int:
        return await self.col.count_documents({**(query or {}), "tenant_id": _require_tenant(tenant_id)})

    async def update(
        self,
        tenant_id: str,
        obj_id: str,
        changes: Mapping[str, Any],
        *,
        expected_version: int | None = None,
        extra_filter: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update a record. With ``expected_version`` the update is optimistic (409 on mismatch)."""
        query: dict[str, Any] = {"_id": obj_id, "tenant_id": _require_tenant(tenant_id), **(extra_filter or {})}
        if expected_version is not None:
            query["version"] = expected_version
        update: dict[str, Any] = {"$set": {**changes, "updated_at": utcnow()}}
        if self.versioned:
            update["$inc"] = {"version": 1}
        try:
            doc = await self.col.find_one_and_update(query, update, return_document=ReturnDocument.AFTER)
        except DuplicateKeyError as exc:
            raise GatewayError(ErrorCode.CONFLICT, "A record with the same unique key already exists.") from exc
        if doc is None:
            exists = await self.col.find_one({"_id": obj_id, "tenant_id": tenant_id}, {"_id": 1})
            if exists and (expected_version is not None or extra_filter):
                raise GatewayError(
                    ErrorCode.VERSION_CONFLICT, "The record was modified concurrently or is in the wrong state."
                )
            raise GatewayError(ErrorCode.NOT_FOUND, "Resource not found.")
        return doc

    async def delete(self, tenant_id: str, obj_id: str) -> bool:
        res = await self.col.delete_one({"_id": obj_id, "tenant_id": _require_tenant(tenant_id)})
        return res.deleted_count == 1
