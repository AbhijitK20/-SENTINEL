# SPDX-License-Identifier: Apache-2.0
"""Authentication and authorization for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Permission(Enum):
    """Permission levels for RBAC."""

    FORECAST_READ = "forecast:read"
    FORECAST_WRITE = "forecast:write"
    ALERT_READ = "alert:read"
    ALERT_WRITE = "alert:write"
    CASE_READ = "case:read"
    CASE_WRITE = "case:write"
    CASE_ASSIGN = "case:assign"
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    MODEL_READ = "model:read"
    MODEL_WRITE = "model:write"
    AUDIT_READ = "audit:read"
    SYSTEM_ADMIN = "system:admin"


class Role(Enum):
    """Role definitions for RBAC."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ENGINEER = "engineer"
    ADMIN = "admin"
    OWNER = "owner"


# Role to permissions mapping
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.FORECAST_READ,
        Permission.ALERT_READ,
        Permission.CASE_READ,
    },
    Role.ANALYST: {
        Permission.FORECAST_READ,
        Permission.ALERT_READ,
        Permission.ALERT_WRITE,
        Permission.CASE_READ,
        Permission.CASE_WRITE,
        Permission.USER_READ,
    },
    Role.ENGINEER: {
        Permission.FORECAST_READ,
        Permission.FORECAST_WRITE,
        Permission.ALERT_READ,
        Permission.ALERT_WRITE,
        Permission.CASE_READ,
        Permission.CASE_WRITE,
        Permission.CASE_ASSIGN,
        Permission.USER_READ,
        Permission.MODEL_READ,
        Permission.MODEL_WRITE,
    },
    Role.ADMIN: {
        Permission.FORECAST_READ,
        Permission.FORECAST_WRITE,
        Permission.ALERT_READ,
        Permission.ALERT_WRITE,
        Permission.CASE_READ,
        Permission.CASE_WRITE,
        Permission.CASE_ASSIGN,
        Permission.USER_READ,
        Permission.USER_WRITE,
        Permission.TENANT_READ,
        Permission.TENANT_WRITE,
        Permission.MODEL_READ,
        Permission.MODEL_WRITE,
        Permission.AUDIT_READ,
    },
    Role.OWNER: {p for p in Permission},  # All permissions
}


@dataclass
class Subject:
    """Authentication subject (user or service)."""

    id: str
    tenant_id: str
    role: Role
    email: str = ""
    permissions: set[Permission] | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if subject has a permission."""
        if self.permissions is not None:
            return permission in self.permissions
        return permission in ROLE_PERMISSIONS.get(self.role, set())


@dataclass
class Resource:
    """Resource for authorization."""

    type: str
    id: str
    tenant_id: str


@dataclass
class AuthorizationContext:
    """Context for authorization decisions."""

    subject: Subject
    resource: Resource
    action: str
    ip_address: str = ""
    trace_id: str = ""


def check_authorization(ctx: AuthorizationContext) -> bool:
    """Check if authorization is allowed.

    Deny-by-default: if no rule matches, deny.
    """
    # Tenant must match
    if ctx.subject.tenant_id != ctx.resource.tenant_id:
        return False

    # Check permission based on resource type and action
    permission = _get_permission(ctx.resource.type, ctx.action)
    if permission is None:
        return False

    return ctx.subject.has_permission(permission)


def _get_permission(resource_type: str, action: str) -> Permission | None:
    """Map resource type and action to permission."""
    mapping = {
        ("forecast", "read"): Permission.FORECAST_READ,
        ("forecast", "write"): Permission.FORECAST_WRITE,
        ("alert", "read"): Permission.ALERT_READ,
        ("alert", "write"): Permission.ALERT_WRITE,
        ("case", "read"): Permission.CASE_READ,
        ("case", "write"): Permission.CASE_WRITE,
        ("case", "assign"): Permission.CASE_ASSIGN,
        ("user", "read"): Permission.USER_READ,
        ("user", "write"): Permission.USER_WRITE,
        ("tenant", "read"): Permission.TENANT_READ,
        ("tenant", "write"): Permission.TENANT_WRITE,
        ("model", "read"): Permission.MODEL_READ,
        ("model", "write"): Permission.MODEL_WRITE,
        ("audit", "read"): Permission.AUDIT_READ,
        ("system", "admin"): Permission.SYSTEM_ADMIN,
    }
    return mapping.get((resource_type, action))
