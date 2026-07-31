"""Shared fail-closed PostgreSQL runtime-role boundary checks."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

RuntimeRoleKind = Literal["control", "auth", "reconciler"]

_ROLE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_TENANT_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_CONTROL_VERSIONS: Final = (1, 2, 3, 4, 5, 6)
_AUTH_VERSIONS: Final = (2, 5, 6)


class _Cursor(Protocol):
    def fetchone(self) -> Mapping[str, Any] | None: ...

    def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class SecurityConnection(Protocol):
    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> _Cursor: ...


@dataclass(frozen=True, slots=True)
class RuntimeBoundaryExpectation:
    """The immutable deployment identity expected on one database pool."""

    tenant_id: str
    login_role: str
    role_kind: RuntimeRoleKind
    migration_owner_role: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not str
            or _TENANT_RE.fullmatch(self.tenant_id) is None
        ):
            raise ValueError("runtime boundary tenant is invalid")
        if (
            type(self.login_role) is not str
            or _ROLE_RE.fullmatch(self.login_role) is None
        ):
            raise ValueError("runtime boundary login role is invalid")
        if self.role_kind not in {"control", "auth", "reconciler"}:
            raise ValueError("runtime boundary role kind is invalid")
        if self.migration_owner_role is not None and (
            type(self.migration_owner_role) is not str
            or _ROLE_RE.fullmatch(self.migration_owner_role) is None
            or self.migration_owner_role == self.login_role
        ):
            raise ValueError("migration owner role is invalid")

    @property
    def schema_versions(self) -> tuple[int, ...]:
        return _AUTH_VERSIONS if self.role_kind == "auth" else _CONTROL_VERSIONS


_IDENTITY_QUERIES: Final[dict[RuntimeRoleKind, str]] = {
    "control": """
        SELECT
            session_user::text AS session_user,
            current_user::text AS current_user,
            current_role::text AS current_role,
            identity.login_role,
            identity.tenant_id,
            identity.role_kind,
            identity.schema_versions
        FROM control_assurance.runtime_identity() AS identity
    """,
    "reconciler": """
        SELECT
            session_user::text AS session_user,
            current_user::text AS current_user,
            current_role::text AS current_role,
            identity.login_role,
            identity.tenant_id,
            identity.role_kind,
            identity.schema_versions
        FROM control_assurance.runtime_identity() AS identity
    """,
    "auth": """
        SELECT
            session_user::text AS session_user,
            current_user::text AS current_user,
            current_role::text AS current_role,
            identity.login_role,
            identity.tenant_id,
            identity.role_kind,
            identity.schema_versions
        FROM control_assurance_auth.runtime_identity() AS identity
    """,
}


def runtime_identity_row(
    connection: SecurityConnection,
    expectation: RuntimeBoundaryExpectation,
) -> Mapping[str, Any] | None:
    """Read identity through the role-kind-specific security-definer routine."""

    return connection.execute(_IDENTITY_QUERIES[expectation.role_kind]).fetchone()


def identity_matches(
    row: Mapping[str, Any] | None,
    expectation: RuntimeBoundaryExpectation,
) -> bool:
    """Return whether a connection is exactly the configured bound login."""

    if not isinstance(row, Mapping):
        return False
    role = expectation.login_role
    versions = row.get("schema_versions")
    return (
        row.get("session_user") == role
        and row.get("current_user") == role
        and row.get("current_role") == role
        and row.get("login_role") == role
        and row.get("tenant_id") == expectation.tenant_id
        and row.get("role_kind") == expectation.role_kind
        and isinstance(versions, (list, tuple))
        and tuple(versions) == expectation.schema_versions
    )


_ROLE_POSTURE_QUERY: Final = """
    SELECT
        role.rolcanlogin,
        role.rolsuper,
        role.rolinherit,
        role.rolcreaterole,
        role.rolcreatedb,
        role.rolreplication,
        role.rolbypassrls,
        role.rolconfig IS NULL AS no_role_config,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = role.oid
               OR membership.roleid = role.oid
        ) AS no_memberships,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_parameter_acl AS parameter
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                parameter.paracl
            ) AS acl
            WHERE acl.grantee IN (0, role.oid)
        ) AS no_parameter_privileges,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            WHERE database.datdba = role.oid
        ) AS owns_no_database,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspowner = role.oid
        ) AS owns_no_schema,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            WHERE relation.relowner = role.oid
        ) AS owns_no_relation,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.proowner = role.oid
        ) AS owns_no_routine,
        NOT pg_catalog.has_database_privilege(
            session_user,
            current_database(),
            'CREATE'
        ) AS no_database_create,
        NOT pg_catalog.has_database_privilege(
            session_user,
            current_database(),
            'TEMPORARY'
        ) AS no_database_temp,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE pg_catalog.has_schema_privilege(
                session_user,
                namespace.oid,
                'CREATE'
            )
        ) AS no_schema_create,
        (
            SELECT owner.rolname = %s
            FROM pg_catalog.pg_database AS database
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = database.datdba
            WHERE database.datname = current_database()
        ) AS exact_database_owner,
        (
            SELECT count(*) = 3
               AND bool_and(owner.rolname = %s)
            FROM pg_catalog.pg_namespace AS namespace
            JOIN pg_catalog.pg_roles AS owner
              ON owner.oid = namespace.nspowner
            WHERE namespace.nspname IN (
                'control_assurance',
                'control_assurance_auth',
                'control_assurance_boundary'
            )
        ) AS exact_schema_owners,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            JOIN pg_catalog.pg_roles AS owner
              ON owner.oid = relation.relowner
            WHERE namespace.nspname IN (
                'control_assurance',
                'control_assurance_auth',
                'control_assurance_boundary'
            )
              AND owner.rolname <> %s
        ) AS exact_relation_owners,
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = routine.pronamespace
            JOIN pg_catalog.pg_roles AS owner
              ON owner.oid = routine.proowner
            WHERE namespace.nspname IN (
                'control_assurance',
                'control_assurance_auth',
                'control_assurance_boundary'
            )
              AND owner.rolname <> %s
        ) AS exact_routine_owners
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = session_user
"""

_ACL_QUERY: Final = """
    WITH runtime_role AS (
        SELECT oid
        FROM pg_catalog.pg_roles
        WHERE rolname = session_user
    ),
    managed_namespaces AS (
        SELECT oid, nspname, nspacl, nspowner
        FROM pg_catalog.pg_namespace
        WHERE nspname IN (
            'control_assurance',
            'control_assurance_auth',
            'control_assurance_boundary'
        )
    )
    SELECT
        CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE session_user::text END
            AS principal,
        'schema'::text AS object_kind,
        namespace.nspname::text AS object_name,
        acl.privilege_type,
        acl.is_grantable
    FROM managed_namespaces AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            namespace.nspacl,
            pg_catalog.acldefault('n', namespace.nspowner)
        )
    ) AS acl
    WHERE acl.grantee IN (0, (SELECT oid FROM runtime_role))

    UNION ALL

    SELECT
        CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE session_user::text END,
        CASE WHEN relation.relkind = 'S' THEN 'sequence' ELSE 'table' END,
        namespace.nspname || '.' || relation.relname,
        acl.privilege_type,
        acl.is_grantable
    FROM pg_catalog.pg_class AS relation
    JOIN managed_namespaces AS namespace
      ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            relation.relacl,
            pg_catalog.acldefault(
                CASE
                    WHEN relation.relkind = 'S' THEN 'S'::"char"
                    ELSE 'r'::"char"
                END,
                relation.relowner
            )
        )
    ) AS acl
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'S')
      AND acl.grantee IN (0, (SELECT oid FROM runtime_role))

    UNION ALL

    SELECT
        CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE session_user::text END,
        'column',
        namespace.nspname || '.' || relation.relname || '.' || attribute.attname,
        acl.privilege_type,
        acl.is_grantable
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = attribute.attrelid
    JOIN managed_namespaces AS namespace
      ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
    WHERE attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND acl.grantee IN (0, (SELECT oid FROM runtime_role))

    UNION ALL

    SELECT
        CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE session_user::text END,
        'function',
        namespace.nspname || '.' || routine.proname || '('
            || pg_catalog.replace(
                pg_catalog.oidvectortypes(routine.proargtypes),
                ', ',
                ','
            )
            || ')',
        acl.privilege_type,
        acl.is_grantable
    FROM pg_catalog.pg_proc AS routine
    JOIN managed_namespaces AS namespace
      ON namespace.oid = routine.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            routine.proacl,
            pg_catalog.acldefault('f', routine.proowner)
        )
    ) AS acl
    WHERE acl.grantee IN (0, (SELECT oid FROM runtime_role))

    ORDER BY 1, 2, 3, 4, 5
"""


def _acl(
    role: str,
    object_kind: str,
    object_name: str,
    privilege: str,
) -> tuple[str, str, str, str, bool]:
    return (role, object_kind, object_name, privilege, False)


def _expected_acls(
    expectation: RuntimeBoundaryExpectation,
) -> frozenset[tuple[str, str, str, str, bool]]:
    role = expectation.login_role
    if expectation.role_kind == "auth":
        return frozenset(
            {
                _acl(role, "schema", "control_assurance_auth", "USAGE"),
                *(
                    _acl(
                        role,
                        "function",
                        f"control_assurance_auth.{name}",
                        "EXECUTE",
                    )
                    for name in (
                        "runtime_identity()",
                        (
                            "reserve_login_admission("
                            "text,text,timestamp with time zone,integer,"
                            "integer,integer,integer,integer)"
                        ),
                        (
                            "finalize_login_admission("
                            "text,text,text,bytea,text,text,"
                            "timestamp with time zone,timestamp with time zone)"
                        ),
                        "cancel_login_admission(text)",
                        (
                            "consume_ready_authorization_transaction("
                            "text,timestamp with time zone,integer,integer,integer)"
                        ),
                        (
                            "create_browser_session("
                            "text,text,text,bytea,timestamp with time zone,"
                            "timestamp with time zone,integer)"
                        ),
                        (
                            "read_browser_session("
                            "text,timestamp with time zone)"
                        ),
                        "revoke_browser_session(text)",
                    )
                ),
            }
        )

    result = {
        _acl(role, "schema", "control_assurance", "USAGE"),
        _acl(
            role,
            "table",
            "control_assurance.schema_migrations",
            "SELECT",
        ),
        _acl(
            role,
            "function",
            "control_assurance.session_tenant()",
            "EXECUTE",
        ),
        _acl(
            role,
            "function",
            "control_assurance.runtime_identity()",
            "EXECUTE",
        ),
    }
    if expectation.role_kind == "control":
        tables = (
            "control_revisions",
            "approval_decisions",
            "active_deployments",
            "deployment_operations",
            "control_audit_events",
        )
        for table in tables:
            for privilege in ("SELECT", "INSERT"):
                result.add(
                    _acl(
                        role,
                        "table",
                        f"control_assurance.{table}",
                        privilege,
                    )
                )
        for column in (
            "state",
            "state_version",
            "submitted_at",
            "decided_at",
        ):
            result.add(
                _acl(
                    role,
                    "column",
                    f"control_assurance.control_revisions.{column}",
                    "UPDATE",
                )
            )
        for column in (
            "revision_id",
            "configuration_digest",
            "activated_by",
            "activated_at",
            "deployment_version",
        ):
            result.add(
                _acl(
                    role,
                    "column",
                    f"control_assurance.active_deployments.{column}",
                    "UPDATE",
                )
            )
    else:
        for table, privileges in (
            ("control_revisions", ("SELECT",)),
            ("deployment_operations", ("SELECT",)),
            ("control_audit_events", ("SELECT", "INSERT")),
        ):
            for privilege in privileges:
                result.add(
                    _acl(
                        role,
                        "table",
                        f"control_assurance.{table}",
                        privilege,
                    )
                )
        for column in (
            "state",
            "state_version",
            "attempt_count",
            "lease_fence",
            "lease_owner",
            "lease_token_digest",
            "leased_at",
            "lease_expires_at",
            "retry_at",
            "applied_at",
            "applied_configuration_digest",
            "target_receipt_digest",
            "failed_at",
            "failure_digest",
        ):
            result.add(
                _acl(
                    role,
                    "column",
                    f"control_assurance.deployment_operations.{column}",
                    "UPDATE",
                )
            )
    return frozenset(result)


def _acl_rows_match(
    rows: Sequence[Mapping[str, Any]],
    expectation: RuntimeBoundaryExpectation,
) -> bool:
    try:
        actual = frozenset(
            (
                row["principal"],
                row["object_kind"],
                row["object_name"],
                row["privilege_type"],
                row["is_grantable"],
            )
            for row in rows
        )
    except (KeyError, TypeError):
        return False
    return actual == _expected_acls(expectation)


def runtime_boundary_is_safe(
    connection: SecurityConnection,
    expectation: RuntimeBoundaryExpectation,
) -> bool:
    """Verify exact login posture, ownership, binding, lineage, and ACLs."""

    if expectation.migration_owner_role is None:
        raise ValueError("migration owner is required for boundary preflight")
    if not identity_matches(runtime_identity_row(connection, expectation), expectation):
        return False
    owner = expectation.migration_owner_role
    posture = connection.execute(
        _ROLE_POSTURE_QUERY,
        (owner, owner, owner, owner),
    ).fetchone()
    if not isinstance(posture, Mapping):
        return False
    if (
        posture.get("rolcanlogin") is not True
        or any(
            posture.get(attribute) is not False
            for attribute in (
                "rolsuper",
                "rolinherit",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
            )
        )
        or any(
            posture.get(check) is not True
            for check in (
                "no_role_config",
                "no_memberships",
                "no_parameter_privileges",
                "owns_no_database",
                "owns_no_schema",
                "owns_no_relation",
                "owns_no_routine",
                "no_database_create",
                "no_database_temp",
                "no_schema_create",
                "exact_database_owner",
                "exact_schema_owners",
                "exact_relation_owners",
                "exact_routine_owners",
            )
        )
    ):
        return False
    return _acl_rows_match(
        connection.execute(_ACL_QUERY).fetchall(),
        expectation,
    )


__all__ = [
    "RuntimeBoundaryExpectation",
    "RuntimeRoleKind",
    "identity_matches",
    "runtime_boundary_is_safe",
    "runtime_identity_row",
]
