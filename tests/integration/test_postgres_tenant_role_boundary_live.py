"""Live PostgreSQL 17 attacks against the deployment role/tenant boundary."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row

from assurance_lab.control_plane.postgres_security import (
    RuntimeBoundaryExpectation,
    runtime_boundary_is_safe,
)

_ADMIN_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_ADMIN_DSN")
_MIGRATION_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN")
_CONTROL_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_DSN")
_AUTH_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_DSN")
_RECONCILER_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_DSN"
)
_TENANT = os.environ.get("CONTROL_ASSURANCE_POSTGRES_TENANT")
_MIGRATION_ROLE = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_MIGRATION_ROLE"
)
_CONTROL_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE")
_AUTH_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE")
_RECONCILER_ROLE = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE"
)

_REQUIRED = (
    _ADMIN_DSN,
    _MIGRATION_DSN,
    _CONTROL_DSN,
    _AUTH_DSN,
    _RECONCILER_DSN,
    _TENANT,
    _MIGRATION_ROLE,
    _CONTROL_ROLE,
    _AUTH_ROLE,
    _RECONCILER_ROLE,
)
pytestmark = pytest.mark.skipif(
    not all(_REQUIRED),
    reason="separated PostgreSQL boundary DSNs and roles are not configured",
)


def _expectation(
    *,
    role: str,
    role_kind: str,
) -> RuntimeBoundaryExpectation:
    assert _TENANT is not None
    assert _MIGRATION_ROLE is not None
    return RuntimeBoundaryExpectation(
        tenant_id=_TENANT,
        login_role=role,
        role_kind=role_kind,  # type: ignore[arg-type]
        migration_owner_role=_MIGRATION_ROLE,
    )


def _safe(dsn: str, expectation: RuntimeBoundaryExpectation) -> bool:
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        return runtime_boundary_is_safe(connection, expectation)


def _configure(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    assert _TENANT is not None
    assert _CONTROL_ROLE is not None
    assert _AUTH_ROLE is not None
    assert _RECONCILER_ROLE is not None
    connection.execute(
        """
        SELECT control_assurance_boundary.configure_runtime_roles(
            %s,
            %s::name,
            %s::name,
            %s::name
        )
        """,
        (_TENANT, _CONTROL_ROLE, _AUTH_ROLE, _RECONCILER_ROLE),
    )


@pytest.fixture(scope="module", autouse=True)
def _installed_boundary() -> Iterator[None]:
    assert _ADMIN_DSN is not None
    assert _MIGRATION_DSN is not None
    schema = (
        Path(__file__).parents[2]
        / "deploy"
        / "postgres"
        / "control-plane-schema.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
        version = admin.execute(
            "SELECT current_setting('server_version_num')::integer"
        ).fetchone()
        assert version is not None and version[0] >= 170000
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
        migration.execute(schema)
        _configure(migration)
    yield
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
        _configure(migration)


def test_exact_minimum_roles_and_schema_separation() -> None:
    assert _CONTROL_DSN is not None
    assert _AUTH_DSN is not None
    assert _RECONCILER_DSN is not None
    assert _CONTROL_ROLE is not None
    assert _AUTH_ROLE is not None
    assert _RECONCILER_ROLE is not None

    assert _safe(
        _CONTROL_DSN,
        _expectation(role=_CONTROL_ROLE, role_kind="control"),
    )
    assert _safe(
        _AUTH_DSN,
        _expectation(role=_AUTH_ROLE, role_kind="auth"),
    )
    assert _safe(
        _RECONCILER_DSN,
        _expectation(role=_RECONCILER_ROLE, role_kind="reconciler"),
    )

    denied = (
        (_CONTROL_DSN, "SELECT * FROM control_assurance_auth.schema_migrations"),
        (_AUTH_DSN, "SELECT * FROM control_assurance_auth.schema_migrations"),
        (_AUTH_DSN, "SELECT * FROM control_assurance.schema_migrations"),
        (
            _AUTH_DSN,
            "SELECT * FROM control_assurance_boundary.runtime_role_bindings",
        ),
        (
            _RECONCILER_DSN,
            "SELECT * FROM control_assurance_auth.schema_migrations",
        ),
        (_CONTROL_DSN, "CREATE TEMPORARY TABLE boundary_escape(value integer)"),
        (_AUTH_DSN, "CREATE TABLE public.boundary_escape(value integer)"),
    )
    for dsn, statement in denied:
        with (
            psycopg.connect(dsn, autocommit=True) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute(statement)


def test_guc_spoof_set_role_and_cross_tenant_attempts_fail_closed() -> None:
    assert _ADMIN_DSN is not None
    assert _MIGRATION_DSN is not None
    assert _CONTROL_DSN is not None
    assert _AUTH_DSN is not None
    assert _CONTROL_ROLE is not None
    assert _AUTH_ROLE is not None

    with psycopg.connect(_CONTROL_DSN, autocommit=True) as control:
        control.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, false)",
            ("spoofed-tenant",),
        )
        tenant = control.execute(
            "SELECT control_assurance.session_tenant()"
        ).fetchone()
        assert tenant == (_TENANT,)

    with (
        psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration,
        pytest.raises(psycopg.errors.UniqueViolation),
    ):
        migration.execute(
            """
            SELECT control_assurance_boundary.configure_runtime_roles(
                'other-tenant',
                %s::name,
                %s::name,
                %s::name
            )
            """,
            (_CONTROL_ROLE, _AUTH_ROLE, _RECONCILER_ROLE),
        )

    with (
        psycopg.connect(_AUTH_DSN, autocommit=True) as auth,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        auth.execute(
            """
            SELECT control_assurance_auth.create_browser_session(
                %s,
                'other-tenant',
                %s,
                %s,
                transaction_timestamp(),
                transaction_timestamp() + interval '1 hour',
                1
            )
            """,
            (
                f"sha256:{'1' * 64}",
                f"sha256:{'2' * 64}",
                b"{}",
            ),
        )

    with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(_AUTH_ROLE),
                sql.Identifier(_CONTROL_ROLE),
            )
        )
    try:
        with psycopg.connect(_CONTROL_DSN, autocommit=True) as control:
            control.execute(
                sql.SQL("SET ROLE {}").format(sql.Identifier(_AUTH_ROLE))
            )
            identities = control.execute(
                "SELECT count(*) FROM control_assurance_auth.runtime_identity()"
            ).fetchone()
            assert identities == (0,)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                control.execute(
                    """
                    SELECT control_assurance_auth.cancel_login_admission(%s)
                    """,
                    (f"sha256:{'3' * 64}",),
                )
        assert not _safe(
            _CONTROL_DSN,
            _expectation(role=_CONTROL_ROLE, role_kind="control"),
        )
    finally:
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(_AUTH_ROLE),
                    sql.Identifier(_CONTROL_ROLE),
                )
            )


def test_configure_owner_public_injection_and_dangerous_roles() -> None:
    assert _ADMIN_DSN is not None
    assert _MIGRATION_DSN is not None
    assert _CONTROL_DSN is not None
    assert _AUTH_ROLE is not None
    assert _RECONCILER_ROLE is not None
    suffix = uuid.uuid4().hex[:8]
    super_role = f"boundary_super_{suffix}"
    bypass_role = f"boundary_bypass_{suffix}"
    injection_role = f'boundary_bad_";select_{suffix}--'

    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
        _configure(migration)
        _configure(migration)
        counts = migration.execute(
            """
            SELECT
                (SELECT count(*)
                 FROM control_assurance_boundary.deployment_tenant),
                (SELECT count(*)
                 FROM control_assurance_boundary.runtime_role_bindings)
            """
        ).fetchone()
        assert counts == (1, 3)

    with (
        psycopg.connect(_CONTROL_DSN, autocommit=True) as control,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        _configure(control)

    with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN SUPERUSER NOINHERIT").format(
                sql.Identifier(super_role)
            )
        )
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER BYPASSRLS NOINHERIT"
            ).format(sql.Identifier(bypass_role))
        )
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT"
            ).format(sql.Identifier(injection_role))
        )
    try:
        with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
            for candidate in (super_role, bypass_role, injection_role):
                with pytest.raises(psycopg.Error):
                    migration.execute(
                        """
                        SELECT control_assurance_boundary.configure_runtime_roles(
                            %s,
                            %s::name,
                            %s::name,
                            %s::name
                        )
                        """,
                        (
                            _TENANT,
                            candidate,
                            _AUTH_ROLE,
                            _RECONCILER_ROLE,
                        ),
                    )
            marker = migration.execute(
                "SELECT to_regnamespace(%s)",
                (f"select_{suffix}",),
            ).fetchone()
            assert marker == (None,)
    finally:
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            for role in (super_role, bypass_role, injection_role):
                admin.execute(
                    sql.SQL("DROP ROLE {}").format(sql.Identifier(role))
                )


def test_startup_rejects_excess_grants_attributes_and_ownership() -> None:
    assert _ADMIN_DSN is not None
    assert _MIGRATION_DSN is not None
    assert _CONTROL_DSN is not None
    assert _AUTH_DSN is not None
    assert _CONTROL_ROLE is not None
    assert _AUTH_ROLE is not None
    assert _MIGRATION_ROLE is not None
    expectation = _expectation(role=_CONTROL_ROLE, role_kind="control")

    mutations = (
        (
            sql.SQL("GRANT USAGE ON SCHEMA control_assurance_auth TO {}").format(
                sql.Identifier(_CONTROL_ROLE)
            ),
            sql.SQL(
                "REVOKE USAGE ON SCHEMA control_assurance_auth FROM {}"
            ).format(sql.Identifier(_CONTROL_ROLE)),
        ),
        (
            sql.SQL("ALTER ROLE {} BYPASSRLS").format(
                sql.Identifier(_CONTROL_ROLE)
            ),
            sql.SQL("ALTER ROLE {} NOBYPASSRLS").format(
                sql.Identifier(_CONTROL_ROLE)
            ),
        ),
        (
            sql.SQL(
                "GRANT SET ON PARAMETER session_replication_role TO {}"
            ).format(sql.Identifier(_CONTROL_ROLE)),
            sql.SQL(
                "REVOKE SET ON PARAMETER session_replication_role FROM {}"
            ).format(sql.Identifier(_CONTROL_ROLE)),
        ),
        (
            sql.SQL(
                "ALTER TABLE control_assurance.control_revisions OWNER TO {}"
            ).format(sql.Identifier(_CONTROL_ROLE)),
            sql.SQL(
                "ALTER TABLE control_assurance.control_revisions OWNER TO {}"
            ).format(sql.Identifier(_MIGRATION_ROLE)),
        ),
    )
    for apply, restore in mutations:
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(apply)
        try:
            assert not _safe(_CONTROL_DSN, expectation)
        finally:
            with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
                admin.execute(restore)
            with psycopg.connect(
                _MIGRATION_DSN,
                autocommit=True,
            ) as migration:
                _configure(migration)

    assert _safe(_CONTROL_DSN, expectation)

    auth_expectation = _expectation(role=_AUTH_ROLE, role_kind="auth")
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
        migration.execute(
            """
            CREATE FUNCTION control_assurance_auth.runtime_identity(integer)
            RETURNS integer
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT $1'
            """
        )
        migration.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION "
                "control_assurance_auth.runtime_identity(integer) TO {}"
            ).format(sql.Identifier(_AUTH_ROLE))
        )
    try:
        assert not _safe(_AUTH_DSN, auth_expectation)
    finally:
        with psycopg.connect(_MIGRATION_DSN, autocommit=True) as migration:
            migration.execute(
                """
                DROP FUNCTION
                    control_assurance_auth.runtime_identity(integer)
                """
            )
            _configure(migration)

    assert _safe(_AUTH_DSN, auth_expectation)
