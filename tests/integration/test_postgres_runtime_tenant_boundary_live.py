"""Opt-in PostgreSQL 17 adversarial tests for runtime database identities.

This test needs an empty, disposable PostgreSQL 17 database and a superuser
DSN. It creates real LOGIN roles so ``session_user`` is the credential identity
PostgreSQL authenticated, rather than a value supplied by the application.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

_ADMIN_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_BOUNDARY_ADMIN_DSN")
pytestmark = pytest.mark.skipif(
    not _ADMIN_DSN,
    reason="CONTROL_ASSURANCE_POSTGRES_BOUNDARY_ADMIN_DSN is not configured",
)

_DOCUMENT = b"{}"
_DOCUMENT_DIGEST = f"sha256:{hashlib.sha256(_DOCUMENT).hexdigest()}"


def _sql() -> Any:
    return importlib.import_module("psycopg.sql")


def _install_schemas(connection: Any) -> None:
    root = Path(__file__).parents[2] / "deploy" / "postgres"
    for filename in (
        "runtime-schema.sql",
        "execution-journal-schema.sql",
        "pam-journal-schema.sql",
    ):
        connection.execute((root / filename).read_text(encoding="utf-8"))


def _role_dsn(admin_dsn: str, role: str, password: str) -> str:
    psycopg = importlib.import_module("psycopg")
    return cast(
        str,
        psycopg.conninfo.make_conninfo(
            admin_dsn,
            user=role,
            password=password,
        ),
    )


def _create_role(
    connection: Any,
    role: str,
    password: str,
    *,
    superuser: bool = False,
    bypass_rls: bool = False,
) -> None:
    sql = _sql()
    connection.execute(
        sql.SQL(
            "CREATE ROLE {} LOGIN PASSWORD {} "
            "{} {} NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION"
        ).format(
            sql.Identifier(role),
            sql.Literal(password),
            sql.SQL("SUPERUSER" if superuser else "NOSUPERUSER"),
            sql.SQL("BYPASSRLS" if bypass_rls else "NOBYPASSRLS"),
        )
    )


def _configure_role(
    connection: Any,
    schema: str,
    tenant: str,
    role: str,
    kind: str,
) -> None:
    sql = _sql()
    row = connection.execute(
        sql.SQL(
            "SELECT {}.configure_login_role(%s, %s::name, %s)"
        ).format(sql.Identifier(schema)),
        (tenant, role, kind),
    ).fetchone()
    assert row == (True,)


def _configure_namespace(
    connection: Any,
    namespace: str,
    tenant: str,
    purpose: str,
) -> None:
    row = connection.execute(
        """
        SELECT control_assurance_pam.configure_journal_namespace(
            %s, %s, %s
        )
        """,
        (namespace, tenant, purpose),
    ).fetchone()
    assert row == (True,)


def _grant_static(connection: Any, statement: str, role: str) -> None:
    connection.execute(
        _sql().SQL(statement).format(role=_sql().Identifier(role))
    )


def _assert_admitted(
    dsn: str,
    schema: str,
    tenant: str,
    role: str,
    kind: str,
) -> None:
    psycopg = importlib.import_module("psycopg")
    sql = _sql()
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            sql.SQL(
                "SELECT {}.assert_session_principal("
                "%s, %s, %s, current_user, session_user)"
            ).format(sql.Identifier(schema)),
            (tenant, role, kind),
        ).fetchone()
    assert row == (True,)


def _insert_runtime_profile(dsn: str, tenant: str) -> None:
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(dsn) as connection:
        connection.execute(
            """
            INSERT INTO control_assurance_runtime.control_profiles (
                tenant_id, profile_id, profile_digest, media_type,
                profile_bytes, registered_at, registered_by
            )
            VALUES (%s, %s, %s, 'application/json', %s, %s, %s)
            """,
            (
                tenant,
                "boundary-v1",
                _DOCUMENT_DIGEST,
                _DOCUMENT,
                datetime(2026, 7, 30, tzinfo=UTC),
                "boundary-live-test",
            ),
        )


def _insert_execution(dsn: str, tenant: str) -> None:
    psycopg = importlib.import_module("psycopg")
    window_start = datetime(2026, 7, 30, tzinfo=UTC)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            """
            INSERT INTO control_assurance_execution.executions (
                tenant_id, run_id, stable_request_digest,
                stable_request_bytes, run_request_bytes, control_id,
                deployment_operation_id, deployment_operation_sequence,
                deployment_receipt_digest, revision_id,
                configuration_digest, configuration_bytes,
                control_profile_id, control_profile_digest,
                control_profile_media_type, control_profile_bytes,
                window_start, window_end, execution_plan_digest,
                execution_plan_bytes, highest_lease_fence,
                highest_attempt_count
            )
            VALUES (
                %s, %s, %s, %s, %s, 'boundary', %s, 1, %s, %s,
                %s, %s, 'boundary-v1', %s, 'application/json', %s,
                %s, %s, %s, %s, 1, 1
            )
            """,
            (
                tenant,
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
                _DOCUMENT,
                _DOCUMENT,
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
                _DOCUMENT,
                _DOCUMENT_DIGEST,
                _DOCUMENT,
                window_start,
                window_start + timedelta(minutes=1),
                _DOCUMENT_DIGEST,
                _DOCUMENT,
            ),
        )
        connection.execute(
            """
            INSERT INTO control_assurance_execution.execution_attempts (
                tenant_id, run_id, lease_fence, attempt_count, worker_id,
                lease_token_digest, state
            )
            VALUES (%s, %s, 1, 1, 'boundary-worker', %s, 'prepared')
            """,
            (tenant, _DOCUMENT_DIGEST, _DOCUMENT_DIGEST),
        )


def _insert_pam_lease(dsn: str, namespace: str, marker: str) -> None:
    psycopg = importlib.import_module("psycopg")
    lease_id = hashlib.sha256(marker.encode()).hexdigest()
    with psycopg.connect(dsn) as connection:
        connection.execute(
            """
            INSERT INTO control_assurance_pam.elastic_jit_leases (
                journal_namespace_digest, lease_id, key_name, index_alias,
                request_digest, endpoint_origin_digest,
                role_descriptor_digest, ttl_seconds, state,
                created_epoch_millis
            )
            VALUES (
                %s, %s, %s, '.alerts-security.alerts-default',
                %s, %s, %s, 900, 'prepared', 1700000000000
            )
            """,
            (
                namespace,
                lease_id,
                f"control-assurance-{lease_id[:32]}",
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
                _DOCUMENT_DIGEST,
            ),
        )


def _expect_privilege_failure(call: Any) -> None:
    psycopg = importlib.import_module("psycopg")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        call()


def test_postgres_17_server_asserted_tenant_and_role_boundary() -> None:
    assert _ADMIN_DSN is not None
    psycopg = importlib.import_module("psycopg")
    suffix = uuid.uuid4().hex[:10]
    tenant_a = f"bank-a-{suffix}"
    tenant_b = f"bank-b-{suffix}"
    password = f"boundary-{uuid.uuid4().hex}"
    roles = {
        "runtime_a": f"ca_rt_a_{suffix}",
        "runtime_b": f"ca_rt_b_{suffix}",
        "registrar_a": f"ca_reg_a_{suffix}",
        "registrar_b": f"ca_reg_b_{suffix}",
        "reconciler_a": f"ca_recon_a_{suffix}",
        "runtime_auditor": f"ca_rt_audit_{suffix}",
        "execution_a": f"ca_ex_a_{suffix}",
        "execution_b": f"ca_ex_b_{suffix}",
        "execution_recovery": f"ca_ex_rec_{suffix}",
        "execution_auditor": f"ca_ex_audit_{suffix}",
        "pam_a": f"ca_pam_a_{suffix}",
        "pam_b": f"ca_pam_b_{suffix}",
        "pam_recovery": f"ca_pam_rec_{suffix}",
        "pam_auditor": f"ca_pam_audit_{suffix}",
        "owner": f"ca_owner_{suffix}",
        "super": f"ca_super_{suffix}",
        "bypass": f"ca_bypass_{suffix}",
        "switch": f"ca_switch_{suffix}",
    }
    namespace_a = f"sha256:{hashlib.sha256(f'{suffix}:a'.encode()).hexdigest()}"
    namespace_b = f"sha256:{hashlib.sha256(f'{suffix}:b'.encode()).hexdigest()}"
    namespace_unmapped = (
        f"sha256:{hashlib.sha256(f'{suffix}:unmapped'.encode()).hexdigest()}"
    )
    scratch_schema = f"boundary_scratch_{suffix}"
    probe_view = f"boundary_view_{suffix}"
    probe_sequence = f"boundary_sequence_{suffix}"
    probe_function = f"boundary_probe_{suffix}"
    database_name = ""

    with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
        version = int(admin.execute("SHOW server_version_num").fetchone()[0])
        assert 170000 <= version < 180000
        database_name = admin.execute(
            "SELECT current_database()"
        ).fetchone()[0]
        _install_schemas(admin)
        for key, role in roles.items():
            _create_role(
                admin,
                role,
                password,
                superuser=key == "super",
                bypass_rls=key == "bypass",
            )
        runtime_roles = {
            roles["runtime_a"]: (tenant_a, "worker"),
            roles["runtime_b"]: (tenant_b, "worker"),
            roles["registrar_a"]: (tenant_a, "registrar"),
            roles["registrar_b"]: (tenant_b, "registrar"),
            roles["reconciler_a"]: (tenant_a, "reconciler"),
            roles["runtime_auditor"]: (tenant_a, "auditor"),
            roles["owner"]: (tenant_a, "worker"),
        }
        execution_roles = {
            roles["execution_a"]: (tenant_a, "worker"),
            roles["execution_b"]: (tenant_b, "worker"),
            roles["execution_recovery"]: (tenant_a, "recovery"),
            roles["execution_auditor"]: (tenant_a, "auditor"),
        }
        pam_roles = {
            roles["pam_a"]: (tenant_a, "broker"),
            roles["pam_b"]: (tenant_b, "broker"),
            roles["pam_recovery"]: (tenant_a, "recovery"),
            roles["pam_auditor"]: (tenant_a, "auditor"),
        }
        for role, (tenant, kind) in runtime_roles.items():
            _configure_role(
                admin,
                "control_assurance_runtime",
                tenant,
                role,
                kind,
            )
        for role, (tenant, kind) in execution_roles.items():
            _configure_role(
                admin,
                "control_assurance_execution",
                tenant,
                role,
                kind,
            )
        for role, (tenant, kind) in pam_roles.items():
            _configure_role(
                admin,
                "control_assurance_pam",
                tenant,
                role,
                kind,
            )
        _configure_namespace(
            admin,
            namespace_a,
            tenant_a,
            "elastic-jit-api-key",
        )
        _configure_namespace(
            admin,
            namespace_b,
            tenant_b,
            "elastic-jit-api-key",
        )
        for key in ("super", "bypass"):
            _expect_privilege_failure(
                lambda key=key: _configure_role(
                    admin,
                    "control_assurance_runtime",
                    tenant_a,
                    roles[key],
                    "worker",
                )
            )
        admin.execute(
            "CREATE TABLE control_assurance_runtime.owner_probe (id integer)"
        )
        admin.execute(
            _sql().SQL(
                "ALTER TABLE control_assurance_runtime.owner_probe OWNER TO {}"
            ).format(_sql().Identifier(roles["owner"]))
        )
        admin.execute(
            _sql().SQL("CREATE SCHEMA {}").format(
                _sql().Identifier(scratch_schema)
            )
        )
        admin.execute(
            _sql().SQL(
                "CREATE VIEW control_assurance_runtime.{} AS SELECT 1 AS value"
            ).format(_sql().Identifier(probe_view))
        )
        admin.execute(
            _sql().SQL(
                "CREATE SEQUENCE control_assurance_runtime.{}"
            ).format(_sql().Identifier(probe_sequence))
        )
        admin.execute(
            _sql().SQL(
                "CREATE FUNCTION control_assurance_runtime.{}(text) "
                "RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT $1'"
            ).format(_sql().Identifier(probe_function))
        )
        admin.execute(
            _sql().SQL(
                "REVOKE ALL ON FUNCTION "
                "control_assurance_runtime.{}(text) FROM PUBLIC"
            ).format(_sql().Identifier(probe_function))
        )

    dsns = {
        key: _role_dsn(_ADMIN_DSN, role, password)
        for key, role in roles.items()
        if key != "switch"
    }
    try:
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )
        _assert_admitted(
            dsns["execution_a"],
            "control_assurance_execution",
            tenant_a,
            roles["execution_a"],
            "worker",
        )
        _assert_admitted(
            dsns["registrar_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["registrar_a"],
            "registrar",
        )
        _assert_admitted(
            dsns["execution_recovery"],
            "control_assurance_execution",
            tenant_a,
            roles["execution_recovery"],
            "recovery",
        )
        _assert_admitted(
            dsns["reconciler_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["reconciler_a"],
            "reconciler",
        )
        _assert_admitted(
            dsns["runtime_auditor"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_auditor"],
            "auditor",
        )
        _assert_admitted(
            dsns["execution_auditor"],
            "control_assurance_execution",
            tenant_a,
            roles["execution_auditor"],
            "auditor",
        )
        _assert_admitted(
            dsns["pam_a"],
            "control_assurance_pam",
            tenant_a,
            roles["pam_a"],
            "broker",
        )
        _assert_admitted(
            dsns["pam_recovery"],
            "control_assurance_pam",
            tenant_a,
            roles["pam_recovery"],
            "recovery",
        )
        _assert_admitted(
            dsns["pam_auditor"],
            "control_assurance_pam",
            tenant_a,
            roles["pam_auditor"],
            "auditor",
        )

        _insert_runtime_profile(dsns["registrar_a"], tenant_a)
        _insert_runtime_profile(dsns["registrar_b"], tenant_b)
        _insert_execution(dsns["execution_a"], tenant_a)
        _insert_execution(dsns["execution_b"], tenant_b)
        _insert_pam_lease(dsns["pam_a"], namespace_a, f"{suffix}:a")
        _insert_pam_lease(dsns["pam_b"], namespace_b, f"{suffix}:b")

        for key, query, expected in (
            (
                "runtime_a",
                """
                SELECT tenant_id
                FROM control_assurance_runtime.control_profiles
                ORDER BY tenant_id
                """,
                [(tenant_a,)],
            ),
            (
                "execution_a",
                """
                SELECT tenant_id
                FROM control_assurance_execution.executions
                ORDER BY tenant_id
                """,
                [(tenant_a,)],
            ),
            (
                "pam_a",
                """
                SELECT journal_namespace_digest
                FROM control_assurance_pam.elastic_jit_leases
                ORDER BY journal_namespace_digest
                """,
                [(namespace_a,)],
            ),
        ):
            with psycopg.connect(dsns[key]) as connection:
                connection.execute(
                    "SELECT set_config('control_assurance.tenant_id', %s, true)",
                    (tenant_b,),
                )
                assert connection.execute(query).fetchall() == expected

        with psycopg.connect(dsns["registrar_a"]) as connection:
            _expect_privilege_failure(
                lambda: connection.execute(
                    """
                    INSERT INTO control_assurance_runtime.control_profiles (
                        tenant_id, profile_id, profile_digest, media_type,
                        profile_bytes, registered_at, registered_by
                    )
                    VALUES (
                        %s, 'cross-tenant', %s, 'application/json',
                        %s, %s, 'boundary-live-test'
                    )
                    """,
                    (
                        tenant_b,
                        _DOCUMENT_DIGEST,
                        _DOCUMENT,
                        datetime(2026, 7, 30, tzinfo=UTC),
                    ),
                )
            )

        with psycopg.connect(dsns["pam_a"]) as connection:
            assert connection.execute(
                """
                SELECT
                    control_assurance_pam.session_owns_namespace(%s),
                    control_assurance_pam.session_owns_namespace(%s),
                    to_regprocedure(
                        'control_assurance_pam.namespace_tenant(text)'
                    )
                """,
                (namespace_a, namespace_b),
            ).fetchone() == (True, False, None)
            _expect_privilege_failure(
                lambda: connection.execute(
                    """
                    SELECT control_assurance_pam.assert_journal_namespace(
                        %s, current_user, session_user
                    )
                    """,
                    (namespace_unmapped,),
                )
            )

        with psycopg.connect(dsns["runtime_a"]) as connection:
            _expect_privilege_failure(
                lambda: connection.execute(
                    """
                    SELECT control_assurance_runtime.configure_login_role(
                        %s, %s::name, 'worker'
                    )
                    """,
                    (tenant_a, roles["runtime_a"]),
                )
            )

        for key, schema, tenant, role, kind in (
            (
                "owner",
                "control_assurance_runtime",
                tenant_a,
                roles["owner"],
                "worker",
            ),
            (
                "super",
                "control_assurance_runtime",
                tenant_a,
                roles["super"],
                "worker",
            ),
            (
                "bypass",
                "control_assurance_runtime",
                tenant_a,
                roles["bypass"],
                "worker",
            ),
        ):
            _expect_privilege_failure(
                lambda key=key, schema=schema, tenant=tenant, role=role, kind=kind: (
                    _assert_admitted(dsns[key], schema, tenant, role, kind)
                )
            )

        sql = _sql()
        mutations = (
            (
                sql.SQL(
                    "GRANT DELETE ON "
                    "control_assurance_runtime.control_profiles TO {}"
                ).format(sql.Identifier(roles["runtime_a"])),
                sql.SQL(
                    "REVOKE DELETE ON "
                    "control_assurance_runtime.control_profiles FROM {}"
                ).format(sql.Identifier(roles["runtime_a"])),
            ),
            (
                sql.SQL(
                    "GRANT SELECT, UPDATE ON "
                    "control_assurance_runtime.role_entitlements TO {}"
                ).format(sql.Identifier(roles["runtime_a"])),
                sql.SQL(
                    "REVOKE SELECT, UPDATE ON "
                    "control_assurance_runtime.role_entitlements FROM {}"
                ).format(sql.Identifier(roles["runtime_a"])),
            ),
            (
                sql.SQL(
                    "GRANT UPDATE (profile_bytes) ON "
                    "control_assurance_runtime.control_profiles TO {}"
                ).format(sql.Identifier(roles["runtime_a"])),
                sql.SQL(
                    "REVOKE UPDATE (profile_bytes) ON "
                    "control_assurance_runtime.control_profiles FROM {}"
                ).format(sql.Identifier(roles["runtime_a"])),
            ),
            (
                sql.SQL("GRANT TEMPORARY ON DATABASE {} TO {}").format(
                    sql.Identifier(database_name),
                    sql.Identifier(roles["runtime_a"]),
                ),
                sql.SQL("REVOKE TEMPORARY ON DATABASE {} FROM {}").format(
                    sql.Identifier(database_name),
                    sql.Identifier(roles["runtime_a"]),
                ),
            ),
            (
                sql.SQL("GRANT USAGE, CREATE ON SCHEMA {} TO {}").format(
                    sql.Identifier(scratch_schema),
                    sql.Identifier(roles["runtime_a"]),
                ),
                sql.SQL("REVOKE USAGE, CREATE ON SCHEMA {} FROM {}").format(
                    sql.Identifier(scratch_schema),
                    sql.Identifier(roles["runtime_a"]),
                ),
            ),
            (
                sql.SQL(
                    "GRANT SELECT ON control_assurance_runtime.{} TO {}"
                ).format(
                    sql.Identifier(probe_view),
                    sql.Identifier(roles["runtime_a"]),
                ),
                sql.SQL(
                    "REVOKE SELECT ON control_assurance_runtime.{} FROM {}"
                ).format(
                    sql.Identifier(probe_view),
                    sql.Identifier(roles["runtime_a"]),
                ),
            ),
            (
                sql.SQL(
                    "GRANT USAGE ON SEQUENCE "
                    "control_assurance_runtime.{} TO {}"
                ).format(
                    sql.Identifier(probe_sequence),
                    sql.Identifier(roles["runtime_a"]),
                ),
                sql.SQL(
                    "REVOKE USAGE ON SEQUENCE "
                    "control_assurance_runtime.{} FROM {}"
                ).format(
                    sql.Identifier(probe_sequence),
                    sql.Identifier(roles["runtime_a"]),
                ),
            ),
            (
                sql.SQL(
                    "GRANT EXECUTE ON FUNCTION "
                    "control_assurance_runtime.{}(text) TO {}"
                ).format(
                    sql.Identifier(probe_function),
                    sql.Identifier(roles["runtime_a"]),
                ),
                sql.SQL(
                    "REVOKE EXECUTE ON FUNCTION "
                    "control_assurance_runtime.{}(text) FROM {}"
                ).format(
                    sql.Identifier(probe_function),
                    sql.Identifier(roles["runtime_a"]),
                ),
            ),
            (
                sql.SQL(
                    "GRANT SELECT ON "
                    "control_assurance_runtime.control_profiles TO PUBLIC"
                ),
                sql.SQL(
                    "REVOKE SELECT ON "
                    "control_assurance_runtime.control_profiles FROM PUBLIC"
                ),
            ),
            (
                sql.SQL("ALTER ROLE {} SET statement_timeout = '1s'").format(
                    sql.Identifier(roles["runtime_a"])
                ),
                sql.SQL("ALTER ROLE {} RESET statement_timeout").format(
                    sql.Identifier(roles["runtime_a"])
                ),
            ),
        )
        for apply_mutation, restore_mutation in mutations:
            with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
                admin.execute(apply_mutation)
            try:
                _expect_privilege_failure(
                    lambda: _assert_admitted(
                        dsns["runtime_a"],
                        "control_assurance_runtime",
                        tenant_a,
                        roles["runtime_a"],
                        "worker",
                    )
                )
            finally:
                with psycopg.connect(
                    _ADMIN_DSN,
                    autocommit=True,
                ) as admin:
                    admin.execute(restore_mutation)
            _assert_admitted(
                dsns["runtime_a"],
                "control_assurance_runtime",
                tenant_a,
                roles["runtime_a"],
                "worker",
            )

        for key, schema, role, kind, owner_table in (
            (
                "execution_a",
                "control_assurance_execution",
                roles["execution_a"],
                "worker",
                "role_entitlements",
            ),
            (
                "pam_a",
                "control_assurance_pam",
                roles["pam_a"],
                "broker",
                "role_entitlements",
            ),
            (
                "pam_a",
                "control_assurance_pam",
                roles["pam_a"],
                "broker",
                "journal_namespaces",
            ),
        ):
            with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
                admin.execute(
                    sql.SQL("GRANT SELECT, UPDATE ON {}.{} TO {}").format(
                        sql.Identifier(schema),
                        sql.Identifier(owner_table),
                        sql.Identifier(role),
                    )
                )
            try:
                _expect_privilege_failure(
                    lambda key=key, schema=schema, role=role, kind=kind: (
                        _assert_admitted(
                            dsns[key],
                            schema,
                            tenant_a,
                            role,
                            kind,
                        )
                    )
                )
            finally:
                with psycopg.connect(
                    _ADMIN_DSN,
                    autocommit=True,
                ) as admin:
                    admin.execute(
                        sql.SQL(
                            "REVOKE SELECT, UPDATE ON {}.{} FROM {}"
                        ).format(
                            sql.Identifier(schema),
                            sql.Identifier(owner_table),
                            sql.Identifier(role),
                        )
                    )
            _assert_admitted(dsns[key], schema, tenant_a, role, kind)

        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                sql.SQL(
                    "REVOKE SELECT ON "
                    "control_assurance_runtime.control_profiles FROM {}"
                ).format(sql.Identifier(roles["runtime_a"]))
            )
        _expect_privilege_failure(
            lambda: _assert_admitted(
                dsns["runtime_a"],
                "control_assurance_runtime",
                tenant_a,
                roles["runtime_a"],
                "worker",
            )
        )
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            _configure_role(
                admin,
                "control_assurance_runtime",
                tenant_a,
                roles["runtime_a"],
                "worker",
            )
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )

        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            _expect_privilege_failure(
                lambda: _configure_role(
                    admin,
                    "control_assurance_execution",
                    tenant_a,
                    roles["runtime_a"],
                    "worker",
                )
            )
            admin.execute(
                """
                INSERT INTO control_assurance_execution.role_entitlements (
                    database_role, tenant_id, principal_kind
                )
                VALUES (%s::name, %s, 'worker')
                """,
                (roles["runtime_a"], tenant_a),
            )
        try:
            _expect_privilege_failure(
                lambda: _assert_admitted(
                    dsns["runtime_a"],
                    "control_assurance_runtime",
                    tenant_a,
                    roles["runtime_a"],
                    "worker",
                )
            )
        finally:
            with psycopg.connect(
                _ADMIN_DSN,
                autocommit=True,
            ) as admin:
                admin.execute(
                    """
                    DELETE FROM control_assurance_execution.role_entitlements
                    WHERE database_role = %s::name
                    """,
                    (roles["runtime_a"],),
                )
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )

        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                sql.SQL(
                    "GRANT USAGE ON SCHEMA "
                    "control_assurance_execution TO {}"
                ).format(sql.Identifier(roles["runtime_a"]))
            )
        try:
            _expect_privilege_failure(
                lambda: _assert_admitted(
                    dsns["runtime_a"],
                    "control_assurance_runtime",
                    tenant_a,
                    roles["runtime_a"],
                    "worker",
                )
            )
        finally:
            with psycopg.connect(
                _ADMIN_DSN,
                autocommit=True,
            ) as admin:
                admin.execute(
                    sql.SQL(
                        "REVOKE USAGE ON SCHEMA "
                        "control_assurance_execution FROM {}"
                    ).format(sql.Identifier(roles["runtime_a"]))
                )
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )

        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            _grant_static(
                admin,
                "GRANT USAGE ON SCHEMA control_assurance_runtime TO {role}",
                roles["switch"],
            )
            _grant_static(
                admin,
                """
                GRANT EXECUTE ON FUNCTION
                    control_assurance_runtime.assert_session_principal(
                        text, text, text, text, text
                    )
                TO {role}
                """,
                roles["switch"],
            )
            admin.execute(
                _sql().SQL("GRANT {} TO {}").format(
                    _sql().Identifier(roles["switch"]),
                    _sql().Identifier(roles["runtime_a"]),
                )
            )
        with psycopg.connect(dsns["runtime_a"]) as connection:
            connection.execute(
                _sql().SQL("SET ROLE {}").format(
                    _sql().Identifier(roles["switch"])
                )
            )
            _expect_privilege_failure(
                lambda: connection.execute(
                    """
                    SELECT control_assurance_runtime.assert_session_principal(
                        %s, %s, 'worker', current_user, session_user
                    )
                    """,
                    (tenant_a, roles["runtime_a"]),
                )
            )
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                _sql().SQL("REVOKE {} FROM {}").format(
                    _sql().Identifier(roles["switch"]),
                    _sql().Identifier(roles["runtime_a"]),
                )
            )
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )

        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                _sql().SQL("GRANT {} TO {}").format(
                    _sql().Identifier(roles["runtime_a"]),
                    _sql().Identifier(roles["switch"]),
                )
            )
        try:
            _expect_privilege_failure(
                lambda: _assert_admitted(
                    dsns["runtime_a"],
                    "control_assurance_runtime",
                    tenant_a,
                    roles["runtime_a"],
                    "worker",
                )
            )
        finally:
            with psycopg.connect(
                _ADMIN_DSN,
                autocommit=True,
            ) as admin:
                admin.execute(
                    _sql().SQL("REVOKE {} FROM {}").format(
                        _sql().Identifier(roles["runtime_a"]),
                        _sql().Identifier(roles["switch"]),
                    )
                )
        _assert_admitted(
            dsns["runtime_a"],
            "control_assurance_runtime",
            tenant_a,
            roles["runtime_a"],
            "worker",
        )

        with psycopg.connect(dsns["execution_a"]) as connection:
            worker_can_consume = connection.execute(
                """
                SELECT has_function_privilege(
                    current_user,
                    'control_assurance_execution.'
                    'consume_publishing_recovery_authorization('
                    'bytea,bytea,bytea,bytea,bytea,bytea,bytea,'
                    'bytea,bytea,bytea,bytea,bytea,bytea)',
                    'EXECUTE'
                )
                """
            ).fetchone()
        with psycopg.connect(dsns["execution_recovery"]) as connection:
            recovery_can_consume = connection.execute(
                """
                SELECT has_function_privilege(
                    current_user,
                    'control_assurance_execution.'
                    'consume_publishing_recovery_authorization('
                    'bytea,bytea,bytea,bytea,bytea,bytea,bytea,'
                    'bytea,bytea,bytea,bytea,bytea,bytea)',
                    'EXECUTE'
                )
                """
            ).fetchone()
        assert worker_can_consume == (False,)
        assert recovery_can_consume == (True,)

        with (
            psycopg.connect(_ADMIN_DSN, autocommit=True) as admin,
            pytest.raises(psycopg.errors.UniqueViolation),
        ):
            _configure_namespace(
                admin,
                namespace_a,
                tenant_b,
                "conflicting-remap",
            )
    finally:
        with psycopg.connect(_ADMIN_DSN, autocommit=True) as admin:
            for schema in (
                "control_assurance_runtime",
                "control_assurance_execution",
                "control_assurance_pam",
            ):
                admin.execute(
                    _sql().SQL(
                        "DELETE FROM {}.role_entitlements "
                        "WHERE database_role = ANY(%s)"
                    ).format(_sql().Identifier(schema)),
                    (list(roles.values()),),
                )
            admin.execute(
                """
                DELETE FROM control_assurance_pam.journal_namespaces
                WHERE journal_namespace_digest = ANY(%s)
                """,
                ([namespace_a, namespace_b],),
            )
            admin.execute(
                _sql().SQL(
                    "DROP VIEW IF EXISTS control_assurance_runtime.{}"
                ).format(_sql().Identifier(probe_view))
            )
            admin.execute(
                _sql().SQL(
                    "DROP SEQUENCE IF EXISTS control_assurance_runtime.{}"
                ).format(_sql().Identifier(probe_sequence))
            )
            admin.execute(
                _sql().SQL(
                    "DROP FUNCTION IF EXISTS "
                    "control_assurance_runtime.{}(text)"
                ).format(_sql().Identifier(probe_function))
            )
            admin.execute(
                _sql().SQL("DROP SCHEMA IF EXISTS {}").format(
                    _sql().Identifier(scratch_schema)
                )
            )
            for role in roles.values():
                admin.execute(
                    _sql().SQL("DROP OWNED BY {}").format(
                        _sql().Identifier(role)
                    )
                )
            for role in reversed(tuple(roles.values())):
                admin.execute(
                    _sql().SQL("DROP ROLE IF EXISTS {}").format(
                        _sql().Identifier(role)
                    )
                )
