#!/usr/bin/env python3
"""Provision the disposable PostgreSQL 17 topology exercised by CI.

The service account is intentionally used only to create isolated databases
and exact login roles.  Each product schema is then installed by its own
database owner and exercised through distinct runtime credentials.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from psycopg import sql


@dataclass(frozen=True, slots=True)
class LoginRole:
    name: str
    password: str


@dataclass(frozen=True, slots=True)
class IntegrationDatabase:
    name: str
    owner: str


ROLES = (
    LoginRole("ca_control_migration", "control-migration-integration-only"),
    LoginRole("ca_control_runtime", "control-runtime-integration-only"),
    LoginRole("ca_auth_runtime", "auth-runtime-integration-only"),
    LoginRole("ca_reconciler_runtime", "reconciler-runtime-integration-only"),
    LoginRole("ca_runtime_migration", "runtime-migration-integration-only"),
    LoginRole("ca_runtime_registrar", "runtime-registrar-integration-only"),
    LoginRole("ca_runtime_reconciler", "runtime-reconciler-integration-only"),
    LoginRole("ca_runtime_worker", "runtime-worker-integration-only"),
    LoginRole("ca_pam_migration", "pam-migration-integration-only"),
    LoginRole("ca_pam_broker", "pam-broker-integration-only"),
    LoginRole("ca_execution_migration", "execution-migration-integration-only"),
    LoginRole("ca_execution_worker", "execution-worker-integration-only"),
    LoginRole("ca_execution_recovery", "execution-recovery-integration-only"),
)

DATABASES = (
    IntegrationDatabase("ca_control_integration", "ca_control_migration"),
    IntegrationDatabase("ca_runtime_integration", "ca_runtime_migration"),
    IntegrationDatabase("ca_pam_integration", "ca_pam_migration"),
    IntegrationDatabase("ca_execution_integration", "ca_execution_migration"),
)
BOUNDARY_DATABASE = "ca_boundary_integration"


def main() -> int:
    dsn = os.environ.get("CONTROL_ASSURANCE_POSTGRES_BOOTSTRAP_DSN")
    if not dsn:
        raise SystemExit("CONTROL_ASSURANCE_POSTGRES_BOOTSTRAP_DSN is required")

    with psycopg.connect(dsn, autocommit=True) as connection:
        server = connection.execute(
            """
            SELECT
                current_setting('server_version_num')::integer,
                current_user,
                rolsuper
            FROM pg_catalog.pg_roles
            WHERE rolname = current_user
            """
        ).fetchone()
        if server is None:
            raise SystemExit("PostgreSQL bootstrap identity could not be read")
        version, administrator, is_superuser = server
        if not 170000 <= int(version) < 180000:
            raise SystemExit("integration topology requires PostgreSQL 17")
        if is_superuser is not True:
            raise SystemExit("integration bootstrap identity must be a superuser")

        existing_roles = {
            row[0]
            for row in connection.execute(
                "SELECT rolname FROM pg_catalog.pg_roles"
            ).fetchall()
        }
        existing_databases = {
            row[0]
            for row in connection.execute(
                "SELECT datname FROM pg_catalog.pg_database"
            ).fetchall()
        }
        requested_roles = {role.name for role in ROLES}
        requested_databases = {
            *(database.name for database in DATABASES),
            BOUNDARY_DATABASE,
        }
        collisions = sorted(
            (existing_roles & requested_roles)
            | (existing_databases & requested_databases)
        )
        if collisions:
            raise SystemExit(
                "integration topology is not disposable: "
                + ", ".join(collisions)
            )

        for role in ROLES:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT "
                    "NOREPLICATION NOBYPASSRLS"
                ).format(
                    sql.Identifier(role.name),
                    sql.Literal(role.password),
                )
            )
        for database in DATABASES:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(database.name),
                    sql.Identifier(database.owner),
                )
            )
        connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(BOUNDARY_DATABASE),
                sql.Identifier(str(administrator)),
            )
        )

    print(
        "provisioned PostgreSQL 17 integration topology: "
        f"{len(ROLES)} exact login roles, "
        f"{len(DATABASES) + 1} isolated databases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
