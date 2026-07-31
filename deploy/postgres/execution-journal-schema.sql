-- Control Assurance external execution journal, migrations 1 through 6.
--
-- Install with a migration owner before any executor starts.  Runtime roles
-- must be granted only USAGE on this schema and the required DML privileges.
-- The Python journal never creates or alters database objects.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $encoding_check$
BEGIN
    IF current_setting('server_encoding') <> 'UTF8' THEN
        RAISE EXCEPTION
            'execution journal requires UTF8 database encoding, found %',
            current_setting('server_encoding');
    END IF;
END;
$encoding_check$;

CREATE SCHEMA IF NOT EXISTS control_assurance_execution;

REVOKE ALL ON SCHEMA control_assurance_execution FROM PUBLIC;

CREATE TABLE IF NOT EXISTS control_assurance_execution.schema_migrations (
    version integer PRIMARY KEY CHECK (version >= 1),
    description text NOT NULL CHECK (length(description) BETWEEN 1 AND 255),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp()
);

-- Migration 6: bind every login credential to one deployment tenant and one
-- journal capability. Only the migration owner may provision these rows.
CREATE TABLE IF NOT EXISTS control_assurance_execution.role_entitlements (
    database_role name PRIMARY KEY,
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    principal_kind text NOT NULL
        CHECK (principal_kind IN ('worker', 'recovery', 'auditor')),
    provisioned_at timestamptz(0) NOT NULL
        DEFAULT transaction_timestamp(),
    provisioned_by name NOT NULL DEFAULT session_user
);

REVOKE ALL ON control_assurance_execution.role_entitlements FROM PUBLIC;

CREATE OR REPLACE FUNCTION
    control_assurance_execution.session_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution
AS $function$
    SELECT entitlement.tenant_id
    FROM control_assurance_execution.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_execution.session_principal_kind()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution
AS $function$
    SELECT entitlement.principal_kind
    FROM control_assurance_execution.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_execution.foreign_store_isolated(p_role name)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution
AS $function$
DECLARE
    role_oid oid;
    store record;
    foreign_entitlement boolean;
BEGIN
    SELECT role.oid
    INTO role_oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = p_role;
    IF role_oid IS NULL THEN
        RETURN FALSE;
    END IF;

    FOR store IN
        SELECT namespace.oid, namespace.nspname
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname IN (
            'control_assurance_runtime',
            'control_assurance_pam'
        )
    LOOP
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(
                COALESCE(
                    (
                        SELECT namespace.nspacl
                        FROM pg_catalog.pg_namespace AS namespace
                        WHERE namespace.oid = store.oid
                    ),
                    pg_catalog.acldefault('n', (
                        SELECT namespace.nspowner
                        FROM pg_catalog.pg_namespace AS namespace
                        WHERE namespace.oid = store.oid
                    ))
                )
            ) AS acl
            WHERE acl.grantee IN (0, role_oid)
        ) OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
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
            WHERE relation.relnamespace = store.oid
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
              AND acl.grantee IN (0, role_oid)
        ) OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = attribute.attrelid
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                attribute.attacl
            ) AS acl
            WHERE relation.relnamespace = store.oid
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee IN (0, role_oid)
        ) OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    routine.proacl,
                    pg_catalog.acldefault('f', routine.proowner)
                )
            ) AS acl
            WHERE routine.pronamespace = store.oid
              AND acl.grantee IN (0, role_oid)
        ) THEN
            RETURN FALSE;
        END IF;

        foreign_entitlement := FALSE;
        IF pg_catalog.to_regclass(
            pg_catalog.format('%I.role_entitlements', store.nspname)
        ) IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'SELECT EXISTS (SELECT 1 FROM %I.role_entitlements '
                'WHERE database_role = $1)',
                store.nspname
            )
            INTO foreign_entitlement
            USING p_role;
        END IF;
        IF foreign_entitlement THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_execution.assert_session_principal(
        expected_tenant text,
        expected_database_role text,
        expected_principal_kind text,
        caller_current_role text,
        caller_session_role text
    )
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution
AS $function$
DECLARE
    entitlement control_assurance_execution.role_entitlements%ROWTYPE;
    role_record pg_catalog.pg_roles%ROWTYPE;
    relation_record record;
    procedure_record record;
    privilege_name text;
    privilege_present boolean;
    privilege_allowed boolean;
BEGIN
    IF expected_tenant !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR expected_database_role !~ '^[a-z][a-z0-9_]{0,62}$'
       OR expected_principal_kind NOT IN ('worker', 'recovery', 'auditor')
       OR caller_current_role IS DISTINCT FROM expected_database_role
       OR caller_session_role IS DISTINCT FROM expected_database_role
       OR caller_current_role IS DISTINCT FROM caller_session_role
       OR caller_session_role IS DISTINCT FROM session_user::text
    THEN
        RAISE EXCEPTION 'execution database principal identity mismatch'
            USING ERRCODE = '42501';
    END IF;

    SELECT *
    INTO entitlement
    FROM control_assurance_execution.role_entitlements
    WHERE database_role = session_user::name;
    SELECT *
    INTO role_record
    FROM pg_catalog.pg_roles
    WHERE rolname = session_user;

    IF entitlement.database_role IS NULL
       OR entitlement.tenant_id IS DISTINCT FROM expected_tenant
       OR entitlement.principal_kind IS DISTINCT FROM expected_principal_kind
       OR role_record.rolname IS NULL
       OR NOT role_record.rolcanlogin
       OR role_record.rolsuper
       OR role_record.rolinherit
       OR role_record.rolcreaterole
       OR role_record.rolcreatedb
       OR role_record.rolreplication
       OR role_record.rolbypassrls
       OR role_record.rolconfig IS NOT NULL
       OR NOT control_assurance_execution.foreign_store_isolated(
            session_user::name
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = role_record.oid
               OR membership.roleid = role_record.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_db_role_setting AS setting
            WHERE setting.setrole = role_record.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            WHERE database.datdba = role_record.oid
       )
       OR NOT pg_catalog.has_schema_privilege(
            session_user,
            'control_assurance_execution',
            'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            session_user,
            'control_assurance_execution',
            'CREATE'
       )
       OR pg_catalog.has_database_privilege(
            session_user,
            current_database(),
            'CREATE'
       )
       OR pg_catalog.has_database_privilege(
            session_user,
            current_database(),
            'TEMPORARY'
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspowner = role_record.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE pg_catalog.has_schema_privilege(
                session_user,
                namespace.oid,
                'CREATE'
            )
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            WHERE relation.relowner = role_record.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS procedure
            WHERE procedure.proowner = role_record.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    namespace.nspacl,
                    pg_catalog.acldefault('n', namespace.nspowner)
                )
            ) AS acl
            WHERE namespace.nspname = 'control_assurance_execution'
              AND (
                  acl.grantee = 0
                  OR (
                      acl.grantee = role_record.oid
                      AND acl.is_grantable
                  )
              )
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
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
            WHERE relation.relnamespace =
                    'control_assurance_execution'::regnamespace
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'S')
              AND (
                  acl.grantee = 0
                  OR (
                      acl.grantee = role_record.oid
                      AND acl.is_grantable
                  )
              )
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = attribute.attrelid
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                attribute.attacl
            ) AS acl
            WHERE relation.relnamespace =
                    'control_assurance_execution'::regnamespace
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee IN (0, role_record.oid)
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS procedure
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    procedure.proacl,
                    pg_catalog.acldefault('f', procedure.proowner)
                )
            ) AS acl
            WHERE procedure.pronamespace =
                    'control_assurance_execution'::regnamespace
              AND (
                  acl.grantee = 0
                  OR (
                      acl.grantee = role_record.oid
                      AND acl.is_grantable
                  )
              )
       )
    THEN
        RAISE EXCEPTION 'execution database principal is over-privileged'
            USING ERRCODE = '42501';
    END IF;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_execution'::regnamespace
          AND relation.relkind IN ('r', 'p', 'v', 'm')
    LOOP
        FOREACH privilege_name IN ARRAY ARRAY[
            'SELECT',
            'INSERT',
            'UPDATE',
            'DELETE',
            'TRUNCATE',
            'REFERENCES',
            'TRIGGER'
        ]
        LOOP
            privilege_present :=
                pg_catalog.has_table_privilege(
                    session_user,
                    relation_record.oid,
                    privilege_name
                );
            privilege_allowed :=
                relation_record.relname <> 'role_entitlements'
                AND CASE expected_principal_kind
                WHEN 'worker' THEN
                    (
                        relation_record.relname = 'schema_migrations'
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname IN (
                            'executions',
                            'execution_attempts'
                        )
                        AND privilege_name IN (
                            'SELECT',
                            'INSERT',
                            'UPDATE'
                        )
                    )
                WHEN 'recovery' THEN
                    relation_record.relname IN (
                        'schema_migrations',
                        'executions',
                        'execution_attempts'
                    )
                    AND privilege_name = 'SELECT'
                WHEN 'auditor' THEN
                    relation_record.relname IN (
                        'schema_migrations',
                        'executions',
                        'execution_attempts',
                        'publishing_recovery_authorizations'
                    )
                    AND privilege_name = 'SELECT'
                    ELSE FALSE
                END;
            IF privilege_present IS DISTINCT FROM privilege_allowed THEN
                RAISE EXCEPTION
                    'execution database principal table privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_execution'::regnamespace
          AND relation.relkind = 'S'
    LOOP
        FOREACH privilege_name IN ARRAY ARRAY[
            'USAGE',
            'SELECT',
            'UPDATE'
        ]
        LOOP
            IF pg_catalog.has_sequence_privilege(
                session_user,
                relation_record.oid,
                privilege_name
            ) THEN
                RAISE EXCEPTION
                    'execution database principal sequence privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR procedure_record IN
        SELECT procedure.oid, procedure.proname
        FROM pg_catalog.pg_proc AS procedure
        WHERE procedure.pronamespace =
                'control_assurance_execution'::regnamespace
    LOOP
        privilege_present := pg_catalog.has_function_privilege(
            session_user,
            procedure_record.oid,
            'EXECUTE'
        );
        privilege_allowed :=
            procedure_record.oid = ANY(ARRAY[
                'control_assurance_execution.session_tenant()'
                    ::regprocedure::oid,
                'control_assurance_execution.session_principal_kind()'
                    ::regprocedure::oid,
                'control_assurance_execution.assert_session_principal('
                    'text,text,text,text,text)'::regprocedure::oid
            ])
            OR (
                expected_principal_kind = 'recovery'
                AND procedure_record.oid =
                    'control_assurance_execution.'
                    'consume_publishing_recovery_authorization('
                    'bytea,bytea,bytea,bytea,bytea,bytea,bytea,'
                    'bytea,bytea,bytea,bytea,bytea,bytea)'
                    ::regprocedure::oid
            );
        IF privilege_present IS DISTINCT FROM privilege_allowed
        THEN
            RAISE EXCEPTION
                'execution database principal routine privilege matrix mismatch'
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$function$;

CREATE TABLE IF NOT EXISTS control_assurance_execution.executions (
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    run_id text NOT NULL
        CHECK (run_id ~ '^sha256:[a-f0-9]{64}$'),
    stable_request_digest text NOT NULL
        CHECK (stable_request_digest ~ '^sha256:[a-f0-9]{64}$'),
    stable_request_bytes bytea NOT NULL
        CHECK (octet_length(stable_request_bytes) BETWEEN 2 AND 65536),
    run_request_bytes bytea NOT NULL
        CHECK (octet_length(run_request_bytes) BETWEEN 2 AND 65536),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    deployment_operation_id text NOT NULL
        CHECK (deployment_operation_id ~ '^sha256:[a-f0-9]{64}$'),
    deployment_operation_sequence bigint NOT NULL
        CHECK (deployment_operation_sequence >= 1),
    deployment_receipt_digest text NOT NULL
        CHECK (deployment_receipt_digest ~ '^sha256:[a-f0-9]{64}$'),
    revision_id text NOT NULL
        CHECK (revision_id ~ '^sha256:[a-f0-9]{64}$'),
    configuration_digest text NOT NULL
        CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    configuration_bytes bytea NOT NULL
        CHECK (octet_length(configuration_bytes) BETWEEN 2 AND 1048576),
    control_profile_id text NOT NULL
        CHECK (control_profile_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_profile_digest text NOT NULL
        CHECK (control_profile_digest ~ '^sha256:[a-f0-9]{64}$'),
    control_profile_media_type text NOT NULL
        CHECK (
            length(control_profile_media_type) BETWEEN 16 AND 128
            AND control_profile_media_type ~
                '^application/(json|[a-z0-9!#$&^_.+-]+[+]json)$'
        ),
    control_profile_bytes bytea NOT NULL
        CHECK (octet_length(control_profile_bytes) BETWEEN 2 AND 1048576),
    window_start timestamptz(0) NOT NULL,
    window_end timestamptz(0) NOT NULL,
    execution_plan_digest text NOT NULL
        CHECK (execution_plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_plan_bytes bytea NOT NULL
        CHECK (octet_length(execution_plan_bytes) BETWEEN 2 AND 2097152),
    execution_identity_digest text
        CHECK (
            execution_identity_digest IS NULL
            OR execution_identity_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    execution_identity_bytes bytea
        CHECK (
            execution_identity_bytes IS NULL
            OR octet_length(execution_identity_bytes) BETWEEN 2 AND 524288
        ),
    highest_lease_fence bigint NOT NULL
        CHECK (highest_lease_fence BETWEEN 1 AND 9223372036854775807),
    highest_attempt_count integer NOT NULL
        CHECK (highest_attempt_count BETWEEN 1 AND 32),
    completion_lease_fence bigint
        CHECK (
            completion_lease_fence IS NULL
            OR completion_lease_fence BETWEEN 1 AND 9223372036854775807
        ),
    evidence_digest text
        CHECK (
            evidence_digest IS NULL
            OR evidence_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    executor_receipt_digest text
        CHECK (
            executor_receipt_digest IS NULL
            OR executor_receipt_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    executor_receipt_bytes bytea
        CHECK (
            executor_receipt_bytes IS NULL
            OR octet_length(executor_receipt_bytes) BETWEEN 2 AND 1048576
        ),
    created_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz(0),
    updated_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT execution_nonempty_window CHECK (window_end > window_start),
    CONSTRAINT execution_stable_request_exact_digest CHECK (
        stable_request_digest =
            'sha256:' || encode(sha256(stable_request_bytes), 'hex')
    ),
    CONSTRAINT execution_run_request_exact_digest CHECK (
        run_id = 'sha256:' || encode(sha256(run_request_bytes), 'hex')
    ),
    CONSTRAINT execution_configuration_exact_digest CHECK (
        configuration_digest =
            'sha256:' || encode(sha256(configuration_bytes), 'hex')
    ),
    CONSTRAINT execution_profile_exact_digest CHECK (
        control_profile_digest =
            'sha256:' || encode(sha256(control_profile_bytes), 'hex')
    ),
    CONSTRAINT execution_plan_exact_digest CHECK (
        execution_plan_digest =
            'sha256:' || encode(sha256(execution_plan_bytes), 'hex')
    ),
    CONSTRAINT execution_identity_shape CHECK (
        (
            execution_identity_digest IS NULL
            AND execution_identity_bytes IS NULL
        )
        OR (
            execution_identity_digest IS NOT NULL
            AND execution_identity_bytes IS NOT NULL
            AND
            execution_identity_digest =
                'sha256:' || encode(sha256(execution_identity_bytes), 'hex')
            AND jsonb_typeof(
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
            ) = 'object'
        )
    ),
    CONSTRAINT execution_completion_shape CHECK (
        (
            completion_lease_fence IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND executor_receipt_bytes IS NULL
            AND completed_at IS NULL
        )
        OR (
            completion_lease_fence = highest_lease_fence
            AND execution_identity_digest IS NOT NULL
            AND execution_identity_bytes IS NOT NULL
            AND evidence_digest IS NOT NULL
            AND executor_receipt_digest IS NOT NULL
            AND executor_receipt_bytes IS NOT NULL
            AND executor_receipt_digest =
                'sha256:' || encode(sha256(executor_receipt_bytes), 'hex')
            AND completed_at IS NOT NULL
        )
    )
);

-- Migration 2 adds the immutable public execution-environment identity.  The
-- exact canonical-JSON check remains in the runtime because PostgreSQL jsonb
-- normalizes input; the database independently enforces size, digest, UTF-8,
-- top-level object shape, and the completed-row requirement.  An installation
-- containing legacy completed rows intentionally cannot be upgraded without
-- an operator-supplied, independently verified identity for those rows.
ALTER TABLE control_assurance_execution.executions
    ADD COLUMN IF NOT EXISTS execution_identity_digest text;
ALTER TABLE control_assurance_execution.executions
    ADD COLUMN IF NOT EXISTS execution_identity_bytes bytea;

ALTER TABLE control_assurance_execution.executions
    DROP CONSTRAINT IF EXISTS execution_identity_shape;
ALTER TABLE control_assurance_execution.executions
    ADD CONSTRAINT execution_identity_shape CHECK (
        (
            execution_identity_digest IS NULL
            AND execution_identity_bytes IS NULL
        )
        OR (
            execution_identity_digest IS NOT NULL
            AND execution_identity_bytes IS NOT NULL
            AND execution_identity_digest ~ '^sha256:[a-f0-9]{64}$'
            AND octet_length(execution_identity_bytes) BETWEEN 2 AND 524288
            AND execution_identity_digest =
                'sha256:' || encode(sha256(execution_identity_bytes), 'hex')
            AND jsonb_typeof(
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
            ) = 'object'
        )
    );

ALTER TABLE control_assurance_execution.executions
    DROP CONSTRAINT IF EXISTS execution_completion_shape;
ALTER TABLE control_assurance_execution.executions
    ADD CONSTRAINT execution_completion_shape CHECK (
        (
            completion_lease_fence IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND executor_receipt_bytes IS NULL
            AND completed_at IS NULL
        )
        OR (
            completion_lease_fence = highest_lease_fence
            AND execution_identity_digest IS NOT NULL
            AND execution_identity_bytes IS NOT NULL
            AND evidence_digest IS NOT NULL
            AND executor_receipt_digest IS NOT NULL
            AND executor_receipt_bytes IS NOT NULL
            AND executor_receipt_digest =
                'sha256:' || encode(sha256(executor_receipt_bytes), 'hex')
            AND completed_at IS NOT NULL
        )
    );

-- Migration 3 makes the database independently reject an identity document
-- for a different logical run.  Exact canonical-byte round trips and the
-- complete nested schemas remain application checks; these relational anchors
-- are deliberately duplicated here so a direct DML caller cannot cross-bind
-- another run, plan, source type, or custody profile.
ALTER TABLE control_assurance_execution.executions
    DROP CONSTRAINT IF EXISTS execution_identity_boundary;
ALTER TABLE control_assurance_execution.executions
    ADD CONSTRAINT execution_identity_boundary CHECK (
        execution_identity_bytes IS NULL
        OR COALESCE((
            convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'media_type'
                =
                'application/vnd.control-assurance.execution-environment-identity.v1+json'
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'schema_version' = '1.0.0'
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'run_id' = run_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'tenant_id' = tenant_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'control_id' = control_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'configuration_digest' = configuration_digest
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'execution_plan_digest' = execution_plan_digest
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                ->> 'source_kind' IN ('elastic-security', 'defender-xdr')
            AND jsonb_typeof(
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
                    -> 'source_identity'
            ) = 'object'
            AND jsonb_typeof(
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
                    -> 'custody_identity'
            ) = 'object'
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'source_identity' ->> 'media_type'
                =
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
                    ->> 'source_identity_media_type'
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'source_identity' ->> 'kind'
                =
                CASE
                    WHEN convert_from(
                        execution_identity_bytes,
                        'UTF8'
                    )::jsonb ->> 'source_kind' = 'elastic-security'
                    THEN 'elastic-runtime-identity'
                    ELSE 'defender-runtime-identity'
                END
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'media_type'
                =
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
                    ->> 'custody_identity_media_type'
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'run_id' = run_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'tenant_id' = tenant_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'control_id' = control_id
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'configuration_digest'
                = configuration_digest
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'execution_plan_digest'
                = execution_plan_digest
            AND convert_from(execution_identity_bytes, 'UTF8')::jsonb
                -> 'custody_identity' ->> 'deployment_profile_digest'
                =
                convert_from(execution_identity_bytes, 'UTF8')::jsonb
                    ->> 'custody_deployment_profile_digest'
        ), FALSE)
    );

CREATE TABLE IF NOT EXISTS control_assurance_execution.execution_attempts (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    lease_fence bigint NOT NULL
        CHECK (lease_fence BETWEEN 1 AND 9223372036854775807),
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 32),
    worker_id text NOT NULL
        CHECK (worker_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    lease_token_digest text NOT NULL
        CHECK (lease_token_digest ~ '^sha256:[a-f0-9]{64}$'),
    state text NOT NULL
        CHECK (
            state IN (
                'prepared',
                'publishing',
                'completed',
                'failed',
                'uncertain'
            )
        ),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    prepared_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
    publishing_at timestamptz(0),
    finished_at timestamptz(0),
    error_code text
        CHECK (
            error_code IS NULL
            OR (
                length(error_code) BETWEEN 1 AND 64
                AND error_code ~ '^[a-z][a-z0-9.-]{0,63}$'
            )
        ),
    evidence_digest text
        CHECK (
            evidence_digest IS NULL
            OR evidence_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    executor_receipt_digest text
        CHECK (
            executor_receipt_digest IS NULL
            OR executor_receipt_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    executor_receipt_bytes bytea
        CHECK (
            executor_receipt_bytes IS NULL
            OR octet_length(executor_receipt_bytes) BETWEEN 2 AND 1048576
        ),
    PRIMARY KEY (tenant_id, run_id, lease_fence),
    UNIQUE (tenant_id, run_id, attempt_count),
    CONSTRAINT execution_attempt_exact_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES control_assurance_execution.executions (tenant_id, run_id),
    CONSTRAINT execution_attempt_state_shape CHECK (
        (
            state = 'prepared'
            AND revision = 0
            AND publishing_at IS NULL
            AND finished_at IS NULL
            AND error_code IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND executor_receipt_bytes IS NULL
        )
        OR (
            state = 'publishing'
            AND revision = 1
            AND publishing_at IS NOT NULL
            AND finished_at IS NULL
            AND error_code IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND executor_receipt_bytes IS NULL
        )
        OR (
            state = 'completed'
            AND revision = 2
            AND publishing_at IS NOT NULL
            AND finished_at IS NOT NULL
            AND error_code IS NULL
            AND evidence_digest IS NOT NULL
            AND executor_receipt_digest IS NOT NULL
            AND executor_receipt_bytes IS NOT NULL
            AND executor_receipt_digest =
                'sha256:' || encode(sha256(executor_receipt_bytes), 'hex')
        )
        OR (
            state IN ('failed', 'uncertain')
            AND revision IN (1, 2)
            AND finished_at IS NOT NULL
            AND error_code IS NOT NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND executor_receipt_bytes IS NULL
        )
    ),
    CONSTRAINT execution_attempt_time_order CHECK (
        (publishing_at IS NULL OR publishing_at >= prepared_at)
        AND (finished_at IS NULL OR finished_at >= prepared_at)
        AND (
            publishing_at IS NULL
            OR finished_at IS NULL
            OR finished_at >= publishing_at
        )
    )
);

-- Migration 4 adds a deliberately separate recovery authority boundary for
-- the one state an ordinary fence cannot safely reclaim: a publishing attempt
-- that already holds a frozen external execution identity.  This table is an
-- append-only audit record, not a work queue.  Rows can only be created by the
-- SECURITY DEFINER routine below, and that routine records the authorization
-- and performs the old/new attempt transition in the same transaction.
--
-- Trust boundary: PostgreSQL does not verify Ed25519.  The dedicated recovery
-- service verifies the pinned final, fencing, drain, maker-IdP, and checker-IdP
-- authority keys before invoking the routine, so possession of that service's
-- DB credential is part of the recovery TCB.  PUBLIC and ordinary worker roles
-- receive no EXECUTE grant here.  The table retains every independently signed
-- canonical artifact, not only the outer recovery envelope.
CREATE TABLE IF NOT EXISTS
    control_assurance_execution.publishing_recovery_authorizations (
        authorization_id text PRIMARY KEY
            CHECK (authorization_id ~ '^sha256:[a-f0-9]{64}$'),
        tenant_id text NOT NULL
            CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
        run_id text NOT NULL
            CHECK (run_id ~ '^sha256:[a-f0-9]{64}$'),
        control_id text NOT NULL
            CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
        configuration_digest text NOT NULL
            CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
        execution_plan_digest text NOT NULL
            CHECK (execution_plan_digest ~ '^sha256:[a-f0-9]{64}$'),
        execution_identity_digest text NOT NULL
            CHECK (execution_identity_digest ~ '^sha256:[a-f0-9]{64}$'),
        recovery_request_digest text NOT NULL
            CHECK (recovery_request_digest ~ '^sha256:[a-f0-9]{64}$'),
        recovery_request_intent_digest text NOT NULL
            CHECK (
                recovery_request_intent_digest
                    ~ '^sha256:[a-f0-9]{64}$'
            ),
        signed_maker_action_digest text NOT NULL
            CHECK (signed_maker_action_digest ~ '^sha256:[a-f0-9]{64}$'),
        maker_action_digest text NOT NULL
            CHECK (maker_action_digest ~ '^sha256:[a-f0-9]{64}$'),
        signed_checker_action_digest text NOT NULL
            CHECK (signed_checker_action_digest ~ '^sha256:[a-f0-9]{64}$'),
        checker_action_digest text NOT NULL
            CHECK (checker_action_digest ~ '^sha256:[a-f0-9]{64}$'),
        pam_scope_digest text NOT NULL
            CHECK (pam_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
        pam_execution_binding_digest text NOT NULL
            CHECK (
                pam_execution_binding_digest ~ '^sha256:[a-f0-9]{64}$'
            ),
        pam_snapshot_high_watermark bigint NOT NULL
            CHECK (
                pam_snapshot_high_watermark BETWEEN 1 AND 9007199254740991
            ),
        pam_lifecycle_record_count integer NOT NULL
            CHECK (pam_lifecycle_record_count BETWEEN 1 AND 128),
        relaunch_fence_operation_digest text NOT NULL
            CHECK (
                relaunch_fence_operation_digest
                    ~ '^sha256:[a-f0-9]{64}$'
            ),
        issuance_fence_operation_digest text NOT NULL
            CHECK (
                issuance_fence_operation_digest
                    ~ '^sha256:[a-f0-9]{64}$'
            ),
        abandoned_attempt_digest text NOT NULL
            CHECK (abandoned_attempt_digest ~ '^sha256:[a-f0-9]{64}$'),
        successor_claim_digest text NOT NULL
            CHECK (successor_claim_digest ~ '^sha256:[a-f0-9]{64}$'),
        signed_compute_fence_digest text NOT NULL
            CHECK (signed_compute_fence_digest ~ '^sha256:[a-f0-9]{64}$'),
        compute_fence_digest text NOT NULL
            CHECK (compute_fence_digest ~ '^sha256:[a-f0-9]{64}$'),
        signed_credential_drain_digest text NOT NULL
            CHECK (signed_credential_drain_digest ~ '^sha256:[a-f0-9]{64}$'),
        credential_drain_digest text NOT NULL
            CHECK (credential_drain_digest ~ '^sha256:[a-f0-9]{64}$'),
        signed_authorization_digest text NOT NULL
            CHECK (signed_authorization_digest ~ '^sha256:[a-f0-9]{64}$'),
        use_claim_digest text NOT NULL
            CHECK (use_claim_digest ~ '^sha256:[a-f0-9]{64}$'),
        signed_authorization_bytes bytea NOT NULL
            CHECK (
                octet_length(signed_authorization_bytes)
                    BETWEEN 2 AND 131072
            ),
        authorization_bytes bytea NOT NULL
            CHECK (octet_length(authorization_bytes) BETWEEN 2 AND 131072),
        recovery_request_bytes bytea NOT NULL
            CHECK (
                octet_length(recovery_request_bytes) BETWEEN 2 AND 131072
            ),
        recovery_request_intent_bytes bytea NOT NULL
            CHECK (
                octet_length(recovery_request_intent_bytes)
                    BETWEEN 2 AND 131072
            ),
        signed_maker_action_bytes bytea NOT NULL
            CHECK (
                octet_length(signed_maker_action_bytes)
                    BETWEEN 2 AND 131072
            ),
        maker_action_bytes bytea NOT NULL
            CHECK (octet_length(maker_action_bytes) BETWEEN 2 AND 131072),
        signed_checker_action_bytes bytea NOT NULL
            CHECK (
                octet_length(signed_checker_action_bytes)
                    BETWEEN 2 AND 131072
            ),
        checker_action_bytes bytea NOT NULL
            CHECK (octet_length(checker_action_bytes) BETWEEN 2 AND 131072),
        signed_compute_fence_bytes bytea NOT NULL
            CHECK (
                octet_length(signed_compute_fence_bytes)
                    BETWEEN 2 AND 131072
            ),
        compute_fence_bytes bytea NOT NULL
            CHECK (octet_length(compute_fence_bytes) BETWEEN 2 AND 131072),
        signed_credential_drain_bytes bytea NOT NULL
            CHECK (
                octet_length(signed_credential_drain_bytes)
                    BETWEEN 2 AND 131072
            ),
        credential_drain_bytes bytea NOT NULL
            CHECK (
                octet_length(credential_drain_bytes) BETWEEN 2 AND 131072
            ),
        use_claim_bytes bytea NOT NULL
            CHECK (octet_length(use_claim_bytes) BETWEEN 2 AND 131072),
        abandoned_lease_fence bigint NOT NULL
            CHECK (
                abandoned_lease_fence BETWEEN 1 AND 9223372036854775806
            ),
        abandoned_attempt_count integer NOT NULL
            CHECK (abandoned_attempt_count BETWEEN 1 AND 31),
        abandoned_attempt_revision bigint NOT NULL
            CHECK (abandoned_attempt_revision = 1),
        abandoned_worker_id text NOT NULL
            CHECK (
                abandoned_worker_id ~ '^[a-z][a-z0-9._-]{0,127}$'
            ),
        abandoned_worker_credential_digest text NOT NULL
            CHECK (
                abandoned_worker_credential_digest
                    ~ '^sha256:[a-f0-9]{64}$'
            ),
        abandoned_lease_token_digest text NOT NULL
            CHECK (
                abandoned_lease_token_digest ~ '^sha256:[a-f0-9]{64}$'
            ),
        abandoned_leased_at timestamptz(0) NOT NULL,
        abandoned_lease_expires_at timestamptz(0) NOT NULL,
        abandoned_publishing_at timestamptz(0) NOT NULL,
        successor_lease_fence bigint NOT NULL
            CHECK (successor_lease_fence BETWEEN 2 AND 9223372036854775807),
        successor_attempt_count integer NOT NULL
            CHECK (successor_attempt_count BETWEEN 2 AND 32),
        successor_attempt_revision bigint NOT NULL
            CHECK (successor_attempt_revision = 1),
        successor_worker_id text NOT NULL
            CHECK (successor_worker_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
        successor_worker_credential_digest text NOT NULL
            CHECK (
                successor_worker_credential_digest
                    ~ '^sha256:[a-f0-9]{64}$'
            ),
        successor_lease_token_digest text NOT NULL
            CHECK (
                successor_lease_token_digest ~ '^sha256:[a-f0-9]{64}$'
            ),
        successor_leased_at timestamptz(0) NOT NULL,
        successor_lease_expires_at timestamptz(0) NOT NULL,
        consumed_at timestamptz(0) NOT NULL,
        authorization_expires_at timestamptz(0) NOT NULL,
        recorded_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
        CONSTRAINT publishing_recovery_execution_fk
            FOREIGN KEY (tenant_id, run_id)
            REFERENCES control_assurance_execution.executions (
                tenant_id,
                run_id
            ),
        CONSTRAINT publishing_recovery_exact_progression CHECK (
            successor_lease_fence = abandoned_lease_fence + 1
            AND successor_attempt_count = abandoned_attempt_count + 1
        ),
        CONSTRAINT publishing_recovery_time_order CHECK (
            abandoned_lease_expires_at > abandoned_leased_at
            AND abandoned_publishing_at >= abandoned_leased_at
            AND abandoned_publishing_at < abandoned_lease_expires_at
            AND successor_leased_at >= abandoned_lease_expires_at
            AND successor_lease_expires_at > successor_leased_at
            AND consumed_at < authorization_expires_at
            AND consumed_at < successor_lease_expires_at
        ),
        CONSTRAINT publishing_recovery_exact_byte_digests CHECK (
            authorization_id =
                'sha256:' || encode(sha256(authorization_bytes), 'hex')
            AND signed_authorization_digest =
                'sha256:' ||
                encode(sha256(signed_authorization_bytes), 'hex')
            AND recovery_request_digest =
                'sha256:' || encode(sha256(recovery_request_bytes), 'hex')
            AND recovery_request_intent_digest =
                'sha256:' ||
                encode(sha256(recovery_request_intent_bytes), 'hex')
            AND signed_maker_action_digest =
                'sha256:' ||
                encode(sha256(signed_maker_action_bytes), 'hex')
            AND maker_action_digest =
                'sha256:' || encode(sha256(maker_action_bytes), 'hex')
            AND signed_checker_action_digest =
                'sha256:' ||
                encode(sha256(signed_checker_action_bytes), 'hex')
            AND checker_action_digest =
                'sha256:' || encode(sha256(checker_action_bytes), 'hex')
            AND signed_compute_fence_digest =
                'sha256:' ||
                encode(sha256(signed_compute_fence_bytes), 'hex')
            AND compute_fence_digest =
                'sha256:' || encode(sha256(compute_fence_bytes), 'hex')
            AND signed_credential_drain_digest =
                'sha256:' ||
                encode(sha256(signed_credential_drain_bytes), 'hex')
            AND credential_drain_digest =
                'sha256:' ||
                encode(sha256(credential_drain_bytes), 'hex')
            AND use_claim_digest =
                'sha256:' || encode(sha256(use_claim_bytes), 'hex')
        ),
        CONSTRAINT publishing_recovery_json_shapes CHECK (
            jsonb_typeof(
                convert_from(signed_authorization_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(authorization_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(recovery_request_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(recovery_request_intent_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(signed_maker_action_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(maker_action_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(signed_checker_action_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(checker_action_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(signed_compute_fence_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(compute_fence_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(signed_credential_drain_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(credential_drain_bytes, 'UTF8')::jsonb
            ) = 'object'
            AND jsonb_typeof(
                convert_from(use_claim_bytes, 'UTF8')::jsonb
            ) = 'object'
        ),
        CONSTRAINT publishing_recovery_root_binding CHECK (
            COALESCE((
                convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'tenant_id' = tenant_id
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'run_id' = run_id
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'control_id' = control_id
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'configuration_digest' = configuration_digest
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'execution_plan_digest' = execution_plan_digest
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'execution_identity_digest'
                    = execution_identity_digest
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'recovery_request_digest'
                    = recovery_request_digest
                AND convert_from(recovery_request_bytes, 'UTF8')::jsonb
                    ->> 'intent_digest'
                    = recovery_request_intent_digest
                AND convert_from(recovery_request_intent_bytes, 'UTF8')::jsonb
                    ->> 'pam_scope_digest'
                    = pam_scope_digest
                AND convert_from(recovery_request_intent_bytes, 'UTF8')::jsonb
                    ->> 'pam_execution_binding_digest'
                    = pam_execution_binding_digest
                AND convert_from(signed_maker_action_bytes, 'UTF8')::jsonb
                    ->> 'actor_action_digest'
                    = maker_action_digest
                AND convert_from(authorization_bytes, 'UTF8')::jsonb
                    ->> 'signed_checker_action_digest'
                    = signed_checker_action_digest
                AND convert_from(signed_checker_action_bytes, 'UTF8')::jsonb
                    ->> 'actor_action_digest'
                    = checker_action_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'authorization_id' = authorization_id
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'tenant_id' = tenant_id
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'run_id' = run_id
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'recovery_request_digest'
                    = recovery_request_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'execution_plan_digest' = execution_plan_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'execution_identity_digest'
                    = execution_identity_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'pam_scope_digest' = pam_scope_digest
                AND (
                    convert_from(use_claim_bytes, 'UTF8')::jsonb
                        ->> 'pam_snapshot_high_watermark'
                    )::bigint = pam_snapshot_high_watermark
                AND (
                    convert_from(use_claim_bytes, 'UTF8')::jsonb
                        ->> 'pam_lifecycle_record_count'
                    )::integer = pam_lifecycle_record_count
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'relaunch_fence_operation_digest'
                    = relaunch_fence_operation_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'issuance_fence_operation_digest'
                    = issuance_fence_operation_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'abandoned_attempt_digest'
                    = abandoned_attempt_digest
                AND convert_from(use_claim_bytes, 'UTF8')::jsonb
                    ->> 'successor_claim_digest'
                    = successor_claim_digest
            ), FALSE)
        )
    );

-- Migration 5 intentionally refuses to reinterpret a v1 recovery row as v2.
-- An installation that already created migration 4 with the former table
-- shape needs an explicit, audited archive/migration procedure.  Failing here
-- is safer than installing a v2 function against a silently incompatible
-- append-only table.
DO $recovery_v2_shape_check$
DECLARE
    missing_columns text[];
BEGIN
    SELECT array_agg(required.column_name ORDER BY required.column_name)
    INTO missing_columns
    FROM (
        VALUES
            ('recovery_request_intent_digest'),
            ('signed_maker_action_digest'),
            ('maker_action_digest'),
            ('signed_checker_action_digest'),
            ('checker_action_digest'),
            ('pam_scope_digest'),
            ('pam_snapshot_high_watermark'),
            ('pam_lifecycle_record_count'),
            ('relaunch_fence_operation_digest'),
            ('issuance_fence_operation_digest'),
            ('recovery_request_intent_bytes'),
            ('signed_maker_action_bytes'),
            ('maker_action_bytes'),
            ('signed_checker_action_bytes'),
            ('checker_action_bytes')
    ) AS required(column_name)
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'control_assurance_execution'
          AND relation.relname = 'publishing_recovery_authorizations'
          AND attribute.attname = required.column_name
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
    );
    IF missing_columns IS NOT NULL THEN
        RAISE EXCEPTION
            'publishing recovery v2 requires an explicit v1 archive migration; missing columns: %',
            missing_columns;
    END IF;
END;
$recovery_v2_shape_check$;

COMMENT ON COLUMN
    control_assurance_execution.publishing_recovery_authorizations.abandoned_worker_credential_digest
IS
    'Signed scheduler/recovery-authority assertion retained for audit; the execution journal did not observe or persist this credential digest.';
COMMENT ON COLUMN
    control_assurance_execution.publishing_recovery_authorizations.abandoned_leased_at
IS
    'Signed scheduler/recovery-authority assertion retained for audit; the execution journal independently compares only the persisted publishing_at timestamp.';
COMMENT ON COLUMN
    control_assurance_execution.publishing_recovery_authorizations.successor_worker_credential_digest
IS
    'Signed scheduler/recovery-authority assertion retained for audit; the current scheduler journal CAS persists worker_id and lease_token_digest, not this credential digest.';
COMMENT ON COLUMN
    control_assurance_execution.publishing_recovery_authorizations.successor_lease_expires_at
IS
    'Signed scheduler/recovery-authority assertion retained for audit and bounded against the database consumption clock; execution_attempts does not persist scheduler lease expiry.';

CREATE INDEX IF NOT EXISTS execution_attempt_recovery
    ON control_assurance_execution.execution_attempts
        (tenant_id, state, prepared_at, run_id, lease_fence)
    WHERE state IN ('prepared', 'publishing', 'uncertain');

CREATE OR REPLACE FUNCTION
    control_assurance_execution.own_execution_insert_clock()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.execution_identity_digest IS NOT NULL
       OR NEW.execution_identity_bytes IS NOT NULL
       OR NEW.completion_lease_fence IS NOT NULL
       OR NEW.evidence_digest IS NOT NULL
       OR NEW.executor_receipt_digest IS NOT NULL
       OR NEW.executor_receipt_bytes IS NOT NULL
       OR NEW.completed_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'new execution cannot start completed'
            USING ERRCODE = '23000';
    END IF;
    NEW.created_at := transaction_timestamp();
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS execution_insert_clock
    ON control_assurance_execution.executions;
CREATE TRIGGER execution_insert_clock
BEFORE INSERT ON control_assurance_execution.executions
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.own_execution_insert_clock();

CREATE OR REPLACE FUNCTION
    control_assurance_execution.own_attempt_insert_clock()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    expected_fence bigint;
    expected_attempt_count integer;
BEGIN
    SELECT highest_lease_fence, highest_attempt_count
    INTO expected_fence, expected_attempt_count
    FROM control_assurance_execution.executions
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;
    IF NOT FOUND
       OR NEW.lease_fence <> expected_fence
       OR NEW.attempt_count <> expected_attempt_count
       OR NEW.finished_at IS NOT NULL
       OR NEW.error_code IS NOT NULL
       OR NEW.evidence_digest IS NOT NULL
       OR NEW.executor_receipt_digest IS NOT NULL
       OR NEW.executor_receipt_bytes IS NOT NULL
    THEN
        RAISE EXCEPTION 'execution attempt does not match current fence'
            USING ERRCODE = '23000';
    END IF;
    IF NEW.state = 'prepared'
       AND NEW.revision = 0
       AND NEW.publishing_at IS NULL
    THEN
        NEW.prepared_at := transaction_timestamp();
    ELSIF NEW.state = 'publishing'
       AND NEW.revision = 1
       AND NEW.publishing_at IS NOT NULL
       AND EXISTS (
           SELECT 1
           FROM
               control_assurance_execution.publishing_recovery_authorizations
                   AS recovery
           WHERE recovery.tenant_id = NEW.tenant_id
             AND recovery.run_id = NEW.run_id
             AND recovery.successor_lease_fence = NEW.lease_fence
             AND recovery.successor_attempt_count = NEW.attempt_count
             AND recovery.successor_worker_id = NEW.worker_id
             AND recovery.successor_lease_token_digest
                 = NEW.lease_token_digest
             AND recovery.successor_leased_at = NEW.prepared_at
             AND recovery.consumed_at = NEW.publishing_at
       )
    THEN
        -- Preserve the signed scheduler lease time and the database clock used
        -- to consume the authorization; do not replace either with a new call
        -- to the clock.
        NULL;
    ELSE
        RAISE EXCEPTION 'execution attempt insert bypassed recovery authority'
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS execution_attempt_insert_clock
    ON control_assurance_execution.execution_attempts;
CREATE TRIGGER execution_attempt_insert_clock
BEFORE INSERT ON control_assurance_execution.execution_attempts
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.own_attempt_insert_clock();

CREATE OR REPLACE FUNCTION
    control_assurance_execution.guard_execution_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    current_state text;
BEGIN
    IF ROW(
        NEW.tenant_id,
        NEW.run_id,
        NEW.stable_request_digest,
        NEW.stable_request_bytes,
        NEW.run_request_bytes,
        NEW.control_id,
        NEW.deployment_operation_id,
        NEW.deployment_operation_sequence,
        NEW.deployment_receipt_digest,
        NEW.revision_id,
        NEW.configuration_digest,
        NEW.configuration_bytes,
        NEW.control_profile_id,
        NEW.control_profile_digest,
        NEW.control_profile_media_type,
        NEW.control_profile_bytes,
        NEW.window_start,
        NEW.window_end,
        NEW.execution_plan_digest,
        NEW.execution_plan_bytes,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.tenant_id,
        OLD.run_id,
        OLD.stable_request_digest,
        OLD.stable_request_bytes,
        OLD.run_request_bytes,
        OLD.control_id,
        OLD.deployment_operation_id,
        OLD.deployment_operation_sequence,
        OLD.deployment_receipt_digest,
        OLD.revision_id,
        OLD.configuration_digest,
        OLD.configuration_bytes,
        OLD.control_profile_id,
        OLD.control_profile_digest,
        OLD.control_profile_media_type,
        OLD.control_profile_bytes,
        OLD.window_start,
        OLD.window_end,
        OLD.execution_plan_digest,
        OLD.execution_plan_bytes,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'immutable execution identity'
            USING ERRCODE = '23000';
    END IF;
    IF NEW.highest_lease_fence < OLD.highest_lease_fence
       OR NEW.highest_attempt_count < OLD.highest_attempt_count
       OR (
           NEW.highest_lease_fence > OLD.highest_lease_fence
           AND NEW.highest_attempt_count <= OLD.highest_attempt_count
       )
       OR (
           NEW.highest_lease_fence = OLD.highest_lease_fence
           AND NEW.highest_attempt_count <> OLD.highest_attempt_count
       )
    THEN
        RAISE EXCEPTION 'execution fence must advance monotonically'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.completion_lease_fence IS NOT NULL
       AND ROW(
           NEW.completion_lease_fence,
           NEW.evidence_digest,
           NEW.executor_receipt_digest,
           NEW.executor_receipt_bytes,
           NEW.completed_at
       ) IS DISTINCT FROM ROW(
           OLD.completion_lease_fence,
           OLD.evidence_digest,
           OLD.executor_receipt_digest,
           OLD.executor_receipt_bytes,
           OLD.completed_at
       )
    THEN
        RAISE EXCEPTION 'immutable execution completion'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.completion_lease_fence IS NOT NULL
       AND (
           NEW.highest_lease_fence <> OLD.highest_lease_fence
           OR NEW.highest_attempt_count <> OLD.highest_attempt_count
       )
    THEN
        RAISE EXCEPTION 'completed execution cannot be reclaimed'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.execution_identity_digest IS NOT NULL
       AND ROW(
           NEW.execution_identity_digest,
           NEW.execution_identity_bytes
       ) IS DISTINCT FROM ROW(
           OLD.execution_identity_digest,
           OLD.execution_identity_bytes
       )
    THEN
        RAISE EXCEPTION 'immutable execution environment identity'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.execution_identity_digest IS NOT NULL
       AND (
           NEW.highest_lease_fence <> OLD.highest_lease_fence
           OR NEW.highest_attempt_count <> OLD.highest_attempt_count
       )
       AND NOT EXISTS (
           SELECT 1
           FROM
               control_assurance_execution.publishing_recovery_authorizations
                   AS recovery
           WHERE recovery.tenant_id = OLD.tenant_id
             AND recovery.run_id = OLD.run_id
             AND recovery.control_id = OLD.control_id
             AND recovery.configuration_digest = OLD.configuration_digest
             AND recovery.execution_plan_digest = OLD.execution_plan_digest
             AND recovery.execution_identity_digest
                 = OLD.execution_identity_digest
             AND recovery.abandoned_lease_fence
                 = OLD.highest_lease_fence
             AND recovery.abandoned_attempt_count
                 = OLD.highest_attempt_count
             AND recovery.successor_lease_fence
                 = NEW.highest_lease_fence
             AND recovery.successor_attempt_count
                 = NEW.highest_attempt_count
       )
    THEN
        RAISE EXCEPTION
            'identity-bound publishing execution requires reconciliation'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.execution_identity_digest IS NULL
       AND NEW.execution_identity_digest IS NOT NULL
    THEN
        SELECT state
        INTO current_state
        FROM control_assurance_execution.execution_attempts
        WHERE tenant_id = OLD.tenant_id
          AND run_id = OLD.run_id
          AND lease_fence = OLD.highest_lease_fence;
        IF NOT FOUND
           OR current_state <> 'publishing'
           OR NEW.highest_lease_fence <> OLD.highest_lease_fence
           OR NEW.highest_attempt_count <> OLD.highest_attempt_count
        THEN
            RAISE EXCEPTION
                'execution environment identity requires current publishing attempt'
                USING ERRCODE = '23000';
        END IF;
    END IF;
    IF OLD.completion_lease_fence IS NULL
       AND NEW.completion_lease_fence IS NOT NULL
    THEN
        NEW.completed_at := statement_timestamp();
    END IF;
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS execution_update_guard
    ON control_assurance_execution.executions;
CREATE TRIGGER execution_update_guard
BEFORE UPDATE ON control_assurance_execution.executions
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.guard_execution_update();

CREATE OR REPLACE FUNCTION
    control_assurance_execution.guard_attempt_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    expected_fence bigint;
    completed_fence bigint;
BEGIN
    IF ROW(
        NEW.tenant_id,
        NEW.run_id,
        NEW.lease_fence,
        NEW.attempt_count,
        NEW.worker_id,
        NEW.lease_token_digest,
        NEW.prepared_at
    ) IS DISTINCT FROM ROW(
        OLD.tenant_id,
        OLD.run_id,
        OLD.lease_fence,
        OLD.attempt_count,
        OLD.worker_id,
        OLD.lease_token_digest,
        OLD.prepared_at
    ) THEN
        RAISE EXCEPTION 'immutable execution attempt identity'
            USING ERRCODE = '23000';
    END IF;
    SELECT highest_lease_fence, completion_lease_fence
    INTO expected_fence, completed_fence
    FROM control_assurance_execution.executions
    WHERE tenant_id = OLD.tenant_id AND run_id = OLD.run_id;
    IF NOT FOUND
       OR OLD.lease_fence <> expected_fence
       OR completed_fence IS NOT NULL
    THEN
        RAISE EXCEPTION 'only the current unfinished attempt may transition'
            USING ERRCODE = '23000';
    END IF;
    IF NOT (
        (
            OLD.state = 'prepared'
            AND NEW.state IN ('publishing', 'failed', 'uncertain')
            AND NEW.revision = OLD.revision + 1
        )
        OR (
            OLD.state = 'publishing'
            AND NEW.state IN ('completed', 'failed', 'uncertain')
            AND NEW.revision = OLD.revision + 1
            AND NEW.publishing_at IS NOT DISTINCT FROM OLD.publishing_at
        )
    ) THEN
        RAISE EXCEPTION 'invalid execution attempt transition'
            USING ERRCODE = '23000';
    END IF;
    IF OLD.state = 'prepared' AND NEW.state = 'publishing' THEN
        NEW.publishing_at := statement_timestamp();
    ELSIF NEW.state IN ('completed', 'failed', 'uncertain') THEN
        IF OLD.state = 'publishing'
           AND NEW.state = 'uncertain'
           AND NEW.error_code = 'recovery-superseded'
           AND EXISTS (
               SELECT 1
               FROM
                   control_assurance_execution
                       .publishing_recovery_authorizations AS recovery
               WHERE recovery.tenant_id = OLD.tenant_id
                 AND recovery.run_id = OLD.run_id
                 AND recovery.abandoned_lease_fence = OLD.lease_fence
                 AND recovery.abandoned_attempt_count = OLD.attempt_count
                 AND recovery.abandoned_attempt_revision = OLD.revision
                 AND recovery.abandoned_worker_id = OLD.worker_id
                 AND recovery.abandoned_lease_token_digest
                     = OLD.lease_token_digest
                 AND recovery.abandoned_publishing_at = OLD.publishing_at
                 AND recovery.consumed_at = NEW.finished_at
           )
        THEN
            -- Keep the database-clock value already bound into the signed use
            -- claim and the append-only recovery record.
            NULL;
        ELSE
            NEW.finished_at := statement_timestamp();
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS execution_attempt_update_guard
    ON control_assurance_execution.execution_attempts;
CREATE TRIGGER execution_attempt_update_guard
BEFORE UPDATE ON control_assurance_execution.execution_attempts
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.guard_attempt_update();

CREATE OR REPLACE FUNCTION
    control_assurance_execution.reject_execution_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'execution journal rows are append-preserving'
        USING ERRCODE = '23000';
END;
$function$;

DROP TRIGGER IF EXISTS execution_delete_guard
    ON control_assurance_execution.executions;
CREATE TRIGGER execution_delete_guard
BEFORE DELETE ON control_assurance_execution.executions
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.reject_execution_delete();

DROP TRIGGER IF EXISTS execution_attempt_delete_guard
    ON control_assurance_execution.execution_attempts;
CREATE TRIGGER execution_attempt_delete_guard
BEFORE DELETE ON control_assurance_execution.execution_attempts
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.reject_execution_delete();

CREATE OR REPLACE FUNCTION
    control_assurance_execution.validate_execution_consistency()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    selected_tenant text;
    selected_run text;
    execution_row control_assurance_execution.executions%ROWTYPE;
    attempt_row control_assurance_execution.execution_attempts%ROWTYPE;
BEGIN
    selected_tenant := NEW.tenant_id;
    selected_run := NEW.run_id;

    SELECT *
    INTO execution_row
    FROM control_assurance_execution.executions
    WHERE tenant_id = selected_tenant AND run_id = selected_run;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution attempt lacks logical execution'
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO attempt_row
    FROM control_assurance_execution.execution_attempts
    WHERE tenant_id = selected_tenant
      AND run_id = selected_run
      AND lease_fence = execution_row.highest_lease_fence;

    IF NOT FOUND
       OR attempt_row.attempt_count <> execution_row.highest_attempt_count
    THEN
        RAISE EXCEPTION 'execution current fence lacks exact attempt'
            USING ERRCODE = '23514';
    END IF;

    IF execution_row.completion_lease_fence IS NULL THEN
        IF attempt_row.state = 'completed' THEN
            RAISE EXCEPTION 'completed attempt lacks logical completion'
                USING ERRCODE = '23514';
        END IF;
    ELSIF (
        attempt_row.state <> 'completed'
        OR execution_row.completion_lease_fence <> attempt_row.lease_fence
        OR execution_row.evidence_digest
            IS DISTINCT FROM attempt_row.evidence_digest
        OR execution_row.executor_receipt_digest
            IS DISTINCT FROM attempt_row.executor_receipt_digest
        OR execution_row.executor_receipt_bytes
            IS DISTINCT FROM attempt_row.executor_receipt_bytes
    ) THEN
        RAISE EXCEPTION 'logical completion differs from current attempt'
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END;
$function$;

DROP TRIGGER IF EXISTS execution_consistency_check
    ON control_assurance_execution.executions;
CREATE CONSTRAINT TRIGGER execution_consistency_check
AFTER INSERT OR UPDATE ON control_assurance_execution.executions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.validate_execution_consistency();

DROP TRIGGER IF EXISTS execution_attempt_consistency_check
    ON control_assurance_execution.execution_attempts;
CREATE CONSTRAINT TRIGGER execution_attempt_consistency_check
AFTER INSERT OR UPDATE ON control_assurance_execution.execution_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.validate_execution_consistency();

ALTER TABLE control_assurance_execution.executions
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_execution.executions
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_execution.execution_attempts
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_execution.execution_attempts
    FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS execution_tenant
    ON control_assurance_execution.executions;
CREATE POLICY execution_tenant
ON control_assurance_execution.executions
USING (
    tenant_id = control_assurance_execution.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_execution.session_tenant()
);

DROP POLICY IF EXISTS execution_attempt_tenant
    ON control_assurance_execution.execution_attempts;
CREATE POLICY execution_attempt_tenant
ON control_assurance_execution.execution_attempts
USING (
    tenant_id = control_assurance_execution.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_execution.session_tenant()
);

ALTER TABLE
    control_assurance_execution.publishing_recovery_authorizations
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE
    control_assurance_execution.publishing_recovery_authorizations
    FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS publishing_recovery_tenant
    ON control_assurance_execution.publishing_recovery_authorizations;
CREATE POLICY publishing_recovery_tenant
ON control_assurance_execution.publishing_recovery_authorizations
USING (
    tenant_id = control_assurance_execution.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_execution.session_tenant()
);

DROP TRIGGER IF EXISTS publishing_recovery_update_guard
    ON control_assurance_execution.publishing_recovery_authorizations;
CREATE TRIGGER publishing_recovery_update_guard
BEFORE UPDATE ON
    control_assurance_execution.publishing_recovery_authorizations
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.reject_execution_delete();

DROP TRIGGER IF EXISTS publishing_recovery_delete_guard
    ON control_assurance_execution.publishing_recovery_authorizations;
CREATE TRIGGER publishing_recovery_delete_guard
BEFORE DELETE ON
    control_assurance_execution.publishing_recovery_authorizations
FOR EACH ROW
EXECUTE FUNCTION control_assurance_execution.reject_execution_delete();

DROP FUNCTION IF EXISTS
    control_assurance_execution.consume_publishing_recovery_authorization(
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea
    );

CREATE OR REPLACE FUNCTION
    control_assurance_execution.consume_publishing_recovery_authorization(
        p_signed_authorization_bytes bytea,
        p_authorization_bytes bytea,
        p_recovery_request_bytes bytea,
        p_recovery_request_intent_bytes bytea,
        p_signed_maker_action_bytes bytea,
        p_maker_action_bytes bytea,
        p_signed_checker_action_bytes bytea,
        p_checker_action_bytes bytea,
        p_signed_compute_fence_bytes bytea,
        p_compute_fence_bytes bytea,
        p_signed_credential_drain_bytes bytea,
        p_credential_drain_bytes bytea,
        p_use_claim_bytes bytea
    )
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution, pg_temp
AS $function$
DECLARE
    signed_document jsonb;
    authorization_document jsonb;
    request_document jsonb;
    request_intent_document jsonb;
    signed_maker_document jsonb;
    maker_document jsonb;
    signed_checker_document jsonb;
    checker_document jsonb;
    signed_fence_document jsonb;
    fence_document jsonb;
    signed_drain_document jsonb;
    drain_document jsonb;
    use_document jsonb;
    old_document jsonb;
    successor_document jsonb;
    execution_row control_assurance_execution.executions%ROWTYPE;
    attempt_row control_assurance_execution.execution_attempts%ROWTYPE;
    inserted_authorization text;
    transitioned_attempt bigint;
    transitioned_execution text;
    authorization_media_type text;
    authorization_id_value text;
    tenant_value text;
    run_value text;
    control_value text;
    configuration_value text;
    plan_value text;
    identity_value text;
    request_digest_value text;
    request_intent_digest_value text;
    signed_maker_digest_value text;
    maker_digest_value text;
    signed_checker_digest_value text;
    checker_digest_value text;
    pam_scope_value text;
    pam_binding_value text;
    pam_snapshot_high_watermark_value bigint;
    pam_lifecycle_record_count_value integer;
    relaunch_fence_operation_value text;
    issuance_fence_operation_value text;
    abandoned_digest_value text;
    successor_digest_value text;
    signed_fence_digest_value text;
    fence_digest_value text;
    signed_drain_digest_value text;
    drain_digest_value text;
    old_fence bigint;
    old_count integer;
    old_revision bigint;
    old_worker text;
    old_worker_credential text;
    old_token text;
    old_leased_at timestamptz(0);
    old_expires_at timestamptz(0);
    old_publishing_at timestamptz(0);
    successor_fence bigint;
    successor_count integer;
    successor_revision bigint;
    successor_worker text;
    successor_worker_credential text;
    successor_token text;
    successor_leased_at timestamptz(0);
    successor_expires_at timestamptz(0);
    consumed_value timestamptz(0);
    authorization_expires_value timestamptz(0);
    database_second timestamptz(0);
BEGIN
    signed_document :=
        convert_from(p_signed_authorization_bytes, 'UTF8')::jsonb;
    authorization_document :=
        convert_from(p_authorization_bytes, 'UTF8')::jsonb;
    request_document :=
        convert_from(p_recovery_request_bytes, 'UTF8')::jsonb;
    request_intent_document :=
        convert_from(p_recovery_request_intent_bytes, 'UTF8')::jsonb;
    signed_maker_document :=
        convert_from(p_signed_maker_action_bytes, 'UTF8')::jsonb;
    maker_document :=
        convert_from(p_maker_action_bytes, 'UTF8')::jsonb;
    signed_checker_document :=
        convert_from(p_signed_checker_action_bytes, 'UTF8')::jsonb;
    checker_document :=
        convert_from(p_checker_action_bytes, 'UTF8')::jsonb;
    signed_fence_document :=
        convert_from(p_signed_compute_fence_bytes, 'UTF8')::jsonb;
    fence_document :=
        convert_from(p_compute_fence_bytes, 'UTF8')::jsonb;
    signed_drain_document :=
        convert_from(p_signed_credential_drain_bytes, 'UTF8')::jsonb;
    drain_document :=
        convert_from(p_credential_drain_bytes, 'UTF8')::jsonb;
    use_document := convert_from(p_use_claim_bytes, 'UTF8')::jsonb;
    old_document := authorization_document -> 'abandoned_attempt';
    successor_document := authorization_document -> 'successor_claim';

    authorization_media_type := authorization_document ->> 'media_type';
    IF authorization_media_type IS DISTINCT FROM
        'application/vnd.control-assurance.publishing-recovery-authorization.v2+json'
       OR signed_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.signed-publishing-recovery.v2+json'
       OR request_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.publishing-recovery-request.v2+json'
       OR request_intent_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.publishing-recovery-request-intent.v2+json'
       OR signed_maker_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.signed-recovery-actor-action.v2+json'
       OR maker_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.recovery-actor-action.v2+json'
       OR signed_checker_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.signed-recovery-actor-action.v2+json'
       OR checker_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.recovery-actor-action.v2+json'
       OR signed_fence_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.signed-compute-fence-attestation.v2+json'
       OR fence_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.compute-fence-attestation.v2+json'
       OR signed_drain_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.signed-credential-drain-attestation.v2+json'
       OR drain_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.credential-drain-attestation.v2+json'
       OR use_document ->> 'media_type' IS DISTINCT FROM
        'application/vnd.control-assurance.publishing-recovery-use.v2+json'
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                jsonb_build_array(
                    signed_document,
                    authorization_document,
                    request_document,
                    request_intent_document,
                    signed_maker_document,
                    maker_document,
                    signed_checker_document,
                    checker_document,
                    signed_fence_document,
                    fence_document,
                    signed_drain_document,
                    drain_document,
                    use_document
                )
            ) AS versioned(document)
            WHERE versioned.document ->> 'schema_version'
                IS DISTINCT FROM '2.0.0'
       )
       OR signed_document -> 'authorization'
            IS DISTINCT FROM authorization_document
       OR authorization_document -> 'recovery_request'
            IS DISTINCT FROM request_document
       OR request_document -> 'intent'
            IS DISTINCT FROM request_intent_document
       OR request_document -> 'signed_maker_action'
            IS DISTINCT FROM signed_maker_document
       OR signed_maker_document -> 'actor_action'
            IS DISTINCT FROM maker_document
       OR authorization_document -> 'signed_checker_action'
            IS DISTINCT FROM signed_checker_document
       OR signed_checker_document -> 'actor_action'
            IS DISTINCT FROM checker_document
       OR authorization_document -> 'abandoned_attempt'
            IS DISTINCT FROM request_intent_document -> 'abandoned_attempt'
       OR authorization_document -> 'successor_claim'
            IS DISTINCT FROM request_intent_document -> 'successor_claim'
       OR authorization_document -> 'signed_compute_fence_attestation'
            IS DISTINCT FROM signed_fence_document
       OR signed_fence_document -> 'attestation'
            IS DISTINCT FROM fence_document
       OR authorization_document -> 'signed_credential_drain_attestation'
            IS DISTINCT FROM signed_drain_document
       OR signed_drain_document -> 'attestation'
            IS DISTINCT FROM drain_document
    THEN
        RAISE EXCEPTION 'publishing recovery document substitution'
            USING ERRCODE = '23000';
    END IF;

    authorization_id_value :=
        'sha256:' || encode(sha256(p_authorization_bytes), 'hex');
    tenant_value := authorization_document ->> 'tenant_id';
    run_value := authorization_document ->> 'run_id';
    control_value := authorization_document ->> 'control_id';
    configuration_value :=
        authorization_document ->> 'configuration_digest';
    plan_value := authorization_document ->> 'execution_plan_digest';
    identity_value :=
        authorization_document ->> 'execution_identity_digest';
    request_digest_value :=
        'sha256:' || encode(sha256(p_recovery_request_bytes), 'hex');
    request_intent_digest_value :=
        'sha256:' ||
        encode(sha256(p_recovery_request_intent_bytes), 'hex');
    signed_maker_digest_value :=
        'sha256:' || encode(sha256(p_signed_maker_action_bytes), 'hex');
    maker_digest_value :=
        'sha256:' || encode(sha256(p_maker_action_bytes), 'hex');
    signed_checker_digest_value :=
        'sha256:' ||
        encode(sha256(p_signed_checker_action_bytes), 'hex');
    checker_digest_value :=
        'sha256:' || encode(sha256(p_checker_action_bytes), 'hex');
    pam_scope_value :=
        request_intent_document ->> 'pam_scope_digest';
    pam_binding_value :=
        request_intent_document ->> 'pam_execution_binding_digest';
    pam_snapshot_high_watermark_value :=
        (drain_document ->> 'snapshot_high_watermark')::bigint;
    pam_lifecycle_record_count_value :=
        (drain_document ->> 'lifecycle_record_count')::integer;
    relaunch_fence_operation_value :=
        fence_document ->> 'relaunch_fence_operation_digest';
    issuance_fence_operation_value :=
        drain_document ->> 'issuance_fence_operation_digest';
    abandoned_digest_value :=
        fence_document ->> 'abandoned_attempt_digest';
    successor_digest_value :=
        use_document ->> 'successor_claim_digest';
    signed_fence_digest_value :=
        'sha256:' || encode(sha256(p_signed_compute_fence_bytes), 'hex');
    fence_digest_value :=
        'sha256:' || encode(sha256(p_compute_fence_bytes), 'hex');
    signed_drain_digest_value :=
        'sha256:' ||
        encode(sha256(p_signed_credential_drain_bytes), 'hex');
    drain_digest_value :=
        'sha256:' || encode(sha256(p_credential_drain_bytes), 'hex');

    old_fence := (old_document ->> 'lease_fence')::bigint;
    old_count := (old_document ->> 'attempt_count')::integer;
    old_revision := (old_document ->> 'attempt_revision')::bigint;
    old_worker := old_document ->> 'worker_id';
    old_worker_credential :=
        old_document ->> 'worker_credential_digest';
    old_token := old_document ->> 'lease_token_digest';
    old_leased_at := (old_document ->> 'leased_at')::timestamptz;
    old_expires_at :=
        (old_document ->> 'lease_expires_at')::timestamptz;
    old_publishing_at :=
        (old_document ->> 'publishing_at')::timestamptz;
    successor_fence :=
        (successor_document ->> 'lease_fence')::bigint;
    successor_count :=
        (successor_document ->> 'attempt_count')::integer;
    successor_revision :=
        (successor_document ->> 'attempt_revision')::bigint;
    successor_worker := successor_document ->> 'worker_id';
    successor_worker_credential :=
        successor_document ->> 'worker_credential_digest';
    successor_token :=
        successor_document ->> 'lease_token_digest';
    successor_leased_at :=
        (successor_document ->> 'leased_at')::timestamptz;
    successor_expires_at :=
        (successor_document ->> 'lease_expires_at')::timestamptz;
    consumed_value := (use_document ->> 'consumed_at')::timestamptz;
    authorization_expires_value :=
        (authorization_document ->> 'expires_at')::timestamptz;
    database_second :=
        date_trunc('second', clock_timestamp())::timestamptz(0);

    IF NOT control_assurance_execution.assert_session_principal(
            tenant_value,
            session_user::text,
            'recovery',
            session_user::text,
            session_user::text
       )
       OR signed_document ->> 'authorization_id'
            IS DISTINCT FROM authorization_id_value
       OR authorization_document ->> 'recovery_request_digest'
            IS DISTINCT FROM request_digest_value
       OR request_document ->> 'intent_digest'
            IS DISTINCT FROM request_intent_digest_value
       OR signed_maker_document ->> 'actor_action_digest'
            IS DISTINCT FROM maker_digest_value
       OR authorization_document ->> 'signed_checker_action_digest'
            IS DISTINCT FROM signed_checker_digest_value
       OR signed_checker_document ->> 'actor_action_digest'
            IS DISTINCT FROM checker_digest_value
       OR maker_document ->> 'role' IS DISTINCT FROM 'maker'
       OR maker_document ->> 'action' IS DISTINCT FROM 'request'
       OR maker_document ->> 'tenant_id' IS DISTINCT FROM tenant_value
       OR maker_document ->> 'run_id' IS DISTINCT FROM run_value
       OR maker_document ->> 'action_digest'
            IS DISTINCT FROM request_intent_digest_value
       OR checker_document ->> 'role' IS DISTINCT FROM 'checker'
       OR checker_document ->> 'action' IS DISTINCT FROM 'approve'
       OR checker_document ->> 'tenant_id' IS DISTINCT FROM tenant_value
       OR checker_document ->> 'run_id' IS DISTINCT FROM run_value
       OR maker_document ->> 'subject_id'
            IS NOT DISTINCT FROM checker_document ->> 'subject_id'
       OR maker_document ->> 'session_digest'
            IS NOT DISTINCT FROM checker_document ->> 'session_digest'
       OR request_intent_document ->> 'tenant_id'
            IS DISTINCT FROM tenant_value
       OR request_intent_document ->> 'run_id'
            IS DISTINCT FROM run_value
       OR request_intent_document ->> 'control_id'
            IS DISTINCT FROM control_value
       OR request_intent_document ->> 'configuration_digest'
            IS DISTINCT FROM configuration_value
       OR request_intent_document ->> 'execution_plan_digest'
            IS DISTINCT FROM plan_value
       OR request_intent_document ->> 'execution_identity_digest'
            IS DISTINCT FROM identity_value
       OR authorization_document
            ->> 'signed_compute_fence_attestation_digest'
            IS DISTINCT FROM signed_fence_digest_value
       OR authorization_document ->> 'compute_fence_attestation_digest'
            IS DISTINCT FROM fence_digest_value
       OR authorization_document
            ->> 'signed_credential_drain_attestation_digest'
            IS DISTINCT FROM signed_drain_digest_value
       OR authorization_document
            ->> 'credential_drain_attestation_digest'
            IS DISTINCT FROM drain_digest_value
       OR use_document ->> 'authorization_id'
            IS DISTINCT FROM authorization_id_value
       OR use_document ->> 'tenant_id' IS DISTINCT FROM tenant_value
       OR use_document ->> 'run_id' IS DISTINCT FROM run_value
       OR use_document ->> 'recovery_request_digest'
            IS DISTINCT FROM request_digest_value
       OR use_document ->> 'abandoned_attempt_digest'
            IS DISTINCT FROM abandoned_digest_value
       OR COALESCE(successor_digest_value !~ '^sha256:[a-f0-9]{64}$', TRUE)
       OR use_document ->> 'pam_scope_digest'
            IS DISTINCT FROM pam_scope_value
       OR (use_document ->> 'pam_snapshot_high_watermark')::bigint
            IS DISTINCT FROM pam_snapshot_high_watermark_value
       OR (use_document ->> 'pam_lifecycle_record_count')::integer
            IS DISTINCT FROM pam_lifecycle_record_count_value
       OR use_document ->> 'relaunch_fence_operation_digest'
            IS DISTINCT FROM relaunch_fence_operation_value
       OR use_document ->> 'issuance_fence_operation_digest'
            IS DISTINCT FROM issuance_fence_operation_value
       OR fence_document ->> 'recovery_request_digest'
            IS DISTINCT FROM request_digest_value
       OR drain_document ->> 'recovery_request_digest'
            IS DISTINCT FROM request_digest_value
       OR drain_document ->> 'compute_fence_attestation_digest'
            IS DISTINCT FROM fence_digest_value
       OR drain_document ->> 'scope_digest'
            IS DISTINCT FROM pam_scope_value
       OR drain_document ->> 'execution_binding_digest'
            IS DISTINCT FROM pam_binding_value
       OR use_document ->> 'execution_plan_digest'
            IS DISTINCT FROM plan_value
       OR use_document ->> 'execution_identity_digest'
            IS DISTINCT FROM identity_value
       OR (use_document ->> 'authorization_expires_at')::timestamptz
            IS DISTINCT FROM authorization_expires_value
       OR consumed_value > database_second
       OR consumed_value < database_second - interval '5 seconds'
       OR consumed_value <
            (authorization_document ->> 'not_before')::timestamptz
       OR consumed_value <
            (authorization_document ->> 'issued_at')::timestamptz
       OR consumed_value >= authorization_expires_value
       OR consumed_value >= successor_expires_at
       OR database_second >= authorization_expires_value
       OR database_second >= successor_expires_at
       OR successor_fence <> old_fence + 1
       OR successor_count <> old_count + 1
       OR old_revision <> 1
       OR successor_revision <> 1
    THEN
        RAISE EXCEPTION 'publishing recovery document binding mismatch'
            USING ERRCODE = '23000';
    END IF;

    INSERT INTO
        control_assurance_execution.publishing_recovery_authorizations (
            authorization_id,
            tenant_id,
            run_id,
            control_id,
            configuration_digest,
            execution_plan_digest,
            execution_identity_digest,
            recovery_request_digest,
            recovery_request_intent_digest,
            signed_maker_action_digest,
            maker_action_digest,
            signed_checker_action_digest,
            checker_action_digest,
            pam_scope_digest,
            pam_execution_binding_digest,
            pam_snapshot_high_watermark,
            pam_lifecycle_record_count,
            relaunch_fence_operation_digest,
            issuance_fence_operation_digest,
            abandoned_attempt_digest,
            successor_claim_digest,
            signed_compute_fence_digest,
            compute_fence_digest,
            signed_credential_drain_digest,
            credential_drain_digest,
            signed_authorization_digest,
            use_claim_digest,
            signed_authorization_bytes,
            authorization_bytes,
            recovery_request_bytes,
            recovery_request_intent_bytes,
            signed_maker_action_bytes,
            maker_action_bytes,
            signed_checker_action_bytes,
            checker_action_bytes,
            signed_compute_fence_bytes,
            compute_fence_bytes,
            signed_credential_drain_bytes,
            credential_drain_bytes,
            use_claim_bytes,
            abandoned_lease_fence,
            abandoned_attempt_count,
            abandoned_attempt_revision,
            abandoned_worker_id,
            abandoned_worker_credential_digest,
            abandoned_lease_token_digest,
            abandoned_leased_at,
            abandoned_lease_expires_at,
            abandoned_publishing_at,
            successor_lease_fence,
            successor_attempt_count,
            successor_attempt_revision,
            successor_worker_id,
            successor_worker_credential_digest,
            successor_lease_token_digest,
            successor_leased_at,
            successor_lease_expires_at,
            consumed_at,
            authorization_expires_at
        )
    VALUES (
        authorization_id_value,
        tenant_value,
        run_value,
        control_value,
        configuration_value,
        plan_value,
        identity_value,
        request_digest_value,
        request_intent_digest_value,
        signed_maker_digest_value,
        maker_digest_value,
        signed_checker_digest_value,
        checker_digest_value,
        pam_scope_value,
        pam_binding_value,
        pam_snapshot_high_watermark_value,
        pam_lifecycle_record_count_value,
        relaunch_fence_operation_value,
        issuance_fence_operation_value,
        abandoned_digest_value,
        successor_digest_value,
        signed_fence_digest_value,
        fence_digest_value,
        signed_drain_digest_value,
        drain_digest_value,
        'sha256:' ||
            encode(sha256(p_signed_authorization_bytes), 'hex'),
        'sha256:' || encode(sha256(p_use_claim_bytes), 'hex'),
        p_signed_authorization_bytes,
        p_authorization_bytes,
        p_recovery_request_bytes,
        p_recovery_request_intent_bytes,
        p_signed_maker_action_bytes,
        p_maker_action_bytes,
        p_signed_checker_action_bytes,
        p_checker_action_bytes,
        p_signed_compute_fence_bytes,
        p_compute_fence_bytes,
        p_signed_credential_drain_bytes,
        p_credential_drain_bytes,
        p_use_claim_bytes,
        old_fence,
        old_count,
        old_revision,
        old_worker,
        old_worker_credential,
        old_token,
        old_leased_at,
        old_expires_at,
        old_publishing_at,
        successor_fence,
        successor_count,
        successor_revision,
        successor_worker,
        successor_worker_credential,
        successor_token,
        successor_leased_at,
        successor_expires_at,
        consumed_value,
        authorization_expires_value
    )
    ON CONFLICT (authorization_id) DO NOTHING
    RETURNING authorization_id
    INTO inserted_authorization;

    IF inserted_authorization IS NULL THEN
        RETURN FALSE;
    END IF;

    SELECT *
    INTO execution_row
    FROM control_assurance_execution.executions
    WHERE tenant_id = tenant_value
      AND run_id = run_value
    FOR UPDATE;
    IF NOT FOUND
       OR execution_row.control_id <> control_value
       OR execution_row.configuration_digest <> configuration_value
       OR execution_row.execution_plan_digest <> plan_value
       OR execution_row.execution_identity_digest IS DISTINCT FROM
            identity_value
       OR execution_row.execution_identity_bytes IS NULL
       OR execution_row.highest_lease_fence <> old_fence
       OR execution_row.highest_attempt_count <> old_count
       OR execution_row.completion_lease_fence IS NOT NULL
    THEN
        RAISE EXCEPTION 'publishing recovery logical execution changed'
            USING ERRCODE = '23000';
    END IF;

    SELECT *
    INTO attempt_row
    FROM control_assurance_execution.execution_attempts
    WHERE tenant_id = tenant_value
      AND run_id = run_value
      AND lease_fence = old_fence
    FOR UPDATE;
    IF NOT FOUND
       OR attempt_row.attempt_count <> old_count
       OR attempt_row.worker_id <> old_worker
       OR attempt_row.lease_token_digest <> old_token
       OR attempt_row.state <> 'publishing'
       OR attempt_row.revision <> old_revision
       OR attempt_row.publishing_at IS DISTINCT FROM old_publishing_at
       OR attempt_row.finished_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'publishing recovery abandoned attempt changed'
            USING ERRCODE = '23000';
    END IF;

    UPDATE control_assurance_execution.execution_attempts
    SET state = 'uncertain',
        revision = revision + 1,
        finished_at = consumed_value,
        error_code = 'recovery-superseded'
    WHERE tenant_id = tenant_value
      AND run_id = run_value
      AND lease_fence = old_fence
      AND attempt_count = old_count
      AND worker_id = old_worker
      AND lease_token_digest = old_token
      AND state = 'publishing'
      AND revision = old_revision
      AND publishing_at = old_publishing_at
    RETURNING lease_fence
    INTO transitioned_attempt;
    IF transitioned_attempt IS NULL THEN
        RAISE EXCEPTION 'publishing recovery old attempt CAS failed'
            USING ERRCODE = '23000';
    END IF;

    UPDATE control_assurance_execution.executions
    SET highest_lease_fence = successor_fence,
        highest_attempt_count = successor_count
    WHERE tenant_id = tenant_value
      AND run_id = run_value
      AND highest_lease_fence = old_fence
      AND highest_attempt_count = old_count
      AND execution_plan_digest = plan_value
      AND execution_identity_digest = identity_value
      AND completion_lease_fence IS NULL
    RETURNING run_id
    INTO transitioned_execution;
    IF transitioned_execution IS NULL THEN
        RAISE EXCEPTION 'publishing recovery execution CAS failed'
            USING ERRCODE = '23000';
    END IF;

    INSERT INTO control_assurance_execution.execution_attempts (
        tenant_id,
        run_id,
        lease_fence,
        attempt_count,
        worker_id,
        lease_token_digest,
        state,
        revision,
        prepared_at,
        publishing_at
    )
    VALUES (
        tenant_value,
        run_value,
        successor_fence,
        successor_count,
        successor_worker,
        successor_token,
        'publishing',
        successor_revision,
        successor_leased_at,
        consumed_value
    );

    RETURN TRUE;
END;
$function$;

COMMENT ON FUNCTION
    control_assurance_execution.consume_publishing_recovery_authorization(
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea,
        bytea
    )
IS
    'Recovery-only atomic authorization consumption and publishing lease adoption. PostgreSQL does not verify Ed25519: the credentialed recovery service is TCB and must verify the pinned final, fence, drain, maker-IdP, and checker-IdP keys first. Grant EXECUTE only to that dedicated service role; never to PUBLIC or a runtime worker role.';

CREATE OR REPLACE FUNCTION
    control_assurance_execution.configure_login_role(
        p_tenant_id text,
        p_login_role name,
        p_principal_kind text
    )
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_execution
AS $function$
DECLARE
    attributes pg_catalog.pg_roles%ROWTYPE;
BEGIN
    IF session_user <> current_user
       OR p_tenant_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_login_role::text !~ '^[a-z][a-z0-9_]{0,62}$'
       OR p_principal_kind NOT IN ('worker', 'recovery', 'auditor')
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.oid =
                'control_assurance_execution.configure_login_role('
                'text,name,text)'::regprocedure
              AND routine.proowner =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname = 'control_assurance_execution'
              AND namespace.nspowner =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            WHERE database.datname = current_database()
              AND database.datdba =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
    THEN
        RAISE EXCEPTION
            'execution role provisioning requires the exact migration owner'
            USING ERRCODE = '42501';
    END IF;

    EXECUTE format(
        'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );
    SELECT *
    INTO attributes
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = p_login_role;
    IF NOT FOUND
       OR NOT attributes.rolcanlogin
       OR attributes.rolsuper
       OR attributes.rolinherit
       OR attributes.rolcreaterole
       OR attributes.rolcreatedb
       OR attributes.rolreplication
       OR attributes.rolbypassrls
       OR attributes.rolconfig IS NOT NULL
       OR NOT control_assurance_execution.foreign_store_isolated(
            p_login_role
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = attributes.oid
               OR membership.roleid = attributes.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_db_role_setting AS setting
            WHERE setting.setrole = attributes.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            WHERE database.datdba = attributes.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspowner = attributes.oid
               OR pg_catalog.has_schema_privilege(
                    p_login_role,
                    namespace.oid,
                    'CREATE'
               )
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            WHERE relation.relowner = attributes.oid
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.proowner = attributes.oid
       )
       OR pg_catalog.has_database_privilege(
            p_login_role,
            current_database(),
            'CREATE'
       )
       OR pg_catalog.has_database_privilege(
            p_login_role,
            current_database(),
            'TEMPORARY'
       )
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = attribute.attrelid
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                attribute.attacl
            ) AS acl
            WHERE relation.relnamespace =
                    'control_assurance_execution'::regnamespace
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee = attributes.oid
       )
    THEN
        RAISE EXCEPTION 'execution login role is absent or privileged'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO control_assurance_execution.role_entitlements (
        database_role,
        tenant_id,
        principal_kind
    )
    VALUES (p_login_role, p_tenant_id, p_principal_kind)
    ON CONFLICT (database_role) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_execution.role_entitlements AS entitlement
        WHERE entitlement.database_role = p_login_role
          AND entitlement.tenant_id = p_tenant_id
          AND entitlement.principal_kind = p_principal_kind
    ) THEN
        RAISE EXCEPTION 'execution login role is already bound'
            USING ERRCODE = '23505';
    END IF;

    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA '
        'control_assurance_execution FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA '
        'control_assurance_execution FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA '
        'control_assurance_execution FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON SCHEMA '
        'control_assurance_execution FROM %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT USAGE ON SCHEMA control_assurance_execution TO %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION '
        'control_assurance_execution.session_tenant(), '
        'control_assurance_execution.session_principal_kind(), '
        'control_assurance_execution.assert_session_principal('
        'text,text,text,text,text) TO %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT SELECT ON '
        'control_assurance_execution.schema_migrations TO %I',
        p_login_role
    );
    IF p_principal_kind = 'worker' THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON '
            'control_assurance_execution.executions, '
            'control_assurance_execution.execution_attempts TO %I',
            p_login_role
        );
    ELSIF p_principal_kind = 'recovery' THEN
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_execution.executions, '
            'control_assurance_execution.execution_attempts TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT EXECUTE ON FUNCTION '
            'control_assurance_execution.'
            'consume_publishing_recovery_authorization('
            'bytea,bytea,bytea,bytea,bytea,bytea,bytea,'
            'bytea,bytea,bytea,bytea,bytea,bytea) TO %I',
            p_login_role
        );
    ELSE
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_execution.executions, '
            'control_assurance_execution.execution_attempts, '
            'control_assurance_execution.'
            'publishing_recovery_authorizations TO %I',
            p_login_role
        );
    END IF;
    RETURN TRUE;
END;
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_execution FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_execution FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance_execution FROM PUBLIC;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    1,
    'immutable execution plans, fenced attempts and idempotent completion'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    2,
    'immutable public execution environment identity'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    3,
    'database-bound execution identity and conservative HA reconciliation'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    4,
    'signed one-time recovery for identity-bound publishing attempts'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    5,
    'independently signed actor actions and exact PAM recovery scope'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_execution.schema_migrations (
    version,
    description
)
VALUES (
    6,
    'session-user tenant entitlements and minimum-privilege principal admission'
)
ON CONFLICT (version) DO NOTHING;

DO $migration_check$
DECLARE
    installed_versions integer[];
BEGIN
    SELECT array_agg(version ORDER BY version)
    INTO installed_versions
    FROM control_assurance_execution.schema_migrations;
    IF installed_versions IS DISTINCT FROM ARRAY[1, 2, 3, 4, 5, 6] THEN
        RAISE EXCEPTION 'unsupported execution journal schema lineage: %',
            installed_versions;
    END IF;
END;
$migration_check$;

COMMIT;
