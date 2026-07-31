-- Control Assurance runtime catalog and scheduler schema, migrations 1-3.
--
-- Install as a migration owner.  Runtime processes must not own these objects.
-- The migration owner provisions exactly one role_entitlements row per login.
-- Tenant isolation is derived from session_user, never from a caller-set GUC.
-- Secret values are forbidden from this schema. Configurations and profiles
-- contain control logic and validated secret-manager references only; lease
-- material is stored as SHA-256.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE SCHEMA IF NOT EXISTS control_assurance_runtime;

REVOKE ALL ON SCHEMA control_assurance_runtime FROM PUBLIC;

CREATE TABLE IF NOT EXISTS control_assurance_runtime.schema_migrations (
    version integer PRIMARY KEY CHECK (version >= 1),
    description text NOT NULL CHECK (length(description) BETWEEN 1 AND 255),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp()
);

-- Migration 3: a server-asserted deployment tenant for every database login.
-- Application roles receive no write privilege on this table.  Re-provisioning
-- a credential for another tenant is therefore an owner-controlled operation.
CREATE TABLE IF NOT EXISTS control_assurance_runtime.role_entitlements (
    database_role name PRIMARY KEY,
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    principal_kind text NOT NULL
        CHECK (
            principal_kind IN (
                'worker',
                'registrar',
                'reconciler',
                'auditor'
            )
        ),
    provisioned_at timestamptz(0) NOT NULL
        DEFAULT transaction_timestamp(),
    provisioned_by name NOT NULL DEFAULT session_user
);

REVOKE ALL ON control_assurance_runtime.role_entitlements FROM PUBLIC;

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.session_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_runtime
AS $function$
    SELECT entitlement.tenant_id
    FROM control_assurance_runtime.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.session_principal_kind()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_runtime
AS $function$
    SELECT entitlement.principal_kind
    FROM control_assurance_runtime.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.foreign_store_isolated(p_role name)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_runtime
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
            'control_assurance_execution',
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
    control_assurance_runtime.assert_session_principal(
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
SET search_path = pg_catalog, control_assurance_runtime
AS $function$
DECLARE
    entitlement control_assurance_runtime.role_entitlements%ROWTYPE;
    role_record pg_catalog.pg_roles%ROWTYPE;
    relation_record record;
    procedure_record record;
    privilege_name text;
    privilege_present boolean;
    privilege_allowed boolean;
BEGIN
    IF expected_tenant !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR expected_database_role !~ '^[a-z][a-z0-9_]{0,62}$'
       OR expected_principal_kind NOT IN (
            'worker',
            'registrar',
            'reconciler',
            'auditor'
       )
       OR caller_current_role IS DISTINCT FROM expected_database_role
       OR caller_session_role IS DISTINCT FROM expected_database_role
       OR caller_current_role IS DISTINCT FROM caller_session_role
       OR caller_session_role IS DISTINCT FROM session_user::text
    THEN
        RAISE EXCEPTION 'runtime database principal identity mismatch'
            USING ERRCODE = '42501';
    END IF;

    SELECT *
    INTO entitlement
    FROM control_assurance_runtime.role_entitlements
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
       OR NOT control_assurance_runtime.foreign_store_isolated(
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
            'control_assurance_runtime',
            'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            session_user,
            'control_assurance_runtime',
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
            WHERE namespace.nspname = 'control_assurance_runtime'
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
                    'control_assurance_runtime'::regnamespace
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
                    'control_assurance_runtime'::regnamespace
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
                    'control_assurance_runtime'::regnamespace
              AND (
                  acl.grantee = 0
                  OR (
                      acl.grantee = role_record.oid
                      AND acl.is_grantable
                  )
              )
       )
    THEN
        RAISE EXCEPTION 'runtime database principal is over-privileged'
            USING ERRCODE = '42501';
    END IF;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_runtime'::regnamespace
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
                AND CASE entitlement.principal_kind
                WHEN 'worker' THEN
                    (
                        relation_record.relname IN (
                            'schema_migrations',
                            'control_profiles',
                            'deployment_history',
                            'deployment_operation_fences',
                            'current_deployed_controls'
                        )
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname IN (
                            'control_runs',
                            'control_run_claims'
                        )
                        AND privilege_name IN (
                            'SELECT',
                            'INSERT',
                            'UPDATE'
                        )
                    )
                    OR (
                        relation_record.relname = 'control_run_outcomes'
                        AND privilege_name IN ('SELECT', 'INSERT')
                    )
                WHEN 'registrar' THEN
                    (
                        relation_record.relname = 'schema_migrations'
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname = 'control_profiles'
                        AND privilege_name IN ('SELECT', 'INSERT')
                    )
                WHEN 'reconciler' THEN
                    (
                        relation_record.relname IN (
                            'schema_migrations',
                            'control_profiles'
                        )
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname IN (
                            'deployment_history',
                            'deployment_operation_fences',
                            'current_deployed_controls'
                        )
                        AND privilege_name IN (
                            'SELECT',
                            'INSERT',
                            'UPDATE'
                        )
                    )
                WHEN 'auditor' THEN
                    relation_record.relname IN (
                        'schema_migrations',
                        'control_profiles',
                        'deployment_history',
                        'deployment_operation_fences',
                        'current_deployed_controls',
                        'control_runs',
                        'control_run_claims',
                        'control_run_outcomes'
                    )
                    AND privilege_name = 'SELECT'
                    ELSE FALSE
                END;
            IF privilege_present IS DISTINCT FROM privilege_allowed THEN
                RAISE EXCEPTION
                    'runtime database principal table privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_runtime'::regnamespace
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
                    'runtime database principal sequence privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR procedure_record IN
        SELECT procedure.oid, procedure.proname
        FROM pg_catalog.pg_proc AS procedure
        WHERE procedure.pronamespace =
                'control_assurance_runtime'::regnamespace
    LOOP
        privilege_present := pg_catalog.has_function_privilege(
            session_user,
            procedure_record.oid,
            'EXECUTE'
        );
        privilege_allowed := procedure_record.oid = ANY(ARRAY[
            'control_assurance_runtime.session_tenant()'
                ::regprocedure::oid,
            'control_assurance_runtime.session_principal_kind()'
                ::regprocedure::oid,
            'control_assurance_runtime.assert_session_principal('
                'text,text,text,text,text)'::regprocedure::oid
        ]);
        IF privilege_present IS DISTINCT FROM privilege_allowed
        THEN
            RAISE EXCEPTION
                'runtime database principal routine privilege matrix mismatch'
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$function$;

CREATE TABLE IF NOT EXISTS control_assurance_runtime.control_profiles (
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    profile_id text NOT NULL
        CHECK (profile_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    profile_digest text NOT NULL
        CHECK (profile_digest ~ '^sha256:[a-f0-9]{64}$'),
    media_type text NOT NULL
        CHECK (
            length(media_type) BETWEEN 16 AND 128
            AND media_type ~
                '^application/(json|[a-z0-9!#$&^_.+-]+[+]json)$'
        ),
    profile_bytes bytea NOT NULL
        CHECK (octet_length(profile_bytes) BETWEEN 2 AND 1048576),
    registered_at timestamptz(0) NOT NULL,
    registered_by text NOT NULL CHECK (length(registered_by) BETWEEN 1 AND 255),
    PRIMARY KEY (tenant_id, profile_id, profile_digest),
    CONSTRAINT runtime_profile_tenant_digest_unique
        UNIQUE (tenant_id, profile_digest),
    CONSTRAINT runtime_profile_exact_digest CHECK (
        profile_digest = 'sha256:' || encode(sha256(profile_bytes), 'hex')
    )
);

CREATE TABLE IF NOT EXISTS control_assurance_runtime.deployment_history (
    operation_id text PRIMARY KEY
        CHECK (operation_id ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    operation_sequence bigint NOT NULL CHECK (operation_sequence >= 1),
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
    enabled boolean NOT NULL,
    interval_seconds integer NOT NULL
        CHECK (interval_seconds BETWEEN 60 AND 86400),
    collection_lag_seconds integer NOT NULL
        CHECK (collection_lag_seconds BETWEEN 0 AND 3600),
    window_seconds integer NOT NULL
        CHECK (
            window_seconds BETWEEN 60 AND 86400
            AND window_seconds <= interval_seconds
        ),
    lease_fence_at_commit bigint NOT NULL CHECK (lease_fence_at_commit >= 1),
    previous_operation_id text
        REFERENCES control_assurance_runtime.deployment_history(operation_id),
    previous_receipt_digest text
        CHECK (
            previous_receipt_digest IS NULL
            OR previous_receipt_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    receipt_digest text NOT NULL UNIQUE
        CHECK (receipt_digest ~ '^sha256:[a-f0-9]{64}$'),
    receipt_bytes bytea NOT NULL
        CHECK (octet_length(receipt_bytes) BETWEEN 2 AND 65536),
    applied_at timestamptz(0) NOT NULL,
    CONSTRAINT runtime_deployment_sequence_unique
        UNIQUE (tenant_id, control_id, operation_sequence),
    CONSTRAINT runtime_deployment_tenant_operation_unique
        UNIQUE (tenant_id, operation_id),
    CONSTRAINT runtime_deployment_exact_identity_unique
        UNIQUE (tenant_id, control_id, operation_id),
    CONSTRAINT runtime_deployment_exact_profile_fk
        FOREIGN KEY (
            tenant_id,
            control_profile_id,
            control_profile_digest
        )
        REFERENCES control_assurance_runtime.control_profiles (
            tenant_id,
            profile_id,
            profile_digest
        ),
    CONSTRAINT runtime_deployment_exact_configuration_digest CHECK (
        configuration_digest =
            'sha256:' || encode(sha256(configuration_bytes), 'hex')
    ),
    CONSTRAINT runtime_deployment_exact_receipt_digest CHECK (
        receipt_digest = 'sha256:' || encode(sha256(receipt_bytes), 'hex')
    ),
    CONSTRAINT runtime_deployment_previous_pair CHECK (
        (previous_operation_id IS NULL) =
        (previous_receipt_digest IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS runtime_deployment_history_order
    ON control_assurance_runtime.deployment_history
        (tenant_id, control_id, applied_at, operation_sequence);

CREATE TABLE IF NOT EXISTS control_assurance_runtime.deployment_operation_fences (
    operation_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    control_id text NOT NULL,
    highest_lease_fence_seen bigint NOT NULL
        CHECK (highest_lease_fence_seen >= 1),
    CONSTRAINT runtime_deployment_fence_exact_history_fk
        FOREIGN KEY (tenant_id, control_id, operation_id)
        REFERENCES control_assurance_runtime.deployment_history
            (tenant_id, control_id, operation_id)
);

CREATE TABLE IF NOT EXISTS control_assurance_runtime.current_deployed_controls (
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    operation_id text NOT NULL,
    operation_sequence bigint NOT NULL CHECK (operation_sequence >= 1),
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
    enabled boolean NOT NULL,
    interval_seconds integer NOT NULL
        CHECK (interval_seconds BETWEEN 60 AND 86400),
    collection_lag_seconds integer NOT NULL
        CHECK (collection_lag_seconds BETWEEN 0 AND 3600),
    window_seconds integer NOT NULL
        CHECK (
            window_seconds BETWEEN 60 AND 86400
            AND window_seconds <= interval_seconds
        ),
    deployment_receipt_digest text NOT NULL
        CHECK (deployment_receipt_digest ~ '^sha256:[a-f0-9]{64}$'),
    lease_fence_at_commit bigint NOT NULL CHECK (lease_fence_at_commit >= 1),
    applied_at timestamptz(0) NOT NULL,
    PRIMARY KEY (tenant_id, control_id),
    CONSTRAINT runtime_current_exact_history_fk
        FOREIGN KEY (tenant_id, control_id, operation_id)
        REFERENCES control_assurance_runtime.deployment_history
            (tenant_id, control_id, operation_id),
    CONSTRAINT runtime_current_exact_configuration_digest CHECK (
        configuration_digest =
            'sha256:' || encode(sha256(configuration_bytes), 'hex')
    )
);

CREATE TABLE IF NOT EXISTS control_assurance_runtime.control_runs (
    run_id text PRIMARY KEY
        CHECK (run_id ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    deployment_operation_id text NOT NULL,
    deployment_operation_sequence bigint NOT NULL CHECK (
        deployment_operation_sequence >= 1
    ),
    deployment_receipt_digest text NOT NULL
        CHECK (deployment_receipt_digest ~ '^sha256:[a-f0-9]{64}$'),
    revision_id text NOT NULL
        CHECK (revision_id ~ '^sha256:[a-f0-9]{64}$'),
    configuration_digest text NOT NULL
        CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    control_profile_id text NOT NULL
        CHECK (control_profile_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_profile_digest text NOT NULL
        CHECK (control_profile_digest ~ '^sha256:[a-f0-9]{64}$'),
    request_bytes bytea NOT NULL
        CHECK (octet_length(request_bytes) BETWEEN 2 AND 65536),
    window_start timestamptz(0) NOT NULL,
    window_end timestamptz(0) NOT NULL,
    due_at timestamptz(0) NOT NULL,
    materialized_at timestamptz(0) NOT NULL,
    state text NOT NULL
        CHECK (state IN ('pending', 'leased', 'succeeded', 'failed')),
    state_version bigint NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    attempt_count integer NOT NULL DEFAULT 0
        CHECK (attempt_count BETWEEN 0 AND 32),
    lease_fence bigint NOT NULL DEFAULT 0 CHECK (lease_fence >= 0),
    lease_owner text
        CHECK (
            lease_owner IS NULL
            OR lease_owner ~ '^[a-z][a-z0-9._-]{0,127}$'
        ),
    lease_token_digest text
        CHECK (
            lease_token_digest IS NULL
            OR lease_token_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    leased_at timestamptz(0),
    lease_expires_at timestamptz(0),
    retry_at timestamptz(0),
    completed_at timestamptz(0),
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
    closure_digest text
        CHECK (
            closure_digest IS NULL
            OR closure_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    failed_at timestamptz(0),
    failure_digest text
        CHECK (
            failure_digest IS NULL
            OR failure_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    CONSTRAINT runtime_run_tenant_id_unique UNIQUE (tenant_id, run_id),
    CONSTRAINT runtime_run_window_unique UNIQUE (
        tenant_id,
        control_id,
        deployment_operation_id,
        window_start,
        window_end
    ),
    CONSTRAINT runtime_run_exact_deployment_fk
        FOREIGN KEY (tenant_id, control_id, deployment_operation_id)
        REFERENCES control_assurance_runtime.deployment_history
            (tenant_id, control_id, operation_id),
    CONSTRAINT runtime_run_exact_profile_fk
        FOREIGN KEY (
            tenant_id,
            control_profile_id,
            control_profile_digest
        )
        REFERENCES control_assurance_runtime.control_profiles (
            tenant_id,
            profile_id,
            profile_digest
        ),
    CONSTRAINT runtime_run_exact_request_digest CHECK (
        run_id = 'sha256:' || encode(sha256(request_bytes), 'hex')
    ),
    CONSTRAINT runtime_run_window_shape CHECK (
        window_start < window_end AND window_end <= due_at
    ),
    CONSTRAINT runtime_run_state_shape CHECK (
        (
            state = 'pending'
            AND state_version = 0
            AND attempt_count = 0
            AND lease_fence = 0
            AND lease_owner IS NULL
            AND lease_token_digest IS NULL
            AND leased_at IS NULL
            AND lease_expires_at IS NULL
            AND retry_at IS NULL
            AND completed_at IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND closure_digest IS NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'leased'
            AND attempt_count BETWEEN 1 AND 32
            AND lease_fence = attempt_count
            AND lease_owner IS NOT NULL
            AND lease_token_digest IS NOT NULL
            AND leased_at IS NOT NULL
            AND lease_expires_at > leased_at
            AND leased_at >= due_at
            AND retry_at IS NULL
            AND completed_at IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND closure_digest IS NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'succeeded'
            AND attempt_count BETWEEN 1 AND 32
            AND lease_fence = attempt_count
            AND lease_owner IS NULL
            AND lease_token_digest IS NULL
            AND leased_at IS NULL
            AND lease_expires_at IS NULL
            AND retry_at IS NULL
            AND completed_at IS NOT NULL
            AND completed_at >= window_end
            AND evidence_digest IS NOT NULL
            AND executor_receipt_digest IS NOT NULL
            AND closure_digest IS NOT NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'failed'
            AND attempt_count BETWEEN 1 AND 32
            AND lease_fence = attempt_count
            AND lease_owner IS NULL
            AND lease_token_digest IS NULL
            AND leased_at IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NULL
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND closure_digest IS NULL
            AND failed_at IS NOT NULL
            AND failure_digest IS NOT NULL
            AND (retry_at IS NULL OR retry_at > failed_at)
        )
    )
);

CREATE INDEX IF NOT EXISTS runtime_runs_claim_order
    ON control_assurance_runtime.control_runs
        (tenant_id, due_at, run_id)
    WHERE state IN ('pending', 'leased', 'failed');

CREATE TABLE IF NOT EXISTS control_assurance_runtime.control_run_claims (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    lease_fence bigint NOT NULL CHECK (lease_fence >= 1),
    attempt_count integer NOT NULL CHECK (attempt_count BETWEEN 1 AND 32),
    worker_id text NOT NULL
        CHECK (worker_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    worker_credential_digest text NOT NULL
        CHECK (worker_credential_digest ~ '^sha256:[a-f0-9]{64}$'),
    lease_token_digest text NOT NULL
        CHECK (lease_token_digest ~ '^sha256:[a-f0-9]{64}$'),
    leased_at timestamptz(0) NOT NULL,
    lease_expires_at timestamptz(0) NOT NULL,
    PRIMARY KEY (tenant_id, run_id, lease_fence),
    CONSTRAINT runtime_claim_exact_run_fk
        FOREIGN KEY (tenant_id, run_id)
        REFERENCES control_assurance_runtime.control_runs(tenant_id, run_id),
    CONSTRAINT runtime_claim_shape CHECK (
        lease_fence = attempt_count
        AND lease_expires_at > leased_at
    )
);

CREATE TABLE IF NOT EXISTS control_assurance_runtime.control_run_outcomes (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    lease_fence bigint NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    recorded_at timestamptz(0) NOT NULL,
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
    closure_digest text
        CHECK (
            closure_digest IS NULL
            OR closure_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    closure_bytes bytea
        CHECK (
            closure_bytes IS NULL
            OR octet_length(closure_bytes) BETWEEN 2 AND 65536
        ),
    failure_digest text
        CHECK (
            failure_digest IS NULL
            OR failure_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    retry_at timestamptz(0),
    PRIMARY KEY (tenant_id, run_id, lease_fence),
    CONSTRAINT runtime_outcome_exact_claim_fk
        FOREIGN KEY (tenant_id, run_id, lease_fence)
        REFERENCES control_assurance_runtime.control_run_claims
            (tenant_id, run_id, lease_fence),
    CONSTRAINT runtime_outcome_exact_closure_digest CHECK (
        closure_bytes IS NULL
        OR closure_digest =
            'sha256:' || encode(sha256(closure_bytes), 'hex')
    ),
    CONSTRAINT runtime_outcome_shape CHECK (
        (
            outcome = 'succeeded'
            AND evidence_digest IS NOT NULL
            AND executor_receipt_digest IS NOT NULL
            AND closure_digest IS NOT NULL
            AND closure_bytes IS NOT NULL
            AND failure_digest IS NULL
            AND retry_at IS NULL
        )
        OR (
            outcome = 'failed'
            AND evidence_digest IS NULL
            AND executor_receipt_digest IS NULL
            AND closure_digest IS NULL
            AND closure_bytes IS NULL
            AND failure_digest IS NOT NULL
            AND (retry_at IS NULL OR retry_at > recorded_at)
        )
    )
);

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.reject_immutable_runtime_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION 'runtime ledger rows are immutable'
        USING ERRCODE = '23514';
END;
$function$;

DROP TRIGGER IF EXISTS deployment_history_immutable
    ON control_assurance_runtime.deployment_history;
CREATE TRIGGER deployment_history_immutable
BEFORE UPDATE OR DELETE ON control_assurance_runtime.deployment_history
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.reject_immutable_runtime_row();

DROP TRIGGER IF EXISTS control_profiles_immutable
    ON control_assurance_runtime.control_profiles;
CREATE TRIGGER control_profiles_immutable
BEFORE UPDATE OR DELETE ON control_assurance_runtime.control_profiles
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.reject_immutable_runtime_row();

DROP TRIGGER IF EXISTS control_run_claims_immutable
    ON control_assurance_runtime.control_run_claims;
CREATE TRIGGER control_run_claims_immutable
BEFORE UPDATE OR DELETE ON control_assurance_runtime.control_run_claims
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.reject_immutable_runtime_row();

DROP TRIGGER IF EXISTS control_run_outcomes_immutable
    ON control_assurance_runtime.control_run_outcomes;
CREATE TRIGGER control_run_outcomes_immutable
BEFORE UPDATE OR DELETE ON control_assurance_runtime.control_run_outcomes
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.reject_immutable_runtime_row();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.enforce_fence_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'runtime deployment fences cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.operation_id <> OLD.operation_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.control_id <> OLD.control_id
       OR NEW.highest_lease_fence_seen <= OLD.highest_lease_fence_seen THEN
        RAISE EXCEPTION 'runtime deployment fence must strictly advance'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS deployment_fence_advance
    ON control_assurance_runtime.deployment_operation_fences;
CREATE TRIGGER deployment_fence_advance
BEFORE UPDATE OR DELETE
ON control_assurance_runtime.deployment_operation_fences
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.enforce_fence_advance();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.enforce_current_deployment_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'current runtime deployments cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.tenant_id <> OLD.tenant_id
        OR NEW.control_id <> OLD.control_id
        OR NEW.operation_sequence <= OLD.operation_sequence
    ) THEN
        RAISE EXCEPTION 'current runtime deployment must strictly advance'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_runtime.deployment_history AS history
        WHERE history.operation_id = NEW.operation_id
          AND history.tenant_id = NEW.tenant_id
          AND history.control_id = NEW.control_id
          AND history.operation_sequence = NEW.operation_sequence
          AND history.revision_id = NEW.revision_id
          AND history.configuration_digest = NEW.configuration_digest
          AND history.configuration_bytes = NEW.configuration_bytes
          AND history.control_profile_id = NEW.control_profile_id
          AND history.control_profile_digest = NEW.control_profile_digest
          AND history.enabled = NEW.enabled
          AND history.interval_seconds = NEW.interval_seconds
          AND history.collection_lag_seconds = NEW.collection_lag_seconds
          AND history.window_seconds = NEW.window_seconds
          AND history.receipt_digest = NEW.deployment_receipt_digest
          AND history.lease_fence_at_commit = NEW.lease_fence_at_commit
          AND history.applied_at = NEW.applied_at
    ) THEN
        RAISE EXCEPTION 'current runtime deployment differs from history'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS current_deployment_advance
    ON control_assurance_runtime.current_deployed_controls;
CREATE TRIGGER current_deployment_advance
BEFORE INSERT OR UPDATE OR DELETE ON
    control_assurance_runtime.current_deployed_controls
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.enforce_current_deployment_advance();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.enforce_control_run_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'control runs cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.run_id <> OLD.run_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.control_id <> OLD.control_id
       OR NEW.deployment_operation_id <> OLD.deployment_operation_id
       OR NEW.deployment_operation_sequence <> OLD.deployment_operation_sequence
       OR NEW.deployment_receipt_digest <> OLD.deployment_receipt_digest
       OR NEW.revision_id <> OLD.revision_id
       OR NEW.configuration_digest <> OLD.configuration_digest
       OR NEW.control_profile_id <> OLD.control_profile_id
       OR NEW.control_profile_digest <> OLD.control_profile_digest
       OR NEW.request_bytes <> OLD.request_bytes
       OR NEW.window_start <> OLD.window_start
       OR NEW.window_end <> OLD.window_end
       OR NEW.due_at <> OLD.due_at
       OR NEW.materialized_at <> OLD.materialized_at THEN
        RAISE EXCEPTION 'control run request identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state_version <> OLD.state_version + 1 THEN
        RAISE EXCEPTION 'control run state version must advance exactly once'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'leased' THEN
        IF NEW.attempt_count <> OLD.attempt_count + 1
           OR NEW.lease_fence <> OLD.lease_fence + 1
           OR NOT (
                OLD.state = 'pending'
                OR (
                    OLD.state = 'leased'
                    AND OLD.lease_expires_at <= NEW.leased_at
                )
                OR (
                    OLD.state = 'failed'
                    AND OLD.retry_at IS NOT NULL
                    AND OLD.retry_at <= NEW.leased_at
                )
           ) THEN
            RAISE EXCEPTION 'control run lease transition is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.state IN ('succeeded', 'failed') THEN
        IF OLD.state <> 'leased'
           OR NEW.attempt_count <> OLD.attempt_count
           OR NEW.lease_fence <> OLD.lease_fence THEN
            RAISE EXCEPTION 'control run terminal transition is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'control run state transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS control_run_identity_immutable
    ON control_assurance_runtime.control_runs;
CREATE TRIGGER control_run_identity_immutable
BEFORE UPDATE OR DELETE ON control_assurance_runtime.control_runs
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.enforce_control_run_identity_immutable();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.validate_control_profile_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    profile jsonb;
BEGIN
    profile := convert_from(NEW.profile_bytes, 'UTF8')::jsonb;
    IF jsonb_typeof(profile) <> 'object' THEN
        RAISE EXCEPTION 'control profile must be one JSON object'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN invalid_text_representation OR character_not_in_repertoire THEN
        RAISE EXCEPTION 'control profile JSON cannot be decoded'
            USING ERRCODE = '23514';
END;
$function$;

DROP TRIGGER IF EXISTS control_profile_validate_insert
    ON control_assurance_runtime.control_profiles;
CREATE TRIGGER control_profile_validate_insert
BEFORE INSERT ON control_assurance_runtime.control_profiles
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.validate_control_profile_insert();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.validate_deployment_history_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    configuration jsonb;
    receipt jsonb;
    latest_operation_id text;
    latest_operation_sequence bigint;
    latest_receipt_digest text;
    latest_applied_at timestamptz(0);
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:runtime-control:'
                || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );
    configuration := convert_from(NEW.configuration_bytes, 'UTF8')::jsonb;
    receipt := convert_from(NEW.receipt_bytes, 'UTF8')::jsonb;
    IF configuration->>'tenant_id' <> NEW.tenant_id
       OR configuration->>'control_id' <> NEW.control_id
       OR (configuration->>'enabled')::boolean <> NEW.enabled
       OR (configuration#>>'{schedule,interval_seconds}')::integer
            <> NEW.interval_seconds
       OR (configuration#>>'{schedule,collection_lag_seconds}')::integer
            <> NEW.collection_lag_seconds
       OR (configuration#>>'{schedule,window_seconds}')::integer
            <> NEW.window_seconds
       OR configuration->>'control_profile_id'
            <> NEW.control_profile_id
       OR configuration->>'control_profile_digest'
            <> NEW.control_profile_digest THEN
        RAISE EXCEPTION 'deployment configuration fields differ from history'
            USING ERRCODE = '23514';
    END IF;
    IF receipt->>'tenant_id' <> NEW.tenant_id
       OR receipt->>'control_id' <> NEW.control_id
       OR receipt->>'operation_id' <> NEW.operation_id
       OR (receipt->>'operation_sequence')::bigint
            <> NEW.operation_sequence
       OR (receipt->>'lease_fence_at_commit')::bigint
            <> NEW.lease_fence_at_commit
       OR receipt->>'revision_id' <> NEW.revision_id
       OR receipt->>'configuration_digest' <> NEW.configuration_digest
       OR receipt->>'control_profile_id' <> NEW.control_profile_id
       OR receipt->>'control_profile_digest'
            <> NEW.control_profile_digest
       OR NULLIF(receipt->>'previous_operation_id', '')
            IS DISTINCT FROM NEW.previous_operation_id
       OR NULLIF(receipt->>'previous_receipt_digest', '')
            IS DISTINCT FROM NEW.previous_receipt_digest
       OR (receipt->>'applied_at')::timestamptz <> NEW.applied_at THEN
        RAISE EXCEPTION 'deployment receipt fields differ from history'
            USING ERRCODE = '23514';
    END IF;
    SELECT previous.operation_id,
           previous.operation_sequence,
           previous.receipt_digest,
           previous.applied_at
    INTO latest_operation_id,
         latest_operation_sequence,
         latest_receipt_digest,
         latest_applied_at
    FROM control_assurance_runtime.deployment_history AS previous
    WHERE previous.tenant_id = NEW.tenant_id
      AND previous.control_id = NEW.control_id
    ORDER BY previous.operation_sequence DESC
    LIMIT 1;
    IF FOUND THEN
        IF NEW.previous_operation_id IS DISTINCT FROM latest_operation_id
           OR NEW.previous_receipt_digest
                IS DISTINCT FROM latest_receipt_digest
           OR NEW.operation_sequence <= latest_operation_sequence
           OR NEW.applied_at <= latest_applied_at THEN
            RAISE EXCEPTION 'deployment receipt predecessor chain is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.previous_operation_id IS NOT NULL
          OR NEW.previous_receipt_digest IS NOT NULL THEN
        RAISE EXCEPTION 'first deployment cannot name a predecessor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN invalid_text_representation OR character_not_in_repertoire THEN
        RAISE EXCEPTION 'deployment canonical JSON cannot be decoded'
            USING ERRCODE = '23514';
END;
$function$;

DROP TRIGGER IF EXISTS deployment_history_validate_insert
    ON control_assurance_runtime.deployment_history;
CREATE TRIGGER deployment_history_validate_insert
BEFORE INSERT ON control_assurance_runtime.deployment_history
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.validate_deployment_history_insert();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.validate_control_run_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    request jsonb;
BEGIN
    request := convert_from(NEW.request_bytes, 'UTF8')::jsonb;
    IF request->>'tenant_id' <> NEW.tenant_id
       OR request->>'control_id' <> NEW.control_id
       OR request->>'deployment_operation_id'
            <> NEW.deployment_operation_id
       OR (request->>'deployment_operation_sequence')::bigint
            <> NEW.deployment_operation_sequence
       OR request->>'deployment_receipt_digest'
            <> NEW.deployment_receipt_digest
       OR request->>'revision_id' <> NEW.revision_id
       OR request->>'configuration_digest' <> NEW.configuration_digest
       OR request->>'control_profile_id' <> NEW.control_profile_id
       OR request->>'control_profile_digest'
            <> NEW.control_profile_digest
       OR (request->>'window_start')::timestamptz <> NEW.window_start
       OR (request->>'window_end')::timestamptz <> NEW.window_end
       OR (request->>'due_at')::timestamptz <> NEW.due_at THEN
        RAISE EXCEPTION 'control run request fields differ from columns'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_runtime.deployment_history AS history
        WHERE history.tenant_id = NEW.tenant_id
          AND history.control_id = NEW.control_id
          AND history.operation_id = NEW.deployment_operation_id
          AND history.operation_sequence =
                NEW.deployment_operation_sequence
          AND history.receipt_digest = NEW.deployment_receipt_digest
          AND history.revision_id = NEW.revision_id
          AND history.configuration_digest = NEW.configuration_digest
          AND history.control_profile_id = NEW.control_profile_id
          AND history.control_profile_digest = NEW.control_profile_digest
          AND history.enabled
          AND NEW.window_start >= history.applied_at
          AND NEW.window_end - NEW.window_start =
                make_interval(secs => history.window_seconds)
          AND NEW.due_at = NEW.window_end
                + make_interval(secs => history.collection_lag_seconds)
          AND mod(
                extract(epoch FROM NEW.window_end)::bigint,
                history.interval_seconds::bigint
              ) = 0
          AND NEW.due_at <= NEW.materialized_at
          AND NOT EXISTS (
                SELECT 1
                FROM control_assurance_runtime.deployment_history AS later
                WHERE later.tenant_id = history.tenant_id
                  AND later.control_id = history.control_id
                  AND later.operation_sequence >
                        history.operation_sequence
                  AND later.applied_at < NEW.window_end
          )
    ) THEN
        RAISE EXCEPTION 'control run is outside its enabled deployment window'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN invalid_text_representation OR character_not_in_repertoire THEN
        RAISE EXCEPTION 'control run canonical JSON cannot be decoded'
            USING ERRCODE = '23514';
END;
$function$;

DROP TRIGGER IF EXISTS control_run_validate_insert
    ON control_assurance_runtime.control_runs;
CREATE TRIGGER control_run_validate_insert
BEFORE INSERT ON control_assurance_runtime.control_runs
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.validate_control_run_insert();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.validate_control_run_claim_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_runtime.control_runs AS run
        WHERE run.tenant_id = NEW.tenant_id
          AND run.run_id = NEW.run_id
          AND run.state = 'leased'
          AND run.lease_fence = NEW.lease_fence
          AND run.attempt_count = NEW.attempt_count
          AND run.lease_owner = NEW.worker_id
          AND run.lease_token_digest = NEW.lease_token_digest
          AND run.leased_at = NEW.leased_at
          AND run.lease_expires_at = NEW.lease_expires_at
    ) THEN
        RAISE EXCEPTION 'control run claim differs from current lease'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS control_run_claim_validate_insert
    ON control_assurance_runtime.control_run_claims;
CREATE TRIGGER control_run_claim_validate_insert
BEFORE INSERT ON control_assurance_runtime.control_run_claims
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.validate_control_run_claim_insert();

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.validate_control_run_outcome_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    current_run control_assurance_runtime.control_runs%ROWTYPE;
    claim control_assurance_runtime.control_run_claims%ROWTYPE;
    closure jsonb;
BEGIN
    SELECT run.*
    INTO current_run
    FROM control_assurance_runtime.control_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.run_id = NEW.run_id
    FOR UPDATE;
    SELECT existing_claim.*
    INTO claim
    FROM control_assurance_runtime.control_run_claims AS existing_claim
    WHERE existing_claim.tenant_id = NEW.tenant_id
      AND existing_claim.run_id = NEW.run_id
      AND existing_claim.lease_fence = NEW.lease_fence;
    IF NOT FOUND
       OR current_run.state <> 'leased'
       OR current_run.lease_fence <> NEW.lease_fence
       OR NEW.recorded_at < current_run.window_end
       OR (
            NEW.outcome = 'succeeded'
            AND NEW.recorded_at >= claim.lease_expires_at
       ) THEN
        RAISE EXCEPTION 'control run outcome differs from current live lease'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'succeeded' THEN
        closure := convert_from(NEW.closure_bytes, 'UTF8')::jsonb;
        IF closure->>'run_id' <> NEW.run_id
           OR closure->>'tenant_id' <> NEW.tenant_id
           OR closure->>'control_id' <> current_run.control_id
           OR closure->>'deployment_operation_id'
                <> current_run.deployment_operation_id
           OR closure->>'deployment_receipt_digest'
                <> current_run.deployment_receipt_digest
           OR closure->>'configuration_digest'
                <> current_run.configuration_digest
           OR closure->>'control_profile_id'
                <> current_run.control_profile_id
           OR closure->>'control_profile_digest'
                <> current_run.control_profile_digest
           OR (closure->>'window_start')::timestamptz
                <> current_run.window_start
           OR (closure->>'window_end')::timestamptz
                <> current_run.window_end
           OR (closure->>'attempt_count')::integer
                <> current_run.attempt_count
           OR (closure->>'lease_fence')::bigint
                <> current_run.lease_fence
           OR closure->>'evidence_digest' <> NEW.evidence_digest
           OR closure->>'executor_receipt_digest'
                <> NEW.executor_receipt_digest
           OR (closure->>'completed_at')::timestamptz
                <> NEW.recorded_at THEN
            RAISE EXCEPTION 'control run closure fields differ from outcome'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN invalid_text_representation OR character_not_in_repertoire THEN
        RAISE EXCEPTION 'control run closure JSON cannot be decoded'
            USING ERRCODE = '23514';
END;
$function$;

DROP TRIGGER IF EXISTS control_run_outcome_validate_insert
    ON control_assurance_runtime.control_run_outcomes;
CREATE TRIGGER control_run_outcome_validate_insert
BEFORE INSERT ON control_assurance_runtime.control_run_outcomes
FOR EACH ROW EXECUTE FUNCTION
    control_assurance_runtime.validate_control_run_outcome_insert();

ALTER TABLE control_assurance_runtime.control_profiles
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_profiles
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.deployment_history
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.deployment_history
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.deployment_operation_fences
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.deployment_operation_fences
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.current_deployed_controls
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.current_deployed_controls
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_runs
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_runs
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_run_claims
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_run_claims
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_run_outcomes
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_runtime.control_run_outcomes
    FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS runtime_deployment_history_tenant
    ON control_assurance_runtime.deployment_history;
CREATE POLICY runtime_deployment_history_tenant
ON control_assurance_runtime.deployment_history
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_control_profiles_tenant
    ON control_assurance_runtime.control_profiles;
CREATE POLICY runtime_control_profiles_tenant
ON control_assurance_runtime.control_profiles
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_deployment_fences_tenant
    ON control_assurance_runtime.deployment_operation_fences;
CREATE POLICY runtime_deployment_fences_tenant
ON control_assurance_runtime.deployment_operation_fences
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_current_deployments_tenant
    ON control_assurance_runtime.current_deployed_controls;
CREATE POLICY runtime_current_deployments_tenant
ON control_assurance_runtime.current_deployed_controls
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_control_runs_tenant
    ON control_assurance_runtime.control_runs;
CREATE POLICY runtime_control_runs_tenant
ON control_assurance_runtime.control_runs
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_control_run_claims_tenant
    ON control_assurance_runtime.control_run_claims;
CREATE POLICY runtime_control_run_claims_tenant
ON control_assurance_runtime.control_run_claims
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

DROP POLICY IF EXISTS runtime_control_run_outcomes_tenant
    ON control_assurance_runtime.control_run_outcomes;
CREATE POLICY runtime_control_run_outcomes_tenant
ON control_assurance_runtime.control_run_outcomes
USING (
    tenant_id = control_assurance_runtime.session_tenant()
)
WITH CHECK (
    tenant_id = control_assurance_runtime.session_tenant()
);

CREATE OR REPLACE FUNCTION
    control_assurance_runtime.configure_login_role(
        p_tenant_id text,
        p_login_role name,
        p_principal_kind text
    )
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_runtime
AS $function$
DECLARE
    attributes pg_catalog.pg_roles%ROWTYPE;
BEGIN
    IF session_user <> current_user
       OR p_tenant_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_login_role::text !~ '^[a-z][a-z0-9_]{0,62}$'
       OR p_principal_kind NOT IN (
            'worker',
            'registrar',
            'reconciler',
            'auditor'
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.oid =
                'control_assurance_runtime.configure_login_role('
                'text,name,text)'::regprocedure
              AND routine.proowner =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname = 'control_assurance_runtime'
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
            'runtime role provisioning requires the exact migration owner'
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
       OR NOT control_assurance_runtime.foreign_store_isolated(
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
                    'control_assurance_runtime'::regnamespace
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee = attributes.oid
       )
    THEN
        RAISE EXCEPTION 'runtime login role is absent or privileged'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO control_assurance_runtime.role_entitlements (
        database_role,
        tenant_id,
        principal_kind
    )
    VALUES (p_login_role, p_tenant_id, p_principal_kind)
    ON CONFLICT (database_role) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_runtime.role_entitlements AS entitlement
        WHERE entitlement.database_role = p_login_role
          AND entitlement.tenant_id = p_tenant_id
          AND entitlement.principal_kind = p_principal_kind
    ) THEN
        RAISE EXCEPTION 'runtime login role is already bound'
            USING ERRCODE = '23505';
    END IF;

    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA '
        'control_assurance_runtime FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA '
        'control_assurance_runtime FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA '
        'control_assurance_runtime FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON SCHEMA '
        'control_assurance_runtime FROM %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT USAGE ON SCHEMA control_assurance_runtime TO %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION '
        'control_assurance_runtime.session_tenant(), '
        'control_assurance_runtime.session_principal_kind(), '
        'control_assurance_runtime.assert_session_principal('
        'text,text,text,text,text) TO %I',
        p_login_role
    );

    IF p_principal_kind = 'worker' THEN
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_runtime.schema_migrations, '
            'control_assurance_runtime.control_profiles, '
            'control_assurance_runtime.deployment_history, '
            'control_assurance_runtime.deployment_operation_fences, '
            'control_assurance_runtime.current_deployed_controls TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON '
            'control_assurance_runtime.control_runs, '
            'control_assurance_runtime.control_run_claims TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON '
            'control_assurance_runtime.control_run_outcomes TO %I',
            p_login_role
        );
    ELSIF p_principal_kind = 'registrar' THEN
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_runtime.schema_migrations TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON '
            'control_assurance_runtime.control_profiles TO %I',
            p_login_role
        );
    ELSIF p_principal_kind = 'reconciler' THEN
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_runtime.schema_migrations, '
            'control_assurance_runtime.control_profiles TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON '
            'control_assurance_runtime.deployment_history, '
            'control_assurance_runtime.deployment_operation_fences, '
            'control_assurance_runtime.current_deployed_controls TO %I',
            p_login_role
        );
    ELSE
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_runtime.schema_migrations, '
            'control_assurance_runtime.control_profiles, '
            'control_assurance_runtime.deployment_history, '
            'control_assurance_runtime.deployment_operation_fences, '
            'control_assurance_runtime.current_deployed_controls, '
            'control_assurance_runtime.control_runs, '
            'control_assurance_runtime.control_run_claims, '
            'control_assurance_runtime.control_run_outcomes TO %I',
            p_login_role
        );
    END IF;
    RETURN TRUE;
END;
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_runtime FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_runtime FROM PUBLIC;

INSERT INTO control_assurance_runtime.schema_migrations (version, description)
VALUES (
    1,
    'fenced deployment catalog, deterministic runs and immutable claim/outcome ledgers'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_runtime.schema_migrations (version, description)
VALUES (
    2,
    'immutable content-addressed control profile registry and exact run binding'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_runtime.schema_migrations (version, description)
VALUES (
    3,
    'session-user tenant entitlements and minimum-privilege principal admission'
)
ON CONFLICT (version) DO NOTHING;

DO $migration_check$
DECLARE
    installed_versions integer[];
BEGIN
    SELECT array_agg(version ORDER BY version)
    INTO installed_versions
    FROM control_assurance_runtime.schema_migrations;
    IF installed_versions IS DISTINCT FROM ARRAY[1, 2, 3]::integer[] THEN
        RAISE EXCEPTION
            'unsupported runtime schema lineage: %',
            installed_versions;
    END IF;
END;
$migration_check$;

COMMIT;
