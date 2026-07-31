-- Control Assurance PAM lifecycle journals, migrations 1 through 3.
--
-- Install this file with a migration owner before starting any broker.  PAM
-- runtime roles should receive only SELECT/INSERT and the lifecycle UPDATE
-- columns they need.  The Python journals never create or alter schema.
-- journal_namespace_digest is a stable, secret-free hash of one logical
-- broker scope; all replicas share it, while independently recovered scopes
-- must use different values.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE SCHEMA IF NOT EXISTS control_assurance_pam;

REVOKE ALL ON SCHEMA control_assurance_pam FROM PUBLIC;

CREATE TABLE IF NOT EXISTS control_assurance_pam.schema_migrations (
    version integer PRIMARY KEY CHECK (version >= 1),
    description text NOT NULL CHECK (length(description) BETWEEN 1 AND 255),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp()
);

-- Migration 3: migration-owner provisioned login and namespace boundaries.
-- Legacy journal rows carry only a namespace digest, so an explicit immutable
-- namespace-to-tenant registry is the only truthful upgrade path. Unmapped
-- namespaces fail closed.
CREATE TABLE IF NOT EXISTS control_assurance_pam.role_entitlements (
    database_role name PRIMARY KEY,
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    principal_kind text NOT NULL
        CHECK (principal_kind IN ('broker', 'recovery', 'auditor')),
    provisioned_at timestamptz(0) NOT NULL
        DEFAULT transaction_timestamp(),
    provisioned_by name NOT NULL DEFAULT session_user
);

CREATE TABLE IF NOT EXISTS control_assurance_pam.journal_namespaces (
    journal_namespace_digest text PRIMARY KEY
        CHECK (journal_namespace_digest ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    purpose text NOT NULL
        CHECK (
            length(purpose) BETWEEN 1 AND 128
            AND purpose ~ '^[a-z][a-z0-9._-]{0,127}$'
        ),
    provisioned_at timestamptz(0) NOT NULL
        DEFAULT transaction_timestamp(),
    provisioned_by name NOT NULL DEFAULT session_user
);

REVOKE ALL ON control_assurance_pam.role_entitlements FROM PUBLIC;
REVOKE ALL ON control_assurance_pam.journal_namespaces FROM PUBLIC;

CREATE OR REPLACE FUNCTION control_assurance_pam.session_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
    SELECT entitlement.tenant_id
    FROM control_assurance_pam.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.session_principal_kind()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
    SELECT entitlement.principal_kind
    FROM control_assurance_pam.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.foreign_store_isolated(p_role name)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
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
            'control_assurance_execution'
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
    control_assurance_pam.session_owns_namespace(namespace_digest text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM control_assurance_pam.journal_namespaces AS namespace
        JOIN control_assurance_pam.role_entitlements AS entitlement
          ON entitlement.database_role = session_user::name
         AND entitlement.tenant_id = namespace.tenant_id
        WHERE namespace.journal_namespace_digest = namespace_digest
    )
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.assert_session_principal(
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
SET search_path = pg_catalog, control_assurance_pam
AS $function$
DECLARE
    entitlement control_assurance_pam.role_entitlements%ROWTYPE;
    role_record pg_catalog.pg_roles%ROWTYPE;
    relation_record record;
    procedure_record record;
    privilege_name text;
    privilege_present boolean;
    privilege_allowed boolean;
BEGIN
    IF expected_tenant !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR expected_database_role !~ '^[a-z][a-z0-9_]{0,62}$'
       OR expected_principal_kind NOT IN ('broker', 'recovery', 'auditor')
       OR caller_current_role IS DISTINCT FROM expected_database_role
       OR caller_session_role IS DISTINCT FROM expected_database_role
       OR caller_current_role IS DISTINCT FROM caller_session_role
       OR caller_session_role IS DISTINCT FROM session_user::text
    THEN
        RAISE EXCEPTION 'PAM database principal identity mismatch'
            USING ERRCODE = '42501';
    END IF;

    SELECT *
    INTO entitlement
    FROM control_assurance_pam.role_entitlements
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
       OR NOT control_assurance_pam.foreign_store_isolated(
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
            'control_assurance_pam',
            'USAGE'
       )
       OR pg_catalog.has_schema_privilege(
            session_user,
            'control_assurance_pam',
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
            WHERE namespace.nspname = 'control_assurance_pam'
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
                    'control_assurance_pam'::regnamespace
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
                    'control_assurance_pam'::regnamespace
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
                    'control_assurance_pam'::regnamespace
              AND (
                  acl.grantee = 0
                  OR (
                      acl.grantee = role_record.oid
                      AND acl.is_grantable
                  )
              )
       )
    THEN
        RAISE EXCEPTION 'PAM database principal is over-privileged'
            USING ERRCODE = '42501';
    END IF;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_pam'::regnamespace
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
                relation_record.relname NOT IN (
                    'role_entitlements',
                    'journal_namespaces'
                )
                AND CASE expected_principal_kind
                WHEN 'broker' THEN
                    (
                        relation_record.relname = 'schema_migrations'
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname IN (
                            'elastic_jit_leases',
                            'defender_token_lifecycle',
                            'execution_bindings',
                            'lifecycle_records'
                        )
                        AND privilege_name IN (
                            'SELECT',
                            'INSERT',
                            'UPDATE'
                        )
                    )
                    OR (
                        relation_record.relname IN (
                            'execution_binding_scopes',
                            'issuance_fences'
                        )
                        AND privilege_name IN ('SELECT', 'INSERT')
                    )
                WHEN 'recovery' THEN
                    (
                        relation_record.relname = 'schema_migrations'
                        AND privilege_name = 'SELECT'
                    )
                    OR (
                        relation_record.relname IN (
                            'elastic_jit_leases',
                            'defender_token_lifecycle',
                            'lifecycle_records'
                        )
                        AND privilege_name IN ('SELECT', 'UPDATE')
                    )
                    OR (
                        relation_record.relname = 'execution_bindings'
                        AND privilege_name IN (
                            'SELECT',
                            'INSERT',
                            'UPDATE'
                        )
                    )
                    OR (
                        relation_record.relname IN (
                            'execution_binding_scopes',
                            'issuance_fences'
                        )
                        AND privilege_name IN ('SELECT', 'INSERT')
                    )
                WHEN 'auditor' THEN
                    relation_record.relname IN (
                        'schema_migrations',
                        'elastic_jit_leases',
                        'defender_token_lifecycle',
                        'execution_bindings',
                        'execution_binding_scopes',
                        'lifecycle_records',
                        'issuance_fences'
                    )
                    AND privilege_name = 'SELECT'
                    ELSE FALSE
                END;
            IF privilege_present IS DISTINCT FROM privilege_allowed THEN
                RAISE EXCEPTION
                    'PAM database principal table privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR relation_record IN
        SELECT relation.oid, relation.relname
        FROM pg_catalog.pg_class AS relation
        WHERE relation.relnamespace =
                'control_assurance_pam'::regnamespace
          AND relation.relkind = 'S'
    LOOP
        FOREACH privilege_name IN ARRAY ARRAY[
            'USAGE',
            'SELECT',
            'UPDATE'
        ]
        LOOP
            privilege_present := pg_catalog.has_sequence_privilege(
                session_user,
                relation_record.oid,
                privilege_name
            );
            privilege_allowed :=
                relation_record.relname = 'lifecycle_sequence'
                AND expected_principal_kind IN ('broker', 'recovery')
                AND privilege_name = 'USAGE';
            IF privilege_present IS DISTINCT FROM privilege_allowed THEN
                RAISE EXCEPTION
                    'PAM database principal sequence privilege matrix mismatch'
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
    END LOOP;

    FOR procedure_record IN
        SELECT procedure.oid, procedure.proname
        FROM pg_catalog.pg_proc AS procedure
        WHERE procedure.pronamespace =
                'control_assurance_pam'::regnamespace
    LOOP
        privilege_present := pg_catalog.has_function_privilege(
            session_user,
            procedure_record.oid,
            'EXECUTE'
        );
        privilege_allowed := procedure_record.oid = ANY(ARRAY[
            'control_assurance_pam.session_tenant()'
                ::regprocedure::oid,
            'control_assurance_pam.session_principal_kind()'
                ::regprocedure::oid,
            'control_assurance_pam.session_owns_namespace(text)'
                ::regprocedure::oid,
            'control_assurance_pam.assert_session_principal('
                'text,text,text,text,text)'::regprocedure::oid,
            'control_assurance_pam.assert_journal_namespace('
                'text,text,text)'::regprocedure::oid
        ]);
        IF privilege_present IS DISTINCT FROM privilege_allowed
        THEN
            RAISE EXCEPTION
                'PAM database principal routine privilege matrix mismatch'
                USING ERRCODE = '42501';
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.assert_journal_namespace(
        namespace_digest text,
        caller_current_role text,
        caller_session_role text
    )
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
DECLARE
    entitled_tenant text;
    mapped_kind text;
BEGIN
    SELECT entitlement.tenant_id, entitlement.principal_kind
    INTO entitled_tenant, mapped_kind
    FROM control_assurance_pam.role_entitlements AS entitlement
    WHERE entitlement.database_role = session_user::name;
    IF entitled_tenant IS NULL
       OR mapped_kind IS NULL
       OR NOT control_assurance_pam.session_owns_namespace(
            namespace_digest
       )
    THEN
        RAISE EXCEPTION 'PAM journal namespace is not owned by this principal'
            USING ERRCODE = '42501';
    END IF;
    RETURN control_assurance_pam.assert_session_principal(
        entitled_tenant,
        session_user::text,
        mapped_kind,
        caller_current_role,
        caller_session_role
    );
END;
$function$;

CREATE TABLE IF NOT EXISTS control_assurance_pam.elastic_jit_leases (
    journal_namespace_digest text NOT NULL
        CHECK (journal_namespace_digest ~ '^sha256:[a-f0-9]{64}$'),
    lease_id text NOT NULL
        CHECK (lease_id ~ '^[a-f0-9]{64}$'),
    key_name text NOT NULL
        CHECK (key_name ~ '^control-assurance-[a-f0-9]{32}$'),
    index_alias text NOT NULL
        CHECK (
            index_alias
            ~ '^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$'
        ),
    request_digest text NOT NULL
        CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    endpoint_origin_digest text NOT NULL
        CHECK (endpoint_origin_digest ~ '^sha256:[a-f0-9]{64}$'),
    role_descriptor_digest text NOT NULL
        CHECK (role_descriptor_digest ~ '^sha256:[a-f0-9]{64}$'),
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 120 AND 3600),
    state text NOT NULL
        CHECK (state IN ('prepared', 'active', 'revoke-pending', 'revoked')),
    key_id text
        CHECK (
            key_id IS NULL
            OR (
                length(key_id) BETWEEN 1 AND 512
                AND key_id ~ '^[A-Za-z0-9_-]+$'
            )
        ),
    expiration_epoch_millis bigint
        CHECK (
            expiration_epoch_millis IS NULL
            OR expiration_epoch_millis >= 0
        ),
    created_epoch_millis bigint NOT NULL CHECK (created_epoch_millis >= 0),
    activated_epoch_millis bigint
        CHECK (
            activated_epoch_millis IS NULL
            OR activated_epoch_millis >= created_epoch_millis
        ),
    revoked_epoch_millis bigint
        CHECK (
            revoked_epoch_millis IS NULL
            OR revoked_epoch_millis >= created_epoch_millis
        ),
    revoke_attempts integer NOT NULL DEFAULT 0 CHECK (revoke_attempts >= 0),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    last_error text
        CHECK (
            last_error IS NULL
            OR (
                length(last_error) BETWEEN 1 AND 512
                AND last_error !~ '[[:cntrl:]]'
            )
        ),
    PRIMARY KEY (journal_namespace_digest, lease_id),
    UNIQUE (journal_namespace_digest, key_name),
    CONSTRAINT elastic_jit_lease_expiration_after_activation CHECK (
        expiration_epoch_millis IS NULL
        OR (
            activated_epoch_millis IS NOT NULL
            AND expiration_epoch_millis > activated_epoch_millis
        )
    ),
    CONSTRAINT elastic_jit_lease_revocation_after_activation CHECK (
        activated_epoch_millis IS NULL
        OR revoked_epoch_millis IS NULL
        OR revoked_epoch_millis >= activated_epoch_millis
    ),
    CONSTRAINT elastic_jit_lease_state_shape CHECK (
        (
            state = 'prepared'
            AND revision = 0
            AND key_id IS NULL
            AND expiration_epoch_millis IS NULL
            AND activated_epoch_millis IS NULL
            AND revoked_epoch_millis IS NULL
            AND revoke_attempts = 0
            AND last_error IS NULL
        )
        OR (
            state = 'active'
            AND revision = 1
            AND key_id IS NOT NULL
            AND expiration_epoch_millis IS NOT NULL
            AND activated_epoch_millis IS NOT NULL
            AND revoked_epoch_millis IS NULL
            AND revoke_attempts = 0
            AND last_error IS NULL
        )
        OR (
            state = 'revoke-pending'
            AND revision >= 1
            AND revoked_epoch_millis IS NULL
            AND revoke_attempts >= 1
            AND (
                (
                    key_id IS NULL
                    AND expiration_epoch_millis IS NULL
                    AND activated_epoch_millis IS NULL
                )
                OR (
                    key_id IS NOT NULL
                    AND expiration_epoch_millis IS NOT NULL
                    AND activated_epoch_millis IS NOT NULL
                )
            )
        )
        OR (
            state = 'revoked'
            AND revision >= 2
            AND revoked_epoch_millis IS NOT NULL
            AND revoke_attempts >= 1
            AND last_error IS NULL
            AND (
                (
                    key_id IS NULL
                    AND expiration_epoch_millis IS NULL
                    AND activated_epoch_millis IS NULL
                )
                OR (
                    key_id IS NOT NULL
                    AND expiration_epoch_millis IS NOT NULL
                    AND activated_epoch_millis IS NOT NULL
                )
            )
        )
    )
);

CREATE INDEX IF NOT EXISTS elastic_jit_leases_recovery
    ON control_assurance_pam.elastic_jit_leases
        (journal_namespace_digest, created_epoch_millis, lease_id)
    WHERE state != 'revoked';

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_elastic_lease_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.journal_namespace_digest,
        NEW.lease_id,
        NEW.key_name,
        NEW.index_alias,
        NEW.request_digest,
        NEW.endpoint_origin_digest,
        NEW.role_descriptor_digest,
        NEW.ttl_seconds,
        NEW.created_epoch_millis
    ) IS DISTINCT FROM ROW(
        OLD.journal_namespace_digest,
        OLD.lease_id,
        OLD.key_name,
        OLD.index_alias,
        OLD.request_digest,
        OLD.endpoint_origin_digest,
        OLD.role_descriptor_digest,
        OLD.ttl_seconds,
        OLD.created_epoch_millis
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'immutable Elastic PAM lease identity';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS elastic_jit_lease_identity_immutable
    ON control_assurance_pam.elastic_jit_leases;
CREATE TRIGGER elastic_jit_lease_identity_immutable
BEFORE UPDATE ON control_assurance_pam.elastic_jit_leases
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_elastic_lease_identity_change();

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_elastic_lease_invalid_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT (
        (
            OLD.state = 'prepared'
            AND NEW.state = 'active'
            AND NEW.revision = OLD.revision + 1
            AND NEW.revoke_attempts = OLD.revoke_attempts
            AND NEW.revoked_epoch_millis
                IS NOT DISTINCT FROM OLD.revoked_epoch_millis
            AND NEW.last_error IS NULL
        )
        OR (
            OLD.state IN ('prepared', 'active', 'revoke-pending')
            AND NEW.state = 'revoke-pending'
            AND NEW.revision = OLD.revision + 1
            AND NEW.revoke_attempts = OLD.revoke_attempts + 1
            AND NEW.key_id IS NOT DISTINCT FROM OLD.key_id
            AND NEW.expiration_epoch_millis
                IS NOT DISTINCT FROM OLD.expiration_epoch_millis
            AND NEW.activated_epoch_millis
                IS NOT DISTINCT FROM OLD.activated_epoch_millis
            AND NEW.revoked_epoch_millis
                IS NOT DISTINCT FROM OLD.revoked_epoch_millis
        )
        OR (
            OLD.state = 'revoke-pending'
            AND NEW.state = 'revoked'
            AND NEW.revision = OLD.revision + 1
            AND NEW.revoke_attempts = OLD.revoke_attempts
            AND NEW.key_id IS NOT DISTINCT FROM OLD.key_id
            AND NEW.expiration_epoch_millis
                IS NOT DISTINCT FROM OLD.expiration_epoch_millis
            AND NEW.activated_epoch_millis
                IS NOT DISTINCT FROM OLD.activated_epoch_millis
            AND NEW.revoked_epoch_millis IS NOT NULL
            AND NEW.last_error IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'invalid Elastic PAM lease state transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS elastic_jit_lease_transition_guard
    ON control_assurance_pam.elastic_jit_leases;
CREATE TRIGGER elastic_jit_lease_transition_guard
BEFORE UPDATE ON control_assurance_pam.elastic_jit_leases
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_elastic_lease_invalid_transition();

CREATE TABLE IF NOT EXISTS control_assurance_pam.defender_token_lifecycle (
    journal_namespace_digest text NOT NULL
        CHECK (journal_namespace_digest ~ '^sha256:[a-f0-9]{64}$'),
    acquisition_id text NOT NULL
        CHECK (acquisition_id ~ '^[a-f0-9]{64}$'),
    request_digest text NOT NULL
        CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    token_endpoint_digest text NOT NULL
        CHECK (token_endpoint_digest ~ '^sha256:[a-f0-9]{64}$'),
    graph_origin_digest text NOT NULL
        CHECK (graph_origin_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL
        CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    credential_mode text NOT NULL
        CHECK (credential_mode IN ('certificate-ps256', 'federated-rs256')),
    credential_reference_digest text NOT NULL
        CHECK (credential_reference_digest ~ '^sha256:[a-f0-9]{64}$'),
    token_request_profile_digest text NOT NULL
        CHECK (token_request_profile_digest ~ '^sha256:[a-f0-9]{64}$'),
    state text NOT NULL
        CHECK (state IN ('prepared', 'issued', 'closed', 'uncertain')),
    closure text
        CHECK (
            closure IS NULL
            OR closure IN (
                'capture-completed-token-release-only',
                'capture-failed-token-release-only',
                'token-request-rejected-no-token',
                'token-request-ambiguous',
                'abandoned-after-crash'
            )
        ),
    created_epoch_millis bigint NOT NULL CHECK (created_epoch_millis >= 0),
    issued_epoch_millis bigint
        CHECK (
            issued_epoch_millis IS NULL
            OR issued_epoch_millis >= created_epoch_millis
        ),
    closed_epoch_millis bigint
        CHECK (
            closed_epoch_millis IS NULL
            OR closed_epoch_millis >= created_epoch_millis
        ),
    access_token_expires_epoch_millis bigint
        CHECK (
            access_token_expires_epoch_millis IS NULL
            OR (
                issued_epoch_millis IS NOT NULL
                AND access_token_expires_epoch_millis > issued_epoch_millis
            )
        ),
    conservative_exposure_end_epoch_millis bigint NOT NULL
        CHECK (
            conservative_exposure_end_epoch_millis >= created_epoch_millis
        ),
    assertion_id_digest text
        CHECK (
            assertion_id_digest IS NULL
            OR assertion_id_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    response_request_id_digest text
        CHECK (
            response_request_id_digest IS NULL
            OR response_request_id_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    last_error text
        CHECK (
            last_error IS NULL
            OR (
                length(last_error) BETWEEN 1 AND 384
                AND last_error !~ '[[:cntrl:]]'
            )
        ),
    PRIMARY KEY (journal_namespace_digest, acquisition_id),
    CONSTRAINT defender_token_expiry_within_conservative_bound CHECK (
        access_token_expires_epoch_millis IS NULL
        OR (
            access_token_expires_epoch_millis
                <= conservative_exposure_end_epoch_millis
            AND access_token_expires_epoch_millis - issued_epoch_millis
                BETWEEN 60000 AND 3900000
        )
    ),
    CONSTRAINT defender_token_lifecycle_state_shape CHECK (
        (
            state = 'prepared'
            AND revision = 0
            AND closure IS NULL
            AND issued_epoch_millis IS NULL
            AND closed_epoch_millis IS NULL
            AND access_token_expires_epoch_millis IS NULL
            AND assertion_id_digest IS NULL
            AND response_request_id_digest IS NULL
            AND last_error IS NULL
        )
        OR (
            state = 'issued'
            AND revision = 1
            AND closure IS NULL
            AND issued_epoch_millis IS NOT NULL
            AND closed_epoch_millis IS NULL
            AND access_token_expires_epoch_millis IS NOT NULL
            AND assertion_id_digest IS NOT NULL
            AND last_error IS NULL
        )
        OR (
            state = 'uncertain'
            AND revision = 1
            AND closure = 'token-request-ambiguous'
            AND issued_epoch_millis IS NULL
            AND closed_epoch_millis IS NOT NULL
            AND access_token_expires_epoch_millis IS NULL
            AND assertion_id_digest IS NULL
            AND response_request_id_digest IS NULL
            AND last_error IS NOT NULL
        )
        OR (
            state = 'closed'
            AND closed_epoch_millis IS NOT NULL
            AND (
                (
                    revision = 1
                    AND closure = 'token-request-rejected-no-token'
                    AND issued_epoch_millis IS NULL
                    AND access_token_expires_epoch_millis IS NULL
                    AND assertion_id_digest IS NULL
                    AND response_request_id_digest IS NULL
                    AND last_error IS NOT NULL
                )
                OR (
                    revision = 2
                    AND closure IN (
                        'capture-completed-token-release-only',
                        'capture-failed-token-release-only',
                        'abandoned-after-crash'
                    )
                    AND issued_epoch_millis IS NOT NULL
                    AND access_token_expires_epoch_millis IS NOT NULL
                    AND assertion_id_digest IS NOT NULL
                    AND (
                        (
                            closure = 'capture-completed-token-release-only'
                            AND last_error IS NULL
                        )
                        OR (
                            closure != 'capture-completed-token-release-only'
                            AND last_error IS NOT NULL
                        )
                    )
                )
            )
        )
    )
);

CREATE INDEX IF NOT EXISTS defender_token_lifecycle_recovery
    ON control_assurance_pam.defender_token_lifecycle
        (journal_namespace_digest, created_epoch_millis, acquisition_id)
    WHERE state IN ('prepared', 'issued');

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_defender_token_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.journal_namespace_digest,
        NEW.acquisition_id,
        NEW.request_digest,
        NEW.token_endpoint_digest,
        NEW.graph_origin_digest,
        NEW.scope_digest,
        NEW.credential_mode,
        NEW.credential_reference_digest,
        NEW.token_request_profile_digest,
        NEW.created_epoch_millis,
        NEW.conservative_exposure_end_epoch_millis
    ) IS DISTINCT FROM ROW(
        OLD.journal_namespace_digest,
        OLD.acquisition_id,
        OLD.request_digest,
        OLD.token_endpoint_digest,
        OLD.graph_origin_digest,
        OLD.scope_digest,
        OLD.credential_mode,
        OLD.credential_reference_digest,
        OLD.token_request_profile_digest,
        OLD.created_epoch_millis,
        OLD.conservative_exposure_end_epoch_millis
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'immutable Defender PAM token identity';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS defender_token_identity_immutable
    ON control_assurance_pam.defender_token_lifecycle;
CREATE TRIGGER defender_token_identity_immutable
BEFORE UPDATE ON control_assurance_pam.defender_token_lifecycle
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_defender_token_identity_change();

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_defender_token_invalid_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT (
        (
            OLD.state = 'prepared'
            AND NEW.state IN ('issued', 'closed', 'uncertain')
            AND NEW.revision = OLD.revision + 1
        )
        OR (
            OLD.state = 'issued'
            AND NEW.state = 'closed'
            AND NEW.revision = OLD.revision + 1
            AND NEW.issued_epoch_millis
                IS NOT DISTINCT FROM OLD.issued_epoch_millis
            AND NEW.access_token_expires_epoch_millis
                IS NOT DISTINCT FROM OLD.access_token_expires_epoch_millis
            AND NEW.assertion_id_digest
                IS NOT DISTINCT FROM OLD.assertion_id_digest
            AND NEW.response_request_id_digest
                IS NOT DISTINCT FROM OLD.response_request_id_digest
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'invalid Defender PAM token state transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS defender_token_transition_guard
    ON control_assurance_pam.defender_token_lifecycle;
CREATE TRIGGER defender_token_transition_guard
BEFORE UPDATE ON control_assurance_pam.defender_token_lifecycle
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_defender_token_invalid_transition();

INSERT INTO control_assurance_pam.schema_migrations (version, description)
VALUES (1, 'Elastic JIT and Defender workload-token PAM lifecycle journals')
ON CONFLICT (version) DO NOTHING;

-- Migration 2: plan-bound lifecycle sequencing and recovery issuance fences.

CREATE TABLE IF NOT EXISTS control_assurance_pam.execution_bindings (
    journal_namespace_digest text NOT NULL
        CHECK (journal_namespace_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_binding_digest text NOT NULL
        CHECK (execution_binding_digest ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    run_id text NOT NULL
        CHECK (run_id ~ '^sha256:[a-f0-9]{64}$'),
    execution_plan_digest text NOT NULL
        CHECK (execution_plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_identity_digest text NOT NULL
        CHECK (execution_identity_digest ~ '^sha256:[a-f0-9]{64}$'),
    lease_fence bigint NOT NULL CHECK (lease_fence BETWEEN 1 AND 9007199254740991),
    lease_expires_at_epoch_millis bigint NOT NULL
        CHECK (lease_expires_at_epoch_millis >= 0),
    pam_scope_digest text NOT NULL
        CHECK (pam_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    predecessor_binding_digest text
        CHECK (
            predecessor_binding_digest IS NULL
            OR predecessor_binding_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    state text NOT NULL CHECK (state IN ('active', 'fenced')),
    registered_at_epoch_millis bigint NOT NULL
        CHECK (registered_at_epoch_millis >= 0),
    fenced_at_epoch_millis bigint
        CHECK (
            fenced_at_epoch_millis IS NULL
            OR fenced_at_epoch_millis >= registered_at_epoch_millis
        ),
    PRIMARY KEY (journal_namespace_digest, execution_binding_digest),
    UNIQUE (
        journal_namespace_digest,
        tenant_id,
        run_id,
        lease_fence
    ),
    UNIQUE (
        journal_namespace_digest,
        execution_binding_digest,
        tenant_id,
        run_id,
        execution_plan_digest,
        execution_identity_digest,
        lease_fence,
        pam_scope_digest
    ),
    CONSTRAINT execution_binding_state_shape CHECK (
        (
            state = 'active'
            AND fenced_at_epoch_millis IS NULL
        )
        OR (
            state = 'fenced'
            AND fenced_at_epoch_millis IS NOT NULL
        )
    ),
    CONSTRAINT execution_binding_registration_precedes_expiry CHECK (
        registered_at_epoch_millis < lease_expires_at_epoch_millis
    ),
    CONSTRAINT execution_binding_predecessor_fk FOREIGN KEY (
        journal_namespace_digest,
        predecessor_binding_digest
    ) REFERENCES control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        execution_binding_digest
    ) DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX IF NOT EXISTS execution_bindings_one_active_run
    ON control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        tenant_id,
        run_id
    )
    WHERE state = 'active';

CREATE TABLE IF NOT EXISTS control_assurance_pam.execution_binding_scopes (
    journal_namespace_digest text NOT NULL,
    execution_binding_digest text NOT NULL,
    authority_class text NOT NULL
        CHECK (authority_class IN ('custody', 'signing', 'source')),
    connector_id text NOT NULL
        CHECK (connector_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    connector_request_digest text NOT NULL
        CHECK (connector_request_digest ~ '^sha256:[a-f0-9]{64}$'),
    PRIMARY KEY (
        journal_namespace_digest,
        execution_binding_digest,
        authority_class,
        connector_id,
        connector_request_digest
    ),
    UNIQUE (
        journal_namespace_digest,
        execution_binding_digest,
        authority_class
    ),
    CONSTRAINT execution_binding_scope_binding_fk FOREIGN KEY (
        journal_namespace_digest,
        execution_binding_digest
    ) REFERENCES control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        execution_binding_digest
    )
);

CREATE SEQUENCE IF NOT EXISTS control_assurance_pam.lifecycle_sequence
    AS bigint
    MINVALUE 1
    MAXVALUE 9007199254740991
    NO CYCLE;

ALTER SEQUENCE control_assurance_pam.lifecycle_sequence
    MAXVALUE 9007199254740991
    NO CYCLE;

CREATE TABLE IF NOT EXISTS control_assurance_pam.lifecycle_records (
    lifecycle_sequence bigint PRIMARY KEY
        DEFAULT nextval('control_assurance_pam.lifecycle_sequence'),
    lifecycle_record_id text NOT NULL
        CHECK (
            lifecycle_record_id
            ~ '^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$'
        ),
    journal_namespace_digest text NOT NULL
        CHECK (journal_namespace_digest ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    run_id text NOT NULL
        CHECK (run_id ~ '^sha256:[a-f0-9]{64}$'),
    execution_plan_digest text NOT NULL
        CHECK (execution_plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_identity_digest text NOT NULL
        CHECK (execution_identity_digest ~ '^sha256:[a-f0-9]{64}$'),
    lease_fence bigint NOT NULL CHECK (lease_fence BETWEEN 1 AND 9007199254740991),
    pam_scope_digest text NOT NULL
        CHECK (pam_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_binding_digest text NOT NULL
        CHECK (execution_binding_digest ~ '^sha256:[a-f0-9]{64}$'),
    authority_class text NOT NULL
        CHECK (authority_class IN ('custody', 'signing', 'source')),
    connector_id text NOT NULL
        CHECK (connector_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    connector_request_digest text NOT NULL
        CHECK (connector_request_digest ~ '^sha256:[a-f0-9]{64}$'),
    credential_reference_digest text
        CHECK (
            credential_reference_digest IS NULL
            OR credential_reference_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    state text NOT NULL
        CHECK (
            state IN (
                'prepared',
                'issued',
                'uncertain',
                'never-issued',
                'expired',
                'revoked'
            )
        ),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_epoch_millis bigint NOT NULL CHECK (created_epoch_millis >= 0),
    issued_epoch_millis bigint
        CHECK (
            issued_epoch_millis IS NULL
            OR issued_epoch_millis >= created_epoch_millis
        ),
    expires_epoch_millis bigint
        CHECK (
            expires_epoch_millis IS NULL
            OR (
                issued_epoch_millis IS NOT NULL
                AND expires_epoch_millis > issued_epoch_millis
            )
        ),
    settled_epoch_millis bigint
        CHECK (
            settled_epoch_millis IS NULL
            OR settled_epoch_millis >= created_epoch_millis
        ),
    maximum_residual_exposure_ends_epoch_millis bigint NOT NULL
        CHECK (
            maximum_residual_exposure_ends_epoch_millis
            >= created_epoch_millis
        ),
    UNIQUE (journal_namespace_digest, lifecycle_record_id),
    CONSTRAINT lifecycle_binding_fk FOREIGN KEY (
        journal_namespace_digest,
        execution_binding_digest,
        tenant_id,
        run_id,
        execution_plan_digest,
        execution_identity_digest,
        lease_fence,
        pam_scope_digest
    ) REFERENCES control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        execution_binding_digest,
        tenant_id,
        run_id,
        execution_plan_digest,
        execution_identity_digest,
        lease_fence,
        pam_scope_digest
    ),
    CONSTRAINT lifecycle_scope_fk FOREIGN KEY (
        journal_namespace_digest,
        execution_binding_digest,
        authority_class,
        connector_id,
        connector_request_digest
    ) REFERENCES control_assurance_pam.execution_binding_scopes (
        journal_namespace_digest,
        execution_binding_digest,
        authority_class,
        connector_id,
        connector_request_digest
    ),
    CONSTRAINT lifecycle_state_shape CHECK (
        (
            state = 'prepared'
            AND revision = 0
            AND issued_epoch_millis IS NULL
            AND expires_epoch_millis IS NULL
            AND settled_epoch_millis IS NULL
        )
        OR (
            state = 'issued'
            AND revision >= 1
            AND issued_epoch_millis IS NOT NULL
            AND expires_epoch_millis IS NOT NULL
            AND settled_epoch_millis IS NULL
            AND expires_epoch_millis
                <= maximum_residual_exposure_ends_epoch_millis
        )
        OR (
            state = 'uncertain'
            AND revision >= 1
            AND settled_epoch_millis IS NULL
        )
        OR (
            state = 'never-issued'
            AND revision >= 1
            AND issued_epoch_millis IS NULL
            AND expires_epoch_millis IS NULL
            AND settled_epoch_millis
                >= maximum_residual_exposure_ends_epoch_millis
        )
        OR (
            state = 'expired'
            AND revision >= 1
            AND issued_epoch_millis IS NOT NULL
            AND expires_epoch_millis IS NOT NULL
            AND expires_epoch_millis
                <= maximum_residual_exposure_ends_epoch_millis
            AND settled_epoch_millis
                >= maximum_residual_exposure_ends_epoch_millis
        )
        OR (
            state = 'revoked'
            AND revision >= 1
            AND settled_epoch_millis
                >= maximum_residual_exposure_ends_epoch_millis
        )
    )
);

CREATE INDEX IF NOT EXISTS lifecycle_records_binding_snapshot
    ON control_assurance_pam.lifecycle_records (
        journal_namespace_digest,
        execution_binding_digest,
        lifecycle_sequence
    );

CREATE TABLE IF NOT EXISTS control_assurance_pam.issuance_fences (
    journal_namespace_digest text NOT NULL,
    operation_digest text NOT NULL
        CHECK (operation_digest ~ '^sha256:[a-f0-9]{64}$'),
    fenced_execution_binding_digest text NOT NULL,
    successor_execution_binding_digest text NOT NULL,
    pam_scope_digest text NOT NULL
        CHECK (pam_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_high_watermark bigint NOT NULL
        CHECK (snapshot_high_watermark BETWEEN 1 AND 9007199254740991),
    effective_at_epoch_millis bigint NOT NULL
        CHECK (effective_at_epoch_millis >= 0),
    valid_until_epoch_millis bigint NOT NULL
        CHECK (valid_until_epoch_millis > effective_at_epoch_millis),
    PRIMARY KEY (
        journal_namespace_digest,
        fenced_execution_binding_digest
    ),
    UNIQUE (journal_namespace_digest, operation_digest),
    UNIQUE (
        journal_namespace_digest,
        successor_execution_binding_digest
    ),
    CONSTRAINT issuance_fence_old_binding_fk FOREIGN KEY (
        journal_namespace_digest,
        fenced_execution_binding_digest
    ) REFERENCES control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        execution_binding_digest
    ),
    CONSTRAINT issuance_fence_successor_binding_fk FOREIGN KEY (
        journal_namespace_digest,
        successor_execution_binding_digest
    ) REFERENCES control_assurance_pam.execution_bindings (
        journal_namespace_digest,
        execution_binding_digest
    )
);

CREATE OR REPLACE FUNCTION
    control_assurance_pam.guard_execution_binding_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (
            NEW.state != 'active'
            OR NEW.fenced_at_epoch_millis IS NOT NULL
            OR NEW.registered_at_epoch_millis
                >= NEW.lease_expires_at_epoch_millis
            OR NEW.lease_expires_at_epoch_millis
                <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23000',
                MESSAGE = 'expired or invalid PAM execution binding';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'PAM execution bindings are append-only';
    END IF;
    IF NOT (
        OLD.state = 'active'
        AND NEW.state = 'fenced'
        AND OLD.journal_namespace_digest = NEW.journal_namespace_digest
        AND OLD.execution_binding_digest = NEW.execution_binding_digest
        AND OLD.tenant_id = NEW.tenant_id
        AND OLD.run_id = NEW.run_id
        AND OLD.execution_plan_digest = NEW.execution_plan_digest
        AND OLD.execution_identity_digest = NEW.execution_identity_digest
        AND OLD.lease_fence = NEW.lease_fence
        AND OLD.lease_expires_at_epoch_millis
            = NEW.lease_expires_at_epoch_millis
        AND OLD.pam_scope_digest = NEW.pam_scope_digest
        AND OLD.predecessor_binding_digest
            IS NOT DISTINCT FROM NEW.predecessor_binding_digest
        AND OLD.registered_at_epoch_millis
            = NEW.registered_at_epoch_millis
        AND OLD.fenced_at_epoch_millis IS NULL
        AND NEW.fenced_at_epoch_millis IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'invalid PAM execution binding transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS execution_binding_mutation_guard
    ON control_assurance_pam.execution_bindings;
CREATE TRIGGER execution_binding_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON control_assurance_pam.execution_bindings
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.guard_execution_binding_mutation();

CREATE OR REPLACE FUNCTION
    control_assurance_pam.guard_lifecycle_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding_state text;
    binding_lease_expires_at bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'PAM lifecycle records are append-only';
    END IF;
    IF TG_OP = 'INSERT' OR (OLD.state = 'prepared' AND NEW.state = 'issued') THEN
        SELECT state, lease_expires_at_epoch_millis
        INTO binding_state, binding_lease_expires_at
        FROM control_assurance_pam.execution_bindings
        WHERE journal_namespace_digest = NEW.journal_namespace_digest
          AND execution_binding_digest = NEW.execution_binding_digest
        FOR UPDATE;
        IF (
            binding_state IS DISTINCT FROM 'active'
            OR binding_lease_expires_at IS NULL
            OR binding_lease_expires_at
                <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23000',
                MESSAGE = 'PAM issuance binding is fenced, expired, or absent';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND (
        ROW(
            NEW.lifecycle_sequence,
            NEW.lifecycle_record_id,
            NEW.journal_namespace_digest,
            NEW.tenant_id,
            NEW.run_id,
            NEW.execution_plan_digest,
            NEW.execution_identity_digest,
            NEW.lease_fence,
            NEW.pam_scope_digest,
            NEW.execution_binding_digest,
            NEW.authority_class,
            NEW.connector_id,
            NEW.connector_request_digest,
            NEW.credential_reference_digest,
            NEW.created_epoch_millis
        ) IS DISTINCT FROM ROW(
            OLD.lifecycle_sequence,
            OLD.lifecycle_record_id,
            OLD.journal_namespace_digest,
            OLD.tenant_id,
            OLD.run_id,
            OLD.execution_plan_digest,
            OLD.execution_identity_digest,
            OLD.lease_fence,
            OLD.pam_scope_digest,
            OLD.execution_binding_digest,
            OLD.authority_class,
            OLD.connector_id,
            OLD.connector_request_digest,
            OLD.credential_reference_digest,
            OLD.created_epoch_millis
        )
        OR NEW.revision != OLD.revision + 1
        OR NOT (
            (
                OLD.state = 'prepared'
                AND NEW.state IN (
                    'issued',
                    'uncertain',
                    'never-issued',
                    'revoked'
                )
            )
            OR (
                OLD.state IN ('issued', 'uncertain')
                AND NEW.state IN ('expired', 'revoked')
            )
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'invalid PAM lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS lifecycle_mutation_guard
    ON control_assurance_pam.lifecycle_records;
CREATE TRIGGER lifecycle_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE
    ON control_assurance_pam.lifecycle_records
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.guard_lifecycle_mutation();

CREATE OR REPLACE FUNCTION
    control_assurance_pam.validate_issuance_fence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_binding control_assurance_pam.execution_bindings%ROWTYPE;
    successor_binding control_assurance_pam.execution_bindings%ROWTYPE;
BEGIN
    SELECT *
    INTO old_binding
    FROM control_assurance_pam.execution_bindings
    WHERE journal_namespace_digest = NEW.journal_namespace_digest
      AND execution_binding_digest = NEW.fenced_execution_binding_digest
    FOR UPDATE;
    SELECT *
    INTO successor_binding
    FROM control_assurance_pam.execution_bindings
    WHERE journal_namespace_digest = NEW.journal_namespace_digest
      AND execution_binding_digest = NEW.successor_execution_binding_digest
    FOR UPDATE;
    IF (
        old_binding.execution_binding_digest IS NULL
        OR successor_binding.execution_binding_digest IS NULL
        OR old_binding.state != 'fenced'
        OR successor_binding.state != 'active'
        OR old_binding.fenced_at_epoch_millis
            != NEW.effective_at_epoch_millis
        OR successor_binding.registered_at_epoch_millis
            != NEW.effective_at_epoch_millis
        OR successor_binding.predecessor_binding_digest
            IS DISTINCT FROM old_binding.execution_binding_digest
        OR successor_binding.tenant_id != old_binding.tenant_id
        OR successor_binding.run_id != old_binding.run_id
        OR successor_binding.execution_plan_digest
            != old_binding.execution_plan_digest
        OR successor_binding.execution_identity_digest
            != old_binding.execution_identity_digest
        OR successor_binding.lease_fence != old_binding.lease_fence + 1
        OR successor_binding.pam_scope_digest != old_binding.pam_scope_digest
        OR NEW.pam_scope_digest != old_binding.pam_scope_digest
        OR NEW.valid_until_epoch_millis
            < successor_binding.lease_expires_at_epoch_millis
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'invalid PAM recovery issuance fence';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS issuance_fence_validation
    ON control_assurance_pam.issuance_fences;
CREATE TRIGGER issuance_fence_validation
BEFORE INSERT ON control_assurance_pam.issuance_fences
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.validate_issuance_fence();

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23000',
        MESSAGE = 'PAM recovery evidence is append-only';
END;
$$;

DROP TRIGGER IF EXISTS execution_binding_scope_append_only
    ON control_assurance_pam.execution_binding_scopes;
CREATE TRIGGER execution_binding_scope_append_only
BEFORE UPDATE OR DELETE
    ON control_assurance_pam.execution_binding_scopes
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_append_only_mutation();

DROP TRIGGER IF EXISTS issuance_fence_append_only
    ON control_assurance_pam.issuance_fences;
CREATE TRIGGER issuance_fence_append_only
BEFORE UPDATE OR DELETE ON control_assurance_pam.issuance_fences
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_append_only_mutation();

DROP TRIGGER IF EXISTS schema_migration_append_only
    ON control_assurance_pam.schema_migrations;
CREATE TRIGGER schema_migration_append_only
BEFORE UPDATE OR DELETE ON control_assurance_pam.schema_migrations
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.reject_append_only_mutation();

ALTER TABLE control_assurance_pam.elastic_jit_leases
    ADD COLUMN IF NOT EXISTS execution_binding_digest text,
    ADD COLUMN IF NOT EXISTS lifecycle_sequence bigint;

ALTER TABLE control_assurance_pam.defender_token_lifecycle
    ADD COLUMN IF NOT EXISTS execution_binding_digest text,
    ADD COLUMN IF NOT EXISTS lifecycle_sequence bigint;

CREATE UNIQUE INDEX IF NOT EXISTS elastic_jit_leases_lifecycle_sequence
    ON control_assurance_pam.elastic_jit_leases (lifecycle_sequence)
    WHERE lifecycle_sequence IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS defender_token_lifecycle_sequence
    ON control_assurance_pam.defender_token_lifecycle (lifecycle_sequence)
    WHERE lifecycle_sequence IS NOT NULL;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.guard_source_issuance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    connector text := TG_ARGV[0];
    binding_state text;
    binding_lease_expires_at bigint;
    linked boolean;
    issuance_transition boolean;
BEGIN
    issuance_transition := TG_OP = 'INSERT'
        OR (
            OLD.state = 'prepared'
            AND NEW.state = TG_ARGV[1]
        );
    IF NOT issuance_transition THEN
        RETURN NEW;
    END IF;
    IF (NEW.execution_binding_digest IS NULL)
        != (NEW.lifecycle_sequence IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'partial PAM lifecycle binding is forbidden';
    END IF;
    IF NEW.execution_binding_digest IS NULL THEN
        IF EXISTS (
            SELECT 1
            FROM control_assurance_pam.execution_binding_scopes AS scope
            JOIN control_assurance_pam.execution_bindings AS binding
              ON binding.journal_namespace_digest
                    = scope.journal_namespace_digest
             AND binding.execution_binding_digest
                    = scope.execution_binding_digest
            WHERE scope.journal_namespace_digest
                    = NEW.journal_namespace_digest
              AND scope.authority_class = 'source'
              AND scope.connector_id = connector
              AND scope.connector_request_digest = NEW.request_digest
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23000',
                MESSAGE = 'unbound source issuance matches a registered PAM scope';
        END IF;
        RETURN NEW;
    END IF;
    SELECT binding.state, binding.lease_expires_at_epoch_millis, EXISTS (
        SELECT 1
        FROM control_assurance_pam.lifecycle_records AS lifecycle
        WHERE lifecycle.lifecycle_sequence = NEW.lifecycle_sequence
          AND lifecycle.journal_namespace_digest
                = NEW.journal_namespace_digest
          AND lifecycle.execution_binding_digest
                = NEW.execution_binding_digest
          AND lifecycle.authority_class = 'source'
          AND lifecycle.connector_id = connector
          AND lifecycle.connector_request_digest = NEW.request_digest
    )
    INTO binding_state, binding_lease_expires_at, linked
    FROM control_assurance_pam.execution_bindings AS binding
    WHERE binding.journal_namespace_digest = NEW.journal_namespace_digest
      AND binding.execution_binding_digest = NEW.execution_binding_digest
    FOR UPDATE;
    IF (
        binding_state IS DISTINCT FROM 'active'
        OR binding_lease_expires_at IS NULL
        OR binding_lease_expires_at
            <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
        OR linked IS DISTINCT FROM true
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'source issuance is outside the active PAM binding';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS elastic_source_issuance_guard
    ON control_assurance_pam.elastic_jit_leases;
CREATE TRIGGER elastic_source_issuance_guard
BEFORE INSERT OR UPDATE ON control_assurance_pam.elastic_jit_leases
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.guard_source_issuance(
    'elastic-security',
    'active'
);

DROP TRIGGER IF EXISTS defender_source_issuance_guard
    ON control_assurance_pam.defender_token_lifecycle;
CREATE TRIGGER defender_source_issuance_guard
BEFORE INSERT OR UPDATE ON control_assurance_pam.defender_token_lifecycle
FOR EACH ROW
EXECUTE FUNCTION control_assurance_pam.guard_source_issuance(
    'defender-xdr',
    'issued'
);

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_elastic_lease_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.journal_namespace_digest,
        NEW.lease_id,
        NEW.key_name,
        NEW.index_alias,
        NEW.request_digest,
        NEW.endpoint_origin_digest,
        NEW.role_descriptor_digest,
        NEW.ttl_seconds,
        NEW.created_epoch_millis,
        NEW.execution_binding_digest,
        NEW.lifecycle_sequence
    ) IS DISTINCT FROM ROW(
        OLD.journal_namespace_digest,
        OLD.lease_id,
        OLD.key_name,
        OLD.index_alias,
        OLD.request_digest,
        OLD.endpoint_origin_digest,
        OLD.role_descriptor_digest,
        OLD.ttl_seconds,
        OLD.created_epoch_millis,
        OLD.execution_binding_digest,
        OLD.lifecycle_sequence
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'immutable Elastic PAM lease identity';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.reject_defender_token_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.journal_namespace_digest,
        NEW.acquisition_id,
        NEW.request_digest,
        NEW.token_endpoint_digest,
        NEW.graph_origin_digest,
        NEW.scope_digest,
        NEW.credential_mode,
        NEW.credential_reference_digest,
        NEW.token_request_profile_digest,
        NEW.created_epoch_millis,
        NEW.conservative_exposure_end_epoch_millis,
        NEW.execution_binding_digest,
        NEW.lifecycle_sequence
    ) IS DISTINCT FROM ROW(
        OLD.journal_namespace_digest,
        OLD.acquisition_id,
        OLD.request_digest,
        OLD.token_endpoint_digest,
        OLD.graph_origin_digest,
        OLD.scope_digest,
        OLD.credential_mode,
        OLD.credential_reference_digest,
        OLD.token_request_profile_digest,
        OLD.created_epoch_millis,
        OLD.conservative_exposure_end_epoch_millis,
        OLD.execution_binding_digest,
        OLD.lifecycle_sequence
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'immutable Defender PAM token identity';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE control_assurance_pam.elastic_jit_leases
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.elastic_jit_leases
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.defender_token_lifecycle
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.defender_token_lifecycle
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.execution_bindings
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.execution_bindings
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.execution_binding_scopes
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.execution_binding_scopes
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.lifecycle_records
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.lifecycle_records
    FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.issuance_fences
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance_pam.issuance_fences
    FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS elastic_jit_namespace_tenant
    ON control_assurance_pam.elastic_jit_leases;
CREATE POLICY elastic_jit_namespace_tenant
ON control_assurance_pam.elastic_jit_leases
USING (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
)
WITH CHECK (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
);

DROP POLICY IF EXISTS defender_token_namespace_tenant
    ON control_assurance_pam.defender_token_lifecycle;
CREATE POLICY defender_token_namespace_tenant
ON control_assurance_pam.defender_token_lifecycle
USING (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
)
WITH CHECK (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
);

DROP POLICY IF EXISTS execution_binding_namespace_tenant
    ON control_assurance_pam.execution_bindings;
CREATE POLICY execution_binding_namespace_tenant
ON control_assurance_pam.execution_bindings
USING (
    tenant_id = control_assurance_pam.session_tenant()
    AND control_assurance_pam.session_owns_namespace(
        journal_namespace_digest
    )
)
WITH CHECK (
    tenant_id = control_assurance_pam.session_tenant()
    AND control_assurance_pam.session_owns_namespace(
        journal_namespace_digest
    )
);

DROP POLICY IF EXISTS execution_binding_scope_namespace_tenant
    ON control_assurance_pam.execution_binding_scopes;
CREATE POLICY execution_binding_scope_namespace_tenant
ON control_assurance_pam.execution_binding_scopes
USING (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
)
WITH CHECK (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
);

DROP POLICY IF EXISTS lifecycle_record_namespace_tenant
    ON control_assurance_pam.lifecycle_records;
CREATE POLICY lifecycle_record_namespace_tenant
ON control_assurance_pam.lifecycle_records
USING (
    tenant_id = control_assurance_pam.session_tenant()
    AND control_assurance_pam.session_owns_namespace(
        journal_namespace_digest
    )
)
WITH CHECK (
    tenant_id = control_assurance_pam.session_tenant()
    AND control_assurance_pam.session_owns_namespace(
        journal_namespace_digest
    )
);

DROP POLICY IF EXISTS issuance_fence_namespace_tenant
    ON control_assurance_pam.issuance_fences;
CREATE POLICY issuance_fence_namespace_tenant
ON control_assurance_pam.issuance_fences
USING (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
)
WITH CHECK (
    control_assurance_pam.session_owns_namespace(journal_namespace_digest)
);

CREATE OR REPLACE FUNCTION
    control_assurance_pam.configure_login_role(
        p_tenant_id text,
        p_login_role name,
        p_principal_kind text
    )
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
DECLARE
    attributes pg_catalog.pg_roles%ROWTYPE;
BEGIN
    IF session_user <> current_user
       OR p_tenant_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_login_role::text !~ '^[a-z][a-z0-9_]{0,62}$'
       OR p_principal_kind NOT IN ('broker', 'recovery', 'auditor')
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.oid =
                'control_assurance_pam.configure_login_role('
                'text,name,text)'::regprocedure
              AND routine.proowner =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname = 'control_assurance_pam'
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
            'PAM role provisioning requires the exact migration owner'
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
       OR NOT control_assurance_pam.foreign_store_isolated(
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
                    'control_assurance_pam'::regnamespace
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee = attributes.oid
       )
    THEN
        RAISE EXCEPTION 'PAM login role is absent or privileged'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO control_assurance_pam.role_entitlements (
        database_role,
        tenant_id,
        principal_kind
    )
    VALUES (p_login_role, p_tenant_id, p_principal_kind)
    ON CONFLICT (database_role) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_pam.role_entitlements AS entitlement
        WHERE entitlement.database_role = p_login_role
          AND entitlement.tenant_id = p_tenant_id
          AND entitlement.principal_kind = p_principal_kind
    ) THEN
        RAISE EXCEPTION 'PAM login role is already bound'
            USING ERRCODE = '23505';
    END IF;

    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA '
        'control_assurance_pam FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA '
        'control_assurance_pam FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA '
        'control_assurance_pam FROM %I',
        p_login_role
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON SCHEMA control_assurance_pam FROM %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT USAGE ON SCHEMA control_assurance_pam TO %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION '
        'control_assurance_pam.session_tenant(), '
        'control_assurance_pam.session_principal_kind(), '
        'control_assurance_pam.session_owns_namespace(text), '
        'control_assurance_pam.assert_session_principal('
        'text,text,text,text,text), '
        'control_assurance_pam.assert_journal_namespace('
        'text,text,text) TO %I',
        p_login_role
    );
    EXECUTE format(
        'GRANT SELECT ON control_assurance_pam.schema_migrations TO %I',
        p_login_role
    );
    IF p_principal_kind = 'broker' THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON '
            'control_assurance_pam.elastic_jit_leases, '
            'control_assurance_pam.defender_token_lifecycle, '
            'control_assurance_pam.execution_bindings, '
            'control_assurance_pam.lifecycle_records TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON '
            'control_assurance_pam.execution_binding_scopes, '
            'control_assurance_pam.issuance_fences TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE '
            'control_assurance_pam.lifecycle_sequence TO %I',
            p_login_role
        );
    ELSIF p_principal_kind = 'recovery' THEN
        EXECUTE format(
            'GRANT SELECT, UPDATE ON '
            'control_assurance_pam.elastic_jit_leases, '
            'control_assurance_pam.defender_token_lifecycle, '
            'control_assurance_pam.lifecycle_records TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON '
            'control_assurance_pam.execution_bindings TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON '
            'control_assurance_pam.execution_binding_scopes, '
            'control_assurance_pam.issuance_fences TO %I',
            p_login_role
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE '
            'control_assurance_pam.lifecycle_sequence TO %I',
            p_login_role
        );
    ELSE
        EXECUTE format(
            'GRANT SELECT ON '
            'control_assurance_pam.schema_migrations, '
            'control_assurance_pam.elastic_jit_leases, '
            'control_assurance_pam.defender_token_lifecycle, '
            'control_assurance_pam.execution_bindings, '
            'control_assurance_pam.execution_binding_scopes, '
            'control_assurance_pam.lifecycle_records, '
            'control_assurance_pam.issuance_fences TO %I',
            p_login_role
        );
    END IF;
    RETURN TRUE;
END;
$function$;

CREATE OR REPLACE FUNCTION
    control_assurance_pam.configure_journal_namespace(
        p_journal_namespace_digest text,
        p_tenant_id text,
        p_purpose text
    )
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_pam
AS $function$
BEGIN
    IF session_user <> current_user
       OR p_journal_namespace_digest
            !~ '^sha256:[a-f0-9]{64}$'
       OR p_tenant_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_purpose !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            WHERE routine.oid =
                'control_assurance_pam.configure_journal_namespace('
                'text,text,text)'::regprocedure
              AND routine.proowner =
                    (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = session_user)
       )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname = 'control_assurance_pam'
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
            'PAM namespace provisioning requires the exact migration owner'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO control_assurance_pam.journal_namespaces (
        journal_namespace_digest,
        tenant_id,
        purpose
    )
    VALUES (
        p_journal_namespace_digest,
        p_tenant_id,
        p_purpose
    )
    ON CONFLICT (journal_namespace_digest) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_pam.journal_namespaces AS namespace
        WHERE namespace.journal_namespace_digest =
                p_journal_namespace_digest
          AND namespace.tenant_id = p_tenant_id
          AND namespace.purpose = p_purpose
    ) THEN
        RAISE EXCEPTION 'PAM journal namespace is already bound'
            USING ERRCODE = '23505';
    END IF;
    RETURN TRUE;
END;
$function$;

-- Migration 3 initially exposed the mapped tenant text to journal roles.
-- Policies now need only an ownership predicate; remove the obsolete reverse
-- lookup on upgrades so a known digest cannot reveal another tenant id.
DROP FUNCTION IF EXISTS control_assurance_pam.namespace_tenant(text);

REVOKE ALL ON control_assurance_pam.execution_bindings FROM PUBLIC;
REVOKE ALL ON control_assurance_pam.execution_binding_scopes FROM PUBLIC;
REVOKE ALL ON control_assurance_pam.lifecycle_records FROM PUBLIC;
REVOKE ALL ON control_assurance_pam.issuance_fences FROM PUBLIC;
REVOKE ALL ON SEQUENCE control_assurance_pam.lifecycle_sequence FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_pam FROM PUBLIC;

INSERT INTO control_assurance_pam.schema_migrations (version, description)
VALUES (
    2,
    'Plan-bound PAM lifecycle sequence, exact snapshots, and recovery issuance fences'
)
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance_pam.schema_migrations (version, description)
VALUES (
    3,
    'session-user tenant entitlements and owner-provisioned journal namespaces'
)
ON CONFLICT (version) DO NOTHING;

DO $migration_check$
DECLARE
    installed_versions integer[];
BEGIN
    SELECT array_agg(version ORDER BY version)
    INTO installed_versions
    FROM control_assurance_pam.schema_migrations;
    IF installed_versions IS DISTINCT FROM ARRAY[1, 2, 3]::integer[] THEN
        RAISE EXCEPTION 'unsupported PAM journal schema lineage: %',
            installed_versions;
    END IF;
END;
$migration_check$;

COMMIT;
