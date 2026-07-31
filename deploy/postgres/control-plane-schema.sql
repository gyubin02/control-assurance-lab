-- Control Assurance control-plane schema, migrations 1 through 6.
--
-- Apply with a dedicated migration owner.  Migration 6 replaces the legacy
-- caller-settable tenant GUC with a migration-owner-controlled login-role
-- binding derived from session_user.  After applying the structural migration,
-- the same owner must call control_assurance_boundary.configure_runtime_roles()
-- once for the deployment before any runtime can pass readiness.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE SCHEMA IF NOT EXISTS control_assurance;

CREATE TABLE IF NOT EXISTS control_assurance.schema_migrations (
    version integer PRIMARY KEY CHECK (version >= 1),
    description text NOT NULL CHECK (length(description) BETWEEN 1 AND 255),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS control_assurance.control_revisions (
    revision_id text PRIMARY KEY
        CHECK (revision_id ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    generation bigint NOT NULL CHECK (generation >= 1),
    parent_revision_id text
        REFERENCES control_assurance.control_revisions(revision_id),
    configuration_digest text NOT NULL
        CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    configuration_bytes bytea NOT NULL
        CHECK (
            octet_length(configuration_bytes) BETWEEN 2 AND 1048576
        ),
    state text NOT NULL
        CHECK (state IN ('draft', 'submitted', 'approved', 'rejected', 'retired')),
    state_version bigint NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 255),
    created_at timestamptz(0) NOT NULL,
    submitted_at timestamptz(0),
    decided_at timestamptz(0),
    CONSTRAINT revisions_generation_unique
        UNIQUE (tenant_id, control_id, generation),
    CONSTRAINT revisions_tenant_identity_unique
        UNIQUE (tenant_id, revision_id),
    CONSTRAINT revisions_pointer_identity_unique
        UNIQUE (tenant_id, control_id, revision_id, configuration_digest),
    CONSTRAINT revisions_lineage_shape CHECK (
        (generation = 1 AND parent_revision_id IS NULL)
        OR (generation > 1 AND parent_revision_id IS NOT NULL)
    ),
    CONSTRAINT revisions_lifecycle_shape CHECK (
        (state = 'draft' AND submitted_at IS NULL AND decided_at IS NULL)
        OR (state = 'submitted' AND submitted_at IS NOT NULL AND decided_at IS NULL)
        OR (
            state IN ('approved', 'rejected', 'retired')
            AND submitted_at IS NOT NULL
            AND decided_at IS NOT NULL
        )
    ),
    CONSTRAINT revisions_lifecycle_order CHECK (
        created_at <= COALESCE(submitted_at, created_at)
        AND COALESCE(submitted_at, created_at)
            <= COALESCE(decided_at, submitted_at, created_at)
    )
);

CREATE INDEX IF NOT EXISTS control_revisions_lineage
    ON control_assurance.control_revisions
        (tenant_id, control_id, generation DESC);

-- This is both a business invariant and a last-line concurrency guard.
CREATE UNIQUE INDEX IF NOT EXISTS control_revisions_one_in_flight
    ON control_assurance.control_revisions (tenant_id, control_id)
    WHERE state IN ('draft', 'submitted');

CREATE TABLE IF NOT EXISTS control_assurance.approval_decisions (
    decision_id text PRIMARY KEY
        CHECK (decision_id ~ '^sha256:[a-f0-9]{64}$'),
    revision_id text NOT NULL UNIQUE,
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    decided_by text NOT NULL CHECK (length(decided_by) BETWEEN 1 AND 255),
    decided_at timestamptz(0) NOT NULL,
    comment text NOT NULL CHECK (length(comment) BETWEEN 1 AND 2000),
    actor_session_digest text NOT NULL
        CHECK (actor_session_digest ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT decisions_revision_tenant_fk
        FOREIGN KEY (tenant_id, revision_id)
        REFERENCES control_assurance.control_revisions (tenant_id, revision_id)
);

CREATE INDEX IF NOT EXISTS approval_decisions_tenant_revision
    ON control_assurance.approval_decisions (tenant_id, revision_id);

CREATE TABLE IF NOT EXISTS control_assurance.active_deployments (
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    revision_id text NOT NULL
        CHECK (revision_id ~ '^sha256:[a-f0-9]{64}$'),
    configuration_digest text NOT NULL
        CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    activated_by text NOT NULL CHECK (length(activated_by) BETWEEN 1 AND 255),
    activated_at timestamptz(0) NOT NULL,
    deployment_version bigint NOT NULL CHECK (deployment_version >= 1),
    PRIMARY KEY (tenant_id, control_id),
    CONSTRAINT active_deployment_exact_revision_fk
        FOREIGN KEY (
            tenant_id,
            control_id,
            revision_id,
            configuration_digest
        )
        REFERENCES control_assurance.control_revisions (
            tenant_id,
            control_id,
            revision_id,
            configuration_digest
        )
);

-- A row in active_deployments is only the approved desired-selection pointer.
-- Actual application is acknowledged separately by this durable outbox.
CREATE TABLE IF NOT EXISTS control_assurance.deployment_operations (
    operation_id text PRIMARY KEY
        CHECK (operation_id ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    control_id text NOT NULL
        CHECK (control_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    operation_sequence bigint NOT NULL CHECK (operation_sequence >= 1),
    kind text NOT NULL CHECK (kind IN ('apply', 'rollback')),
    revision_id text NOT NULL
        CHECK (revision_id ~ '^sha256:[a-f0-9]{64}$'),
    configuration_digest text NOT NULL
        CHECK (configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    predecessor_operation_id text
        REFERENCES control_assurance.deployment_operations(operation_id),
    retry_of_operation_id text
        CONSTRAINT deployment_operation_retry_digest
        CHECK (
            retry_of_operation_id IS NULL
            OR retry_of_operation_id ~ '^sha256:[a-f0-9]{64}$'
        ),
    requested_by text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 255),
    requested_at timestamptz(0) NOT NULL,
    requester_session_digest text NOT NULL
        CHECK (requester_session_digest ~ '^sha256:[a-f0-9]{64}$'),
    state text NOT NULL
        CHECK (state IN ('pending', 'leased', 'applied', 'failed')),
    state_version bigint NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
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
    applied_at timestamptz(0),
    applied_configuration_digest text
        CHECK (
            applied_configuration_digest IS NULL
            OR applied_configuration_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    target_receipt_digest text
        CHECK (
            target_receipt_digest IS NULL
            OR target_receipt_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    failed_at timestamptz(0),
    failure_digest text
        CHECK (
            failure_digest IS NULL
            OR failure_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    CONSTRAINT deployment_operation_sequence_unique
        UNIQUE (tenant_id, control_id, operation_sequence),
    CONSTRAINT deployment_operation_exact_revision_fk
        FOREIGN KEY (
            tenant_id,
            control_id,
            revision_id,
            configuration_digest
        )
        REFERENCES control_assurance.control_revisions (
            tenant_id,
            control_id,
            revision_id,
            configuration_digest
        ),
    CONSTRAINT deployment_operation_retry_fk
        FOREIGN KEY (retry_of_operation_id)
        REFERENCES control_assurance.deployment_operations (operation_id),
    CONSTRAINT deployment_operation_state_shape CHECK (
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
            AND applied_at IS NULL
            AND applied_configuration_digest IS NULL
            AND target_receipt_digest IS NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'leased'
            AND attempt_count >= 1
            AND lease_fence = attempt_count
            AND lease_owner IS NOT NULL
            AND lease_token_digest IS NOT NULL
            AND leased_at IS NOT NULL
            AND leased_at >= requested_at
            AND lease_expires_at > leased_at
            AND retry_at IS NULL
            AND applied_at IS NULL
            AND applied_configuration_digest IS NULL
            AND target_receipt_digest IS NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'applied'
            AND attempt_count >= 1
            AND lease_fence = attempt_count
            AND lease_owner IS NULL
            AND lease_token_digest IS NULL
            AND leased_at IS NULL
            AND lease_expires_at IS NULL
            AND retry_at IS NULL
            AND applied_at IS NOT NULL
            AND applied_at >= requested_at
            AND applied_configuration_digest = configuration_digest
            AND target_receipt_digest IS NOT NULL
            AND failed_at IS NULL
            AND failure_digest IS NULL
        )
        OR (
            state = 'failed'
            AND attempt_count >= 1
            AND lease_fence = attempt_count
            AND lease_owner IS NULL
            AND lease_token_digest IS NULL
            AND leased_at IS NULL
            AND lease_expires_at IS NULL
            AND applied_at IS NULL
            AND applied_configuration_digest IS NULL
            AND target_receipt_digest IS NULL
            AND failed_at IS NOT NULL
            AND failed_at >= requested_at
            AND failure_digest IS NOT NULL
            AND (
                retry_at IS NULL
                OR (
                    retry_at > failed_at
                    AND retry_at <= failed_at + interval '24 hours'
                )
            )
        )
    )
);

-- Migration 4: retries are new immutable intent, so their lineage must live in
-- the operation itself rather than only in an audit-event detail document.
ALTER TABLE control_assurance.deployment_operations
    ADD COLUMN IF NOT EXISTS retry_of_operation_id text;

DO $deployment_retry_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'control_assurance.deployment_operations'::regclass
          AND conname = 'deployment_operation_retry_digest'
    ) THEN
        ALTER TABLE control_assurance.deployment_operations
            ADD CONSTRAINT deployment_operation_retry_digest
            CHECK (
                retry_of_operation_id IS NULL
                OR retry_of_operation_id ~ '^sha256:[a-f0-9]{64}$'
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'control_assurance.deployment_operations'::regclass
          AND conname = 'deployment_operation_retry_fk'
    ) THEN
        ALTER TABLE control_assurance.deployment_operations
            ADD CONSTRAINT deployment_operation_retry_fk
            FOREIGN KEY (retry_of_operation_id)
            REFERENCES control_assurance.deployment_operations (operation_id);
    END IF;
END;
$deployment_retry_fk$;

CREATE INDEX IF NOT EXISTS deployment_operations_poll
    ON control_assurance.deployment_operations (
        tenant_id, state, retry_at, requested_at, operation_sequence
    );

CREATE UNIQUE INDEX IF NOT EXISTS deployment_operations_one_unresolved
    ON control_assurance.deployment_operations (tenant_id, control_id)
    WHERE state IN ('pending', 'leased')
       OR (state = 'failed' AND retry_at IS NOT NULL);

CREATE TABLE IF NOT EXISTS control_assurance.control_audit_events (
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    sequence bigint NOT NULL CHECK (sequence >= 1),
    previous_event_digest text NOT NULL
        CHECK (previous_event_digest ~ '^sha256:[a-f0-9]{64}$'),
    event_digest text NOT NULL UNIQUE
        CHECK (event_digest ~ '^sha256:[a-f0-9]{64}$'),
    action text NOT NULL CHECK (
        action IN (
            'revision-created',
            'revision-submitted',
            'revision-approved',
            'revision-rejected',
            'revision-activated',
            'deployment-retry-requested',
            'deployment-rollback-requested',
            'deployment-leased',
            'deployment-applied',
            'deployment-failed'
        )
    ),
    object_id text NOT NULL CHECK (object_id ~ '^sha256:[a-f0-9]{64}$'),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    actor_session_digest text NOT NULL
        CHECK (actor_session_digest ~ '^sha256:[a-f0-9]{64}$'),
    occurred_at timestamptz(0) NOT NULL,
    details_digest text NOT NULL
        CHECK (details_digest ~ '^sha256:[a-f0-9]{64}$'),
    details_bytes bytea NOT NULL
        CHECK (octet_length(details_bytes) BETWEEN 2 AND 65536),
    event_bytes bytea NOT NULL
        CHECK (octet_length(event_bytes) BETWEEN 2 AND 65536),
    PRIMARY KEY (tenant_id, sequence)
);

-- CREATE TABLE IF NOT EXISTS cannot update the migration-1 inline check.
ALTER TABLE control_assurance.control_audit_events
    DROP CONSTRAINT IF EXISTS control_audit_events_action_check;
ALTER TABLE control_assurance.control_audit_events
    ADD CONSTRAINT control_audit_events_action_check CHECK (
        action IN (
            'revision-created',
            'revision-submitted',
            'revision-approved',
            'revision-rejected',
            'revision-activated',
            'deployment-retry-requested',
            'deployment-rollback-requested',
            'deployment-leased',
            'deployment-applied',
            'deployment-failed'
        )
    );

CREATE OR REPLACE FUNCTION control_assurance.reject_immutable_change()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_revision_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    latest control_assurance.control_revisions%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:control:' || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );

    SELECT *
    INTO latest
    FROM control_assurance.control_revisions
    WHERE tenant_id = NEW.tenant_id
      AND control_id = NEW.control_id
    ORDER BY generation DESC
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        IF NEW.generation <> 1 OR NEW.parent_revision_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid first revision lineage'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF latest.state IN ('draft', 'submitted') THEN
            RAISE EXCEPTION 'another revision is still in flight'
                USING ERRCODE = '23505';
        END IF;
        IF NEW.generation <> latest.generation + 1
           OR NEW.parent_revision_id IS DISTINCT FROM latest.revision_id THEN
            RAISE EXCEPTION 'revision is not based on latest generation'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_revision_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:control:' || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );
    IF ROW(
        NEW.revision_id,
        NEW.tenant_id,
        NEW.control_id,
        NEW.generation,
        NEW.parent_revision_id,
        NEW.configuration_digest,
        NEW.configuration_bytes,
        NEW.created_by,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.revision_id,
        OLD.tenant_id,
        OLD.control_id,
        OLD.generation,
        OLD.parent_revision_id,
        OLD.configuration_digest,
        OLD.configuration_bytes,
        OLD.created_by,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'revision content and lineage are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.state_version <> OLD.state_version + 1 THEN
        RAISE EXCEPTION 'revision state version must advance exactly once'
            USING ERRCODE = '23514';
    END IF;

    IF NOT (
        (OLD.state = 'draft' AND NEW.state = 'submitted'
            AND OLD.submitted_at IS NULL
            AND NEW.submitted_at IS NOT NULL
            AND NEW.decided_at IS NULL)
        OR
        (OLD.state = 'submitted' AND NEW.state IN ('approved', 'rejected')
            AND NEW.submitted_at = OLD.submitted_at
            AND NEW.decided_at IS NOT NULL)
        OR
        (OLD.state = 'approved' AND NEW.state = 'retired'
            AND NEW.submitted_at = OLD.submitted_at
            AND NEW.decided_at = OLD.decided_at)
    ) THEN
        RAISE EXCEPTION 'invalid revision lifecycle transition'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state IN ('approved', 'rejected')
       AND NOT EXISTS (
            SELECT 1
            FROM control_assurance.approval_decisions AS decision
            WHERE decision.tenant_id = NEW.tenant_id
              AND decision.revision_id = NEW.revision_id
              AND decision.decision = NEW.state
              AND decision.decided_at = NEW.decided_at
       ) THEN
        RAISE EXCEPTION 'decided revision lacks its immutable approval decision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_decision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    revision control_assurance.control_revisions%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    SELECT *
    INTO revision
    FROM control_assurance.control_revisions
    WHERE tenant_id = NEW.tenant_id
      AND revision_id = NEW.revision_id
    FOR UPDATE;
    IF NOT FOUND OR revision.state <> 'submitted' THEN
        RAISE EXCEPTION 'decision target must be a submitted revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.decided_by = revision.created_by THEN
        RAISE EXCEPTION 'revision maker cannot decide their own revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.decided_at < revision.submitted_at THEN
        RAISE EXCEPTION 'decision precedes submission'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_active_deployment()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    revision_state text;
    revision_creator text;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:control:' || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );
    SELECT state, created_by
    INTO revision_state, revision_creator
    FROM control_assurance.control_revisions
    WHERE tenant_id = NEW.tenant_id
      AND control_id = NEW.control_id
      AND revision_id = NEW.revision_id
      AND configuration_digest = NEW.configuration_digest
    FOR UPDATE;
    IF NOT FOUND OR revision_state <> 'approved' THEN
        RAISE EXCEPTION 'active pointer must reference an approved exact revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.activated_by = revision_creator THEN
        RAISE EXCEPTION 'revision maker cannot activate their own revision'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE'
       AND NEW.deployment_version <> OLD.deployment_version + 1 THEN
        RAISE EXCEPTION 'deployment version must advance exactly once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_deployment_operation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    target_state text;
    target_creator text;
    current_sequence bigint;
    current_applied text;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:control:' || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );
    SELECT state, created_by
    INTO target_state, target_creator
    FROM control_assurance.control_revisions
    WHERE tenant_id = NEW.tenant_id
      AND control_id = NEW.control_id
      AND revision_id = NEW.revision_id
      AND configuration_digest = NEW.configuration_digest
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment target is not an exact immutable revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.kind = 'apply' AND target_state <> 'approved' THEN
        RAISE EXCEPTION 'apply target must be an approved revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.kind = 'rollback' AND (
        target_state <> 'retired'
        OR NOT EXISTS (
            SELECT 1
            FROM control_assurance.approval_decisions AS decision
            WHERE decision.tenant_id = NEW.tenant_id
              AND decision.revision_id = NEW.revision_id
              AND decision.decision = 'approved'
        )
    ) THEN
        RAISE EXCEPTION 'rollback target must be a previously approved retired revision'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.requested_by = target_creator THEN
        RAISE EXCEPTION 'revision maker cannot request its deployment'
            USING ERRCODE = '23514';
    END IF;

    SELECT COALESCE(max(operation_sequence), 0)
    INTO current_sequence
    FROM control_assurance.deployment_operations
    WHERE tenant_id = NEW.tenant_id
      AND control_id = NEW.control_id;
    IF NEW.operation_sequence <> current_sequence + 1 THEN
        RAISE EXCEPTION 'deployment operation sequence is not contiguous'
            USING ERRCODE = '23514';
    END IF;

    SELECT operation_id
    INTO current_applied
    FROM control_assurance.deployment_operations
    WHERE tenant_id = NEW.tenant_id
      AND control_id = NEW.control_id
      AND state = 'applied'
    ORDER BY operation_sequence DESC
    LIMIT 1;
    IF NEW.predecessor_operation_id IS DISTINCT FROM current_applied THEN
        RAISE EXCEPTION 'deployment predecessor differs from applied state'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.kind = 'rollback' AND current_applied IS NULL THEN
        RAISE EXCEPTION 'rollback requires a previously applied operation'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.retry_of_operation_id IS NOT NULL AND (
        NEW.kind <> 'apply'
        OR NOT EXISTS (
            SELECT 1
            FROM control_assurance.deployment_operations AS failed
            WHERE failed.operation_id = NEW.retry_of_operation_id
              AND failed.tenant_id = NEW.tenant_id
              AND failed.control_id = NEW.control_id
              AND failed.revision_id = NEW.revision_id
              AND failed.configuration_digest = NEW.configuration_digest
              AND failed.state = 'failed'
              AND failed.retry_at IS NULL
              AND failed.operation_sequence = NEW.operation_sequence - 1
        )
    ) THEN
        RAISE EXCEPTION 'deployment retry lineage is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_deployment_operation_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:control:' || NEW.tenant_id || ':' || NEW.control_id,
            0
        )
    );
    IF ROW(
        NEW.operation_id,
        NEW.tenant_id,
        NEW.control_id,
        NEW.operation_sequence,
        NEW.kind,
        NEW.revision_id,
        NEW.configuration_digest,
        NEW.predecessor_operation_id,
        NEW.retry_of_operation_id,
        NEW.requested_by,
        NEW.requested_at,
        NEW.requester_session_digest
    ) IS DISTINCT FROM ROW(
        OLD.operation_id,
        OLD.tenant_id,
        OLD.control_id,
        OLD.operation_sequence,
        OLD.kind,
        OLD.revision_id,
        OLD.configuration_digest,
        OLD.predecessor_operation_id,
        OLD.retry_of_operation_id,
        OLD.requested_by,
        OLD.requested_at,
        OLD.requester_session_digest
    ) THEN
        RAISE EXCEPTION 'deployment operation request is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.state_version <> OLD.state_version + 1 THEN
        RAISE EXCEPTION 'deployment state version must advance exactly once'
            USING ERRCODE = '23514';
    END IF;
    IF (
        OLD.state = 'pending'
        AND NEW.state = 'leased'
        AND NEW.attempt_count = OLD.attempt_count + 1
        AND NEW.lease_fence = OLD.lease_fence + 1
    ) OR (
        OLD.state = 'failed'
        AND OLD.retry_at IS NOT NULL
        AND NEW.state = 'leased'
        AND NEW.leased_at >= OLD.retry_at
        AND NEW.attempt_count = OLD.attempt_count + 1
        AND NEW.lease_fence = OLD.lease_fence + 1
    ) OR (
        OLD.state = 'leased'
        AND NEW.state = 'leased'
        AND NEW.leased_at >= OLD.lease_expires_at
        AND NEW.attempt_count = OLD.attempt_count + 1
        AND NEW.lease_fence = OLD.lease_fence + 1
    ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'leased'
       AND NEW.state = 'applied'
       AND NEW.attempt_count = OLD.attempt_count
       AND NEW.lease_fence = OLD.lease_fence
       AND NEW.applied_at < OLD.lease_expires_at
       AND NEW.applied_configuration_digest = OLD.configuration_digest THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'leased'
       AND NEW.state = 'failed'
       AND NEW.attempt_count = OLD.attempt_count
       AND NEW.lease_fence = OLD.lease_fence
       AND NEW.failed_at < OLD.lease_expires_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid deployment operation transition'
        USING ERRCODE = '23514';
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance.guard_audit_append()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    last_sequence bigint;
    last_digest text;
    expected_previous text := 'sha256:' || repeat('0', 64);
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:audit:' || NEW.tenant_id, 0)
    );
    SELECT sequence, event_digest
    INTO last_sequence, last_digest
    FROM control_assurance.control_audit_events
    WHERE tenant_id = NEW.tenant_id
    ORDER BY sequence DESC
    LIMIT 1;

    IF FOUND THEN
        expected_previous := last_digest;
        IF NEW.sequence <> last_sequence + 1 THEN
            RAISE EXCEPTION 'audit sequence is not contiguous'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.sequence <> 1 THEN
        RAISE EXCEPTION 'first audit sequence must be one'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.previous_event_digest <> expected_previous THEN
        RAISE EXCEPTION 'audit predecessor digest does not match head'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS revisions_lineage_guard
    ON control_assurance.control_revisions;
CREATE TRIGGER revisions_lineage_guard
BEFORE INSERT ON control_assurance.control_revisions
FOR EACH ROW EXECUTE FUNCTION control_assurance.guard_revision_lineage();

DROP TRIGGER IF EXISTS schema_migrations_no_rewrite
    ON control_assurance.schema_migrations;
CREATE TRIGGER schema_migrations_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON control_assurance.schema_migrations
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance.reject_immutable_change();

DROP TRIGGER IF EXISTS revisions_update_guard
    ON control_assurance.control_revisions;
CREATE TRIGGER revisions_update_guard
BEFORE UPDATE ON control_assurance.control_revisions
FOR EACH ROW EXECUTE FUNCTION control_assurance.guard_revision_update();

DROP TRIGGER IF EXISTS revisions_no_delete
    ON control_assurance.control_revisions;
CREATE TRIGGER revisions_no_delete
BEFORE DELETE OR TRUNCATE ON control_assurance.control_revisions
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance.reject_immutable_change();

DROP TRIGGER IF EXISTS decisions_insert_guard
    ON control_assurance.approval_decisions;
CREATE TRIGGER decisions_insert_guard
BEFORE INSERT ON control_assurance.approval_decisions
FOR EACH ROW EXECUTE FUNCTION control_assurance.guard_decision_insert();

DROP TRIGGER IF EXISTS decisions_no_rewrite
    ON control_assurance.approval_decisions;
CREATE TRIGGER decisions_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON control_assurance.approval_decisions
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance.reject_immutable_change();

DROP TRIGGER IF EXISTS deployments_revision_guard
    ON control_assurance.active_deployments;
CREATE TRIGGER deployments_revision_guard
BEFORE INSERT OR UPDATE ON control_assurance.active_deployments
FOR EACH ROW EXECUTE FUNCTION control_assurance.guard_active_deployment();

DROP TRIGGER IF EXISTS deployment_operations_insert_guard
    ON control_assurance.deployment_operations;
CREATE TRIGGER deployment_operations_insert_guard
BEFORE INSERT ON control_assurance.deployment_operations
FOR EACH ROW EXECUTE FUNCTION
    control_assurance.guard_deployment_operation_insert();

DROP TRIGGER IF EXISTS deployment_operations_update_guard
    ON control_assurance.deployment_operations;
CREATE TRIGGER deployment_operations_update_guard
BEFORE UPDATE ON control_assurance.deployment_operations
FOR EACH ROW EXECUTE FUNCTION
    control_assurance.guard_deployment_operation_update();

DROP TRIGGER IF EXISTS deployment_operations_no_delete
    ON control_assurance.deployment_operations;
CREATE TRIGGER deployment_operations_no_delete
BEFORE DELETE OR TRUNCATE ON control_assurance.deployment_operations
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance.reject_immutable_change();

DROP TRIGGER IF EXISTS audit_append_guard
    ON control_assurance.control_audit_events;
CREATE TRIGGER audit_append_guard
BEFORE INSERT ON control_assurance.control_audit_events
FOR EACH ROW EXECUTE FUNCTION control_assurance.guard_audit_append();

DROP TRIGGER IF EXISTS audit_no_rewrite
    ON control_assurance.control_audit_events;
CREATE TRIGGER audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON control_assurance.control_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance.reject_immutable_change();

-- RLS is forced even for the table owner.  Migration and break-glass roles
-- should be distinct from the runtime role and use a controlled BYPASSRLS path.
ALTER TABLE control_assurance.control_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.control_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.approval_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.active_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.active_deployments FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.deployment_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.deployment_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.control_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assurance.control_audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_revisions
    ON control_assurance.control_revisions;
CREATE POLICY tenant_revisions
ON control_assurance.control_revisions
USING (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
)
WITH CHECK (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
);

DROP POLICY IF EXISTS tenant_decisions
    ON control_assurance.approval_decisions;
CREATE POLICY tenant_decisions
ON control_assurance.approval_decisions
USING (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
)
WITH CHECK (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
);

DROP POLICY IF EXISTS tenant_deployments
    ON control_assurance.active_deployments;
CREATE POLICY tenant_deployments
ON control_assurance.active_deployments
USING (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
)
WITH CHECK (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
);

DROP POLICY IF EXISTS tenant_deployment_operations
    ON control_assurance.deployment_operations;
CREATE POLICY tenant_deployment_operations
ON control_assurance.deployment_operations
USING (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
)
WITH CHECK (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
);

DROP POLICY IF EXISTS tenant_audit
    ON control_assurance.control_audit_events;
CREATE POLICY tenant_audit
ON control_assurance.control_audit_events
USING (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
)
WITH CHECK (
    tenant_id = NULLIF(
        current_setting('control_assurance.tenant_id', true),
        ''
    )
);

-- Authentication state deliberately lives outside the tenant-RLS schema.
-- Before the callback is verified there is no trusted tenant identity, and a
-- browser session must be found by an opaque digest before its tenant can be
-- resolved.  The runtime authentication role therefore receives EXECUTE only
-- on the routines below (plus SELECT on schema_migrations), and receives no
-- privileges on either schema's base tables.  The control-plane runtime role
-- receives no USAGE or EXECUTE privilege in this schema.
CREATE SCHEMA IF NOT EXISTS control_assurance_auth;
REVOKE ALL ON SCHEMA control_assurance_auth FROM PUBLIC;

CREATE TABLE IF NOT EXISTS control_assurance_auth.authorization_transactions (
    transaction_digest text PRIMARY KEY
        CHECK (transaction_digest ~ '^sha256:[a-f0-9]{64}$'),
    state_digest text NOT NULL
        CHECK (state_digest ~ '^sha256:[a-f0-9]{64}$'),
    nonce_digest text NOT NULL
        CHECK (nonce_digest ~ '^sha256:[a-f0-9]{64}$'),
    verifier_ciphertext bytea NOT NULL
        CHECK (octet_length(verifier_ciphertext) BETWEEN 16 AND 16384),
    verifier_key_reference text NOT NULL
        CHECK (length(verifier_key_reference) BETWEEN 1 AND 512),
    verifier_algorithm text NOT NULL
        CHECK (
            length(verifier_algorithm) BETWEEN 1 AND 64
            AND verifier_algorithm ~ '^[A-Za-z0-9._:/@+-]+$'
        ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT authorization_transaction_ttl CHECK (
        isfinite(created_at)
        AND isfinite(expires_at)
        AND
        expires_at > created_at
        AND expires_at <= created_at + interval '15 minutes'
    )
);

CREATE INDEX IF NOT EXISTS authorization_transactions_expiry
    ON control_assurance_auth.authorization_transactions (expires_at);

CREATE TABLE IF NOT EXISTS control_assurance_auth.authorization_transaction_burns (
    transaction_digest text PRIMARY KEY
        CHECK (transaction_digest ~ '^sha256:[a-f0-9]{64}$'),
    transaction_expires_at timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL,
    purge_after timestamptz NOT NULL,
    CONSTRAINT authorization_burn_retention CHECK (
        isfinite(transaction_expires_at)
        AND isfinite(consumed_at)
        AND isfinite(purge_after)
        AND purge_after >= transaction_expires_at
        AND purge_after >= consumed_at
    )
);

CREATE INDEX IF NOT EXISTS authorization_transaction_burns_expiry
    ON control_assurance_auth.authorization_transaction_burns (purge_after);

CREATE TABLE IF NOT EXISTS control_assurance_auth.browser_sessions (
    session_id_digest text PRIMARY KEY
        CHECK (session_id_digest ~ '^sha256:[a-f0-9]{64}$'),
    tenant_id text NOT NULL
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    actor_digest text NOT NULL
        CHECK (actor_digest ~ '^sha256:[a-f0-9]{64}$'),
    actor_bytes bytea NOT NULL
        CHECK (octet_length(actor_bytes) BETWEEN 2 AND 65536),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT browser_session_ttl CHECK (
        isfinite(issued_at)
        AND isfinite(expires_at)
        AND (revoked_at IS NULL OR isfinite(revoked_at))
        AND expires_at > issued_at
        AND expires_at <= issued_at + interval '1 day'
    )
);

CREATE INDEX IF NOT EXISTS browser_sessions_expiry
    ON control_assurance_auth.browser_sessions (expires_at);
CREATE INDEX IF NOT EXISTS browser_sessions_tenant
    ON control_assurance_auth.browser_sessions (tenant_id, expires_at);

CREATE OR REPLACE FUNCTION control_assurance_auth.reject_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION '% cannot be rewritten directly', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.guard_session_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF ROW(
        NEW.session_id_digest,
        NEW.tenant_id,
        NEW.actor_digest,
        NEW.actor_bytes,
        NEW.issued_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.session_id_digest,
        OLD.tenant_id,
        OLD.actor_digest,
        OLD.actor_bytes,
        OLD.issued_at,
        OLD.expires_at
    ) OR OLD.revoked_at IS NOT NULL
      OR NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'browser session is immutable except for first revocation'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS authorization_transactions_no_update
    ON control_assurance_auth.authorization_transactions;
CREATE TRIGGER authorization_transactions_no_update
BEFORE UPDATE OR TRUNCATE
ON control_assurance_auth.authorization_transactions
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance_auth.reject_rewrite();

DROP TRIGGER IF EXISTS authorization_burns_no_rewrite
    ON control_assurance_auth.authorization_transaction_burns;
CREATE TRIGGER authorization_burns_no_rewrite
BEFORE UPDATE OR TRUNCATE
ON control_assurance_auth.authorization_transaction_burns
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance_auth.reject_rewrite();

DROP TRIGGER IF EXISTS browser_sessions_update_guard
    ON control_assurance_auth.browser_sessions;
CREATE TRIGGER browser_sessions_update_guard
BEFORE UPDATE ON control_assurance_auth.browser_sessions
FOR EACH ROW EXECUTE FUNCTION control_assurance_auth.guard_session_update();

DROP TRIGGER IF EXISTS browser_sessions_no_truncate
    ON control_assurance_auth.browser_sessions;
CREATE TRIGGER browser_sessions_no_truncate
BEFORE TRUNCATE ON control_assurance_auth.browser_sessions
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance_auth.reject_rewrite();

CREATE OR REPLACE FUNCTION control_assurance_auth.create_authorization_transaction(
    p_transaction_digest text,
    p_state_digest text,
    p_nonce_digest text,
    p_verifier_ciphertext bytea,
    p_verifier_key_reference text,
    p_verifier_algorithm text,
    p_created_at timestamptz,
    p_expires_at timestamptz,
    p_cleanup_limit integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
BEGIN
    IF p_cleanup_limit < 1 OR p_cleanup_limit > 10000 THEN
        RAISE EXCEPTION 'cleanup limit is invalid' USING ERRCODE = '22023';
    END IF;

    WITH doomed AS (
        SELECT current.ctid
        FROM control_assurance_auth.authorization_transactions AS current
        WHERE current.expires_at <= p_created_at
        ORDER BY current.expires_at
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.authorization_transactions AS current
    USING doomed
    WHERE current.ctid = doomed.ctid;

    WITH doomed AS (
        SELECT consumed.ctid
        FROM control_assurance_auth.authorization_transaction_burns AS consumed
        WHERE consumed.purge_after <= p_created_at
        ORDER BY consumed.purge_after
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.authorization_transaction_burns AS consumed
    USING doomed
    WHERE consumed.ctid = doomed.ctid;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-transaction:' || p_transaction_digest,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM control_assurance_auth.authorization_transactions AS current
        WHERE current.transaction_digest = p_transaction_digest
    ) OR EXISTS (
        SELECT 1
        FROM control_assurance_auth.authorization_transaction_burns AS consumed
        WHERE consumed.transaction_digest = p_transaction_digest
    ) THEN
        RETURN false;
    END IF;

    INSERT INTO control_assurance_auth.authorization_transactions (
        transaction_digest,
        state_digest,
        nonce_digest,
        verifier_ciphertext,
        verifier_key_reference,
        verifier_algorithm,
        created_at,
        expires_at
    ) VALUES (
        p_transaction_digest,
        p_state_digest,
        p_nonce_digest,
        p_verifier_ciphertext,
        p_verifier_key_reference,
        p_verifier_algorithm,
        p_created_at,
        p_expires_at
    );
    RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.consume_authorization_transaction(
    p_transaction_digest text,
    p_consumed_at timestamptz,
    p_burn_retention_seconds integer
)
RETURNS TABLE (
    transaction_digest text,
    state_digest text,
    nonce_digest text,
    verifier_ciphertext bytea,
    verifier_key_reference text,
    verifier_algorithm text,
    created_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    claimed control_assurance_auth.authorization_transactions%ROWTYPE;
BEGIN
    IF p_burn_retention_seconds < 60
       OR p_burn_retention_seconds > 86400 THEN
        RAISE EXCEPTION 'burn retention is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-transaction:' || p_transaction_digest,
            0
        )
    );
    DELETE FROM control_assurance_auth.authorization_transactions AS current
    WHERE current.transaction_digest = p_transaction_digest
    RETURNING current.* INTO claimed;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    INSERT INTO control_assurance_auth.authorization_transaction_burns (
        transaction_digest,
        transaction_expires_at,
        consumed_at,
        purge_after
    ) VALUES (
        claimed.transaction_digest,
        claimed.expires_at,
        p_consumed_at,
        GREATEST(claimed.expires_at, p_consumed_at)
            + make_interval(secs => p_burn_retention_seconds)
    );

    RETURN QUERY SELECT
        claimed.transaction_digest,
        claimed.state_digest,
        claimed.nonce_digest,
        claimed.verifier_ciphertext,
        claimed.verifier_key_reference,
        claimed.verifier_algorithm,
        claimed.created_at,
        claimed.expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.create_browser_session(
    p_session_id_digest text,
    p_tenant_id text,
    p_actor_digest text,
    p_actor_bytes bytea,
    p_issued_at timestamptz,
    p_expires_at timestamptz,
    p_cleanup_limit integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
BEGIN
    IF p_cleanup_limit < 1 OR p_cleanup_limit > 10000 THEN
        RAISE EXCEPTION 'cleanup limit is invalid' USING ERRCODE = '22023';
    END IF;
    WITH doomed AS (
        SELECT session.ctid
        FROM control_assurance_auth.browser_sessions AS session
        WHERE session.expires_at <= p_issued_at
        ORDER BY session.expires_at
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.browser_sessions AS session
    USING doomed
    WHERE session.ctid = doomed.ctid;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-session:' || p_session_id_digest,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM control_assurance_auth.browser_sessions AS session
        WHERE session.session_id_digest = p_session_id_digest
    ) THEN
        RETURN false;
    END IF;
    INSERT INTO control_assurance_auth.browser_sessions (
        session_id_digest,
        tenant_id,
        actor_digest,
        actor_bytes,
        issued_at,
        expires_at
    ) VALUES (
        p_session_id_digest,
        p_tenant_id,
        p_actor_digest,
        p_actor_bytes,
        p_issued_at,
        p_expires_at
    );
    RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.read_browser_session(
    p_session_id_digest text,
    p_read_at timestamptz
)
RETURNS TABLE (
    session_id_digest text,
    tenant_id text,
    actor_digest text,
    actor_bytes bytea,
    issued_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    current control_assurance_auth.browser_sessions%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-session:' || p_session_id_digest,
            0
        )
    );
    SELECT session.*
    INTO current
    FROM control_assurance_auth.browser_sessions AS session
    WHERE session.session_id_digest = p_session_id_digest
    FOR UPDATE;
    IF NOT FOUND OR current.revoked_at IS NOT NULL THEN
        RETURN;
    END IF;
    IF p_read_at < current.issued_at OR p_read_at >= current.expires_at THEN
        UPDATE control_assurance_auth.browser_sessions AS session
        SET revoked_at = transaction_timestamp()
        WHERE session.session_id_digest = p_session_id_digest
          AND session.revoked_at IS NULL;
        RETURN;
    END IF;
    RETURN QUERY SELECT
        current.session_id_digest,
        current.tenant_id,
        current.actor_digest,
        current.actor_bytes,
        current.issued_at,
        current.expires_at;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.revoke_browser_session(
    p_session_id_digest text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    changed bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-session:' || p_session_id_digest,
            0
        )
    );
    UPDATE control_assurance_auth.browser_sessions AS session
    SET revoked_at = transaction_timestamp()
    WHERE session.session_id_digest = p_session_id_digest
      AND session.revoked_at IS NULL;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.create_authorization_transaction(
        text, text, text, bytea, text, text, timestamptz, timestamptz, integer
    )
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.consume_authorization_transaction(
        text, timestamptz, integer
    )
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.create_browser_session(
        text, text, text, bytea, timestamptz, timestamptz, integer
    )
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.read_browser_session(text, timestamptz)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.revoke_browser_session(text)
    FROM PUBLIC;

-- Migration 5: a database-wide admission slot spans PKCE protection and the
-- ready authorization transaction.  This makes global/source limits atomic
-- across API replicas and prevents a fast protector from escaping the count.
CREATE TABLE IF NOT EXISTS control_assurance_auth.oidc_login_admissions (
    transaction_digest text PRIMARY KEY
        CHECK (transaction_digest ~ '^sha256:[a-f0-9]{64}$'),
    source_digest text NOT NULL
        CHECK (source_digest ~ '^hmac-sha256:[a-f0-9]{64}$'),
    phase text NOT NULL CHECK (phase IN ('reserved', 'ready')),
    admitted_at timestamptz NOT NULL,
    reservation_expires_at timestamptz NOT NULL,
    transaction_expires_at timestamptz NOT NULL,
    CONSTRAINT oidc_login_admission_time_shape CHECK (
        isfinite(admitted_at)
        AND isfinite(reservation_expires_at)
        AND isfinite(transaction_expires_at)
        AND reservation_expires_at > admitted_at
        AND reservation_expires_at <= admitted_at + interval '2 minutes'
        AND transaction_expires_at > admitted_at
        AND transaction_expires_at <= admitted_at + interval '15 minutes'
    )
);

CREATE INDEX IF NOT EXISTS oidc_login_admissions_reservation_expiry
    ON control_assurance_auth.oidc_login_admissions
        (reservation_expires_at)
    WHERE phase = 'reserved';
CREATE INDEX IF NOT EXISTS oidc_login_admissions_transaction_expiry
    ON control_assurance_auth.oidc_login_admissions
        (transaction_expires_at)
    WHERE phase = 'ready';
CREATE INDEX IF NOT EXISTS oidc_login_admissions_source
    ON control_assurance_auth.oidc_login_admissions
        (source_digest, phase, reservation_expires_at, transaction_expires_at);

-- Transactions installed by migration 2 were already callback-ready.  Bind
-- them to a non-identifying legacy bucket before adding the exact FK.  This is
-- idempotent and lets those transactions age out without weakening ready-only
-- callback consumption.
INSERT INTO control_assurance_auth.oidc_login_admissions (
    transaction_digest,
    source_digest,
    phase,
    admitted_at,
    reservation_expires_at,
    transaction_expires_at
)
SELECT
    transaction.transaction_digest,
    'hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000',
    'ready',
    transaction.created_at,
    LEAST(
        transaction.created_at + interval '30 seconds',
        transaction.expires_at
    ),
    transaction.expires_at
FROM control_assurance_auth.authorization_transactions AS transaction
ON CONFLICT (transaction_digest) DO NOTHING;

DO $authorization_admission_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid =
            'control_assurance_auth.authorization_transactions'::regclass
          AND conname = 'authorization_transaction_admission_fk'
    ) THEN
        ALTER TABLE control_assurance_auth.authorization_transactions
            ADD CONSTRAINT authorization_transaction_admission_fk
            FOREIGN KEY (transaction_digest)
            REFERENCES control_assurance_auth.oidc_login_admissions (
                transaction_digest
            )
            ON DELETE CASCADE;
    END IF;
END;
$authorization_admission_fk$;

DROP TRIGGER IF EXISTS oidc_login_admissions_no_rewrite
    ON control_assurance_auth.oidc_login_admissions;
CREATE TRIGGER oidc_login_admissions_no_rewrite
BEFORE UPDATE OR TRUNCATE
ON control_assurance_auth.oidc_login_admissions
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance_auth.reject_rewrite();

CREATE OR REPLACE FUNCTION control_assurance_auth.reserve_login_admission(
    p_transaction_digest text,
    p_source_digest text,
    p_transaction_expires_at timestamptz,
    p_reservation_ttl_seconds integer,
    p_global_active_limit integer,
    p_source_active_limit integer,
    p_burn_capacity integer,
    p_cleanup_limit integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    v_admitted_at timestamptz := transaction_timestamp();
    global_active bigint;
    source_active bigint;
    burn_count bigint;
BEGIN
    IF p_transaction_digest !~ '^sha256:[a-f0-9]{64}$'
       OR p_source_digest !~ '^hmac-sha256:[a-f0-9]{64}$'
       OR NOT isfinite(p_transaction_expires_at)
       OR p_transaction_expires_at <= v_admitted_at
       OR p_transaction_expires_at > v_admitted_at + interval '15 minutes'
       OR p_reservation_ttl_seconds < 5
       OR p_reservation_ttl_seconds > 120
       OR p_global_active_limit < 1
       OR p_global_active_limit > 100000
       OR p_source_active_limit < 1
       OR p_source_active_limit > p_global_active_limit
       OR p_burn_capacity < p_global_active_limit
       OR p_burn_capacity > 1000000
       OR p_cleanup_limit < 1
       OR p_cleanup_limit > 10000 THEN
        RAISE EXCEPTION 'OIDC login admission arguments are invalid'
            USING ERRCODE = '22023';
    END IF;

    -- Every reserve takes one fixed transaction lock.  Counts and insertion
    -- therefore form one serial admission decision across all replicas.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:oidc-login-admission:global', 0)
    );

    WITH doomed AS (
        SELECT admission.ctid
        FROM control_assurance_auth.oidc_login_admissions AS admission
        WHERE (
            admission.phase = 'reserved'
            AND admission.reservation_expires_at <= v_admitted_at
        ) OR (
            admission.phase = 'ready'
            AND admission.transaction_expires_at <= v_admitted_at
        )
        ORDER BY
            LEAST(
                admission.reservation_expires_at,
                admission.transaction_expires_at
            )
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.oidc_login_admissions AS admission
    USING doomed
    WHERE admission.ctid = doomed.ctid;

    WITH doomed AS (
        SELECT burn.ctid
        FROM control_assurance_auth.authorization_transaction_burns AS burn
        WHERE burn.purge_after <= v_admitted_at
        ORDER BY burn.purge_after
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.authorization_transaction_burns AS burn
    USING doomed
    WHERE burn.ctid = doomed.ctid;

    SELECT count(*) INTO burn_count
    FROM control_assurance_auth.authorization_transaction_burns;
    IF burn_count >= p_burn_capacity THEN
        RETURN 'burn-capacity';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM control_assurance_auth.oidc_login_admissions AS admission
        WHERE admission.transaction_digest = p_transaction_digest
    ) OR EXISTS (
        SELECT 1
        FROM control_assurance_auth.authorization_transaction_burns AS burn
        WHERE burn.transaction_digest = p_transaction_digest
    ) THEN
        RETURN 'conflict';
    END IF;

    SELECT count(*) INTO global_active
    FROM control_assurance_auth.oidc_login_admissions AS admission
    WHERE (
        admission.phase = 'reserved'
        AND admission.reservation_expires_at > v_admitted_at
    ) OR (
        admission.phase = 'ready'
        AND admission.transaction_expires_at > v_admitted_at
    );
    IF global_active >= p_global_active_limit THEN
        RETURN 'global-limit';
    END IF;

    SELECT count(*) INTO source_active
    FROM control_assurance_auth.oidc_login_admissions AS admission
    WHERE admission.source_digest = p_source_digest
      AND (
        (
            admission.phase = 'reserved'
            AND admission.reservation_expires_at > v_admitted_at
        ) OR (
            admission.phase = 'ready'
            AND admission.transaction_expires_at > v_admitted_at
        )
      );
    IF source_active >= p_source_active_limit THEN
        RETURN 'source-limit';
    END IF;

    INSERT INTO control_assurance_auth.oidc_login_admissions (
        transaction_digest,
        source_digest,
        phase,
        admitted_at,
        reservation_expires_at,
        transaction_expires_at
    ) VALUES (
        p_transaction_digest,
        p_source_digest,
        'reserved',
        v_admitted_at,
        v_admitted_at + make_interval(secs => p_reservation_ttl_seconds),
        p_transaction_expires_at
    );
    RETURN 'reserved';
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.finalize_login_admission(
    p_transaction_digest text,
    p_state_digest text,
    p_nonce_digest text,
    p_verifier_ciphertext bytea,
    p_verifier_key_reference text,
    p_verifier_algorithm text,
    p_created_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    claimed control_assurance_auth.oidc_login_admissions%ROWTYPE;
    finalized_at timestamptz := transaction_timestamp();
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-transaction:' || p_transaction_digest,
            0
        )
    );
    DELETE FROM control_assurance_auth.oidc_login_admissions AS admission
    WHERE admission.transaction_digest = p_transaction_digest
      AND admission.phase = 'reserved'
      AND admission.reservation_expires_at > finalized_at
      AND admission.transaction_expires_at = p_expires_at
    RETURNING admission.* INTO claimed;
    IF NOT FOUND THEN
        -- An expired reservation is never made callback-visible.
        DELETE FROM control_assurance_auth.oidc_login_admissions AS admission
        WHERE admission.transaction_digest = p_transaction_digest
          AND admission.phase = 'reserved'
          AND admission.reservation_expires_at <= finalized_at;
        RETURN false;
    END IF;

    INSERT INTO control_assurance_auth.oidc_login_admissions (
        transaction_digest,
        source_digest,
        phase,
        admitted_at,
        reservation_expires_at,
        transaction_expires_at
    ) VALUES (
        claimed.transaction_digest,
        claimed.source_digest,
        'ready',
        claimed.admitted_at,
        claimed.reservation_expires_at,
        claimed.transaction_expires_at
    );

    INSERT INTO control_assurance_auth.authorization_transactions (
        transaction_digest,
        state_digest,
        nonce_digest,
        verifier_ciphertext,
        verifier_key_reference,
        verifier_algorithm,
        created_at,
        expires_at
    ) VALUES (
        p_transaction_digest,
        p_state_digest,
        p_nonce_digest,
        p_verifier_ciphertext,
        p_verifier_key_reference,
        p_verifier_algorithm,
        p_created_at,
        p_expires_at
    );
    RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.cancel_login_admission(
    p_transaction_digest text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    changed bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-transaction:' || p_transaction_digest,
            0
        )
    );
    DELETE FROM control_assurance_auth.oidc_login_admissions AS admission
    WHERE admission.transaction_digest = p_transaction_digest;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$function$;

CREATE OR REPLACE FUNCTION
control_assurance_auth.consume_ready_authorization_transaction(
    p_transaction_digest text,
    p_consumed_at timestamptz,
    p_burn_retention_seconds integer,
    p_cleanup_limit integer,
    p_burn_capacity integer
)
RETURNS TABLE (
    transaction_digest text,
    state_digest text,
    nonce_digest text,
    verifier_ciphertext bytea,
    verifier_key_reference text,
    verifier_algorithm text,
    created_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, control_assurance_auth
AS $function$
DECLARE
    claimed control_assurance_auth.authorization_transactions%ROWTYPE;
    burn_count bigint;
BEGIN
    IF p_burn_retention_seconds < 60
       OR p_burn_retention_seconds > 86400
       OR p_cleanup_limit < 1
       OR p_cleanup_limit > 10000
       OR p_burn_capacity < 1
       OR p_burn_capacity > 1000000 THEN
        RAISE EXCEPTION 'OIDC consume arguments are invalid'
            USING ERRCODE = '22023';
    END IF;

    -- Serialize the capacity check and burn insertion.  If the bounded replay
    -- ledger is full, fail before deleting callback state.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('control-assurance:oidc-transaction-burns:global', 0)
    );
    WITH doomed AS (
        SELECT burn.ctid
        FROM control_assurance_auth.authorization_transaction_burns AS burn
        WHERE burn.purge_after <= p_consumed_at
        ORDER BY burn.purge_after
        FOR UPDATE SKIP LOCKED
        LIMIT p_cleanup_limit
    )
    DELETE FROM control_assurance_auth.authorization_transaction_burns AS burn
    USING doomed
    WHERE burn.ctid = doomed.ctid;

    SELECT count(*) INTO burn_count
    FROM control_assurance_auth.authorization_transaction_burns;
    IF burn_count >= p_burn_capacity THEN
        RAISE EXCEPTION 'OIDC replay ledger is at capacity'
            USING ERRCODE = '54000';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'control-assurance:oidc-transaction:' || p_transaction_digest,
            0
        )
    );
    DELETE FROM control_assurance_auth.authorization_transactions AS current
    USING control_assurance_auth.oidc_login_admissions AS admission
    WHERE current.transaction_digest = p_transaction_digest
      AND admission.transaction_digest = current.transaction_digest
      AND admission.phase = 'ready'
    RETURNING current.* INTO claimed;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    DELETE FROM control_assurance_auth.oidc_login_admissions AS admission
    WHERE admission.transaction_digest = claimed.transaction_digest
      AND admission.phase = 'ready';

    INSERT INTO control_assurance_auth.authorization_transaction_burns (
        transaction_digest,
        transaction_expires_at,
        consumed_at,
        purge_after
    ) VALUES (
        claimed.transaction_digest,
        claimed.expires_at,
        p_consumed_at,
        GREATEST(claimed.expires_at, p_consumed_at)
            + make_interval(secs => p_burn_retention_seconds)
    );

    RETURN QUERY SELECT
        claimed.transaction_digest,
        claimed.state_digest,
        claimed.nonce_digest,
        claimed.verifier_ciphertext,
        claimed.verifier_key_reference,
        claimed.verifier_algorithm,
        claimed.created_at,
        claimed.expires_at;
END;
$function$;

-- Drop migration-2 entry points so no previously granted EXECUTE privilege can
-- bypass admission or consume a reservation after migration 5.
DROP FUNCTION IF EXISTS
    control_assurance_auth.create_authorization_transaction(
        text, text, text, bytea, text, text, timestamptz, timestamptz, integer
    );
DROP FUNCTION IF EXISTS
    control_assurance_auth.consume_authorization_transaction(
        text, timestamptz, integer
    );

REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.reserve_login_admission(
        text, text, timestamptz, integer, integer, integer, integer, integer
    )
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.finalize_login_admission(
        text, text, text, bytea, text, text, timestamptz, timestamptz
    )
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.cancel_login_admission(text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION
    control_assurance_auth.consume_ready_authorization_transaction(
        text, timestamptz, integer, integer, integer
    )
    FROM PUBLIC;

-- Migration 6: one deployment is bound to one tenant and three distinct login
-- roles.  Runtime code can neither read nor mutate this mapping.  session_user
-- is the connection-time identity and is intentionally unaffected by SET ROLE.
CREATE SCHEMA IF NOT EXISTS control_assurance_boundary;
REVOKE ALL ON SCHEMA control_assurance_boundary FROM PUBLIC;

CREATE TABLE IF NOT EXISTS
control_assurance_boundary.deployment_tenant (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id text NOT NULL UNIQUE
        CHECK (tenant_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
    installed_by name NOT NULL DEFAULT session_user
);

CREATE TABLE IF NOT EXISTS
control_assurance_boundary.runtime_role_bindings (
    login_role name PRIMARY KEY,
    tenant_id text NOT NULL
        REFERENCES control_assurance_boundary.deployment_tenant(tenant_id),
    role_kind text NOT NULL
        CHECK (role_kind IN ('control', 'auth', 'reconciler')),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp(),
    installed_by name NOT NULL DEFAULT session_user,
    CONSTRAINT runtime_role_binding_kind_unique
        UNIQUE (tenant_id, role_kind)
);

REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_boundary FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_boundary FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance_boundary FROM PUBLIC;

CREATE OR REPLACE FUNCTION
control_assurance_boundary.bound_tenant(p_role_kinds text[])
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT binding.tenant_id
    FROM control_assurance_boundary.runtime_role_bindings AS binding
    WHERE binding.login_role = session_user
      AND binding.role_kind = ANY (p_role_kinds)
$function$;

REVOKE ALL ON FUNCTION
    control_assurance_boundary.bound_tenant(text[])
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION control_assurance.session_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT control_assurance_boundary.bound_tenant(
        ARRAY['control', 'reconciler']::text[]
    )
$function$;

CREATE OR REPLACE FUNCTION control_assurance.runtime_identity()
RETURNS TABLE (
    login_role text,
    tenant_id text,
    role_kind text,
    schema_versions integer[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT
        session_user::text,
        binding.tenant_id,
        binding.role_kind,
        (
            SELECT array_agg(migration.version ORDER BY migration.version)
            FROM control_assurance.schema_migrations AS migration
        )
    FROM control_assurance_boundary.runtime_role_bindings AS binding
    WHERE binding.login_role = session_user
      AND binding.role_kind IN ('control', 'reconciler')
$function$;

REVOKE ALL ON FUNCTION control_assurance.session_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION control_assurance.runtime_identity() FROM PUBLIC;

-- Replace every migration-1 tenant policy.  The permissive policy still
-- applies to all roles, but auth/unmapped roles receive NULL from
-- session_tenant() and therefore see and write no rows.
DROP POLICY IF EXISTS tenant_revisions
    ON control_assurance.control_revisions;
CREATE POLICY tenant_revisions
ON control_assurance.control_revisions
USING (tenant_id = control_assurance.session_tenant())
WITH CHECK (tenant_id = control_assurance.session_tenant());

DROP POLICY IF EXISTS tenant_decisions
    ON control_assurance.approval_decisions;
CREATE POLICY tenant_decisions
ON control_assurance.approval_decisions
USING (tenant_id = control_assurance.session_tenant())
WITH CHECK (tenant_id = control_assurance.session_tenant());

DROP POLICY IF EXISTS tenant_deployments
    ON control_assurance.active_deployments;
CREATE POLICY tenant_deployments
ON control_assurance.active_deployments
USING (tenant_id = control_assurance.session_tenant())
WITH CHECK (tenant_id = control_assurance.session_tenant());

DROP POLICY IF EXISTS tenant_deployment_operations
    ON control_assurance.deployment_operations;
CREATE POLICY tenant_deployment_operations
ON control_assurance.deployment_operations
USING (tenant_id = control_assurance.session_tenant())
WITH CHECK (tenant_id = control_assurance.session_tenant());

DROP POLICY IF EXISTS tenant_audit
    ON control_assurance.control_audit_events;
CREATE POLICY tenant_audit
ON control_assurance.control_audit_events
USING (tenant_id = control_assurance.session_tenant())
WITH CHECK (tenant_id = control_assurance.session_tenant());

-- Auth has an independent component lineage.  The auth login role learns it
-- only through runtime_identity(); it never receives a base-table grant or
-- USAGE on the control schema.
CREATE TABLE IF NOT EXISTS control_assurance_auth.schema_migrations (
    version integer PRIMARY KEY CHECK (version IN (2, 5, 6)),
    description text NOT NULL CHECK (length(description) BETWEEN 1 AND 255),
    installed_at timestamptz(0) NOT NULL DEFAULT transaction_timestamp()
);

DROP TRIGGER IF EXISTS auth_schema_migrations_no_rewrite
    ON control_assurance_auth.schema_migrations;
CREATE TRIGGER auth_schema_migrations_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE
ON control_assurance_auth.schema_migrations
FOR EACH STATEMENT EXECUTE FUNCTION control_assurance_auth.reject_rewrite();

INSERT INTO control_assurance_auth.schema_migrations (version, description)
VALUES
    (2, 'one-time OIDC transaction and opaque session state'),
    (5, 'bounded distributed OIDC login admission'),
    (6, 'session-user-bound authentication runtime role')
ON CONFLICT (version) DO NOTHING;

-- Keep the accepted migration-5 bodies byte-for-byte available as private
-- implementation routines, then put a role-binding guard in front of their
-- original signatures.  Rerunning the monolithic schema is idempotent.
DO $rename_auth_v5_routines$
BEGIN
    IF to_regprocedure(
        'control_assurance_auth.reserve_login_admission_v5('
        'text,text,timestamptz,integer,integer,integer,integer,integer)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.reserve_login_admission(
            text, text, timestamptz, integer, integer, integer, integer, integer
        ) RENAME TO reserve_login_admission_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.finalize_login_admission_v5('
        'text,text,text,bytea,text,text,timestamptz,timestamptz)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.finalize_login_admission(
            text, text, text, bytea, text, text, timestamptz, timestamptz
        ) RENAME TO finalize_login_admission_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.cancel_login_admission_v5(text)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.cancel_login_admission(text)
            RENAME TO cancel_login_admission_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.consume_ready_authorization_transaction_v5('
        'text,timestamptz,integer,integer,integer)'
    ) IS NULL THEN
        ALTER FUNCTION
            control_assurance_auth.consume_ready_authorization_transaction(
                text, timestamptz, integer, integer, integer
            )
            RENAME TO consume_ready_authorization_transaction_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.create_browser_session_v5('
        'text,text,text,bytea,timestamptz,timestamptz,integer)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.create_browser_session(
            text, text, text, bytea, timestamptz, timestamptz, integer
        ) RENAME TO create_browser_session_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.read_browser_session_v5(text,timestamptz)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.read_browser_session(
            text, timestamptz
        ) RENAME TO read_browser_session_v5;
    END IF;
    IF to_regprocedure(
        'control_assurance_auth.revoke_browser_session_v5(text)'
    ) IS NULL THEN
        ALTER FUNCTION control_assurance_auth.revoke_browser_session(text)
            RENAME TO revoke_browser_session_v5;
    END IF;
END;
$rename_auth_v5_routines$;

CREATE OR REPLACE FUNCTION control_assurance_auth.runtime_identity()
RETURNS TABLE (
    login_role text,
    tenant_id text,
    role_kind text,
    schema_versions integer[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT
        session_user::text,
        binding.tenant_id,
        binding.role_kind,
        (
            SELECT array_agg(migration.version ORDER BY migration.version)
            FROM control_assurance_auth.schema_migrations AS migration
        )
    FROM control_assurance_boundary.runtime_role_bindings AS binding
    WHERE binding.login_role = session_user
      AND binding.role_kind = 'auth'
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.reserve_login_admission(
    p_transaction_digest text,
    p_source_digest text,
    p_transaction_expires_at timestamptz,
    p_reservation_ttl_seconds integer,
    p_global_active_limit integer,
    p_source_active_limit integer,
    p_burn_capacity integer,
    p_cleanup_limit integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    bound_tenant text;
BEGIN
    bound_tenant := control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    );
    IF bound_tenant IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    RETURN control_assurance_auth.reserve_login_admission_v5(
        p_transaction_digest,
        p_source_digest,
        p_transaction_expires_at,
        p_reservation_ttl_seconds,
        p_global_active_limit,
        p_source_active_limit,
        p_burn_capacity,
        p_cleanup_limit
    );
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.finalize_login_admission(
    p_transaction_digest text,
    p_state_digest text,
    p_nonce_digest text,
    p_verifier_ciphertext bytea,
    p_verifier_key_reference text,
    p_verifier_algorithm text,
    p_created_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    ) IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    RETURN control_assurance_auth.finalize_login_admission_v5(
        p_transaction_digest,
        p_state_digest,
        p_nonce_digest,
        p_verifier_ciphertext,
        p_verifier_key_reference,
        p_verifier_algorithm,
        p_created_at,
        p_expires_at
    );
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.cancel_login_admission(
    p_transaction_digest text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    ) IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    RETURN control_assurance_auth.cancel_login_admission_v5(
        p_transaction_digest
    );
END;
$function$;

CREATE OR REPLACE FUNCTION
control_assurance_auth.consume_ready_authorization_transaction(
    p_transaction_digest text,
    p_consumed_at timestamptz,
    p_burn_retention_seconds integer,
    p_cleanup_limit integer,
    p_burn_capacity integer
)
RETURNS TABLE (
    transaction_digest text,
    state_digest text,
    nonce_digest text,
    verifier_ciphertext bytea,
    verifier_key_reference text,
    verifier_algorithm text,
    created_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    ) IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT *
    FROM control_assurance_auth.consume_ready_authorization_transaction_v5(
        p_transaction_digest,
        p_consumed_at,
        p_burn_retention_seconds,
        p_cleanup_limit,
        p_burn_capacity
    );
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.create_browser_session(
    p_session_id_digest text,
    p_tenant_id text,
    p_actor_digest text,
    p_actor_bytes bytea,
    p_issued_at timestamptz,
    p_expires_at timestamptz,
    p_cleanup_limit integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    bound_tenant text;
BEGIN
    bound_tenant := control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    );
    IF bound_tenant IS NULL OR p_tenant_id IS DISTINCT FROM bound_tenant THEN
        RAISE EXCEPTION 'authentication tenant differs from runtime role'
            USING ERRCODE = '42501';
    END IF;
    RETURN control_assurance_auth.create_browser_session_v5(
        p_session_id_digest,
        p_tenant_id,
        p_actor_digest,
        p_actor_bytes,
        p_issued_at,
        p_expires_at,
        p_cleanup_limit
    );
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.read_browser_session(
    p_session_id_digest text,
    p_read_at timestamptz
)
RETURNS TABLE (
    session_id_digest text,
    tenant_id text,
    actor_digest text,
    actor_bytes bytea,
    issued_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    bound_tenant text;
BEGIN
    bound_tenant := control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    );
    IF bound_tenant IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_auth.browser_sessions AS session
        WHERE session.session_id_digest = p_session_id_digest
          AND session.tenant_id = bound_tenant
    ) THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT stored.*
    FROM control_assurance_auth.read_browser_session_v5(
        p_session_id_digest,
        p_read_at
    ) AS stored
    WHERE stored.tenant_id = bound_tenant;
END;
$function$;

CREATE OR REPLACE FUNCTION control_assurance_auth.revoke_browser_session(
    p_session_id_digest text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    bound_tenant text;
BEGIN
    bound_tenant := control_assurance_boundary.bound_tenant(
        ARRAY['auth']::text[]
    );
    IF bound_tenant IS NULL THEN
        RAISE EXCEPTION 'unbound authentication runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_auth.browser_sessions AS session
        WHERE session.session_id_digest = p_session_id_digest
          AND session.tenant_id = bound_tenant
    ) THEN
        RETURN false;
    END IF;
    RETURN control_assurance_auth.revoke_browser_session_v5(
        p_session_id_digest
    );
END;
$function$;

-- Runtime roles are provisioned outside this generic migration.  Only the
-- migration owner can execute this function (PUBLIC and every runtime schema
-- are revoked below).  It validates non-escalating LOGIN roles, records the
-- one-tenant mapping, and installs the exact object/column grants.
CREATE OR REPLACE FUNCTION
control_assurance_boundary.configure_runtime_roles(
    p_tenant_id text,
    p_control_role name,
    p_auth_role name,
    p_reconciler_role name
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    candidate name;
    attributes record;
    existing record;
BEGIN
    IF session_user <> current_user
       OR p_tenant_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_control_role = p_auth_role
       OR p_control_role = p_reconciler_role
       OR p_auth_role = p_reconciler_role THEN
        RAISE EXCEPTION 'runtime role binding arguments are invalid'
            USING ERRCODE = '22023';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = routine.proowner
        WHERE routine.oid =
            'control_assurance_boundary.configure_runtime_roles('
            'text,name,name,name)'::regprocedure
          AND owner.rolname = session_user
    )
       OR NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = database.datdba
            WHERE database.datname = current_database()
              AND owner.rolname = session_user
       ) THEN
        RAISE EXCEPTION 'runtime roles require the exact migration owner'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO control_assurance_boundary.deployment_tenant (
        singleton,
        tenant_id
    )
    VALUES (true, p_tenant_id)
    ON CONFLICT (singleton) DO NOTHING;

    IF NOT EXISTS (
        SELECT 1
        FROM control_assurance_boundary.deployment_tenant AS deployment
        WHERE deployment.singleton
          AND deployment.tenant_id = p_tenant_id
    ) THEN
        RAISE EXCEPTION 'database is already bound to another tenant'
            USING ERRCODE = '23505';
    END IF;

    EXECUTE format(
        'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );

    FOREACH candidate IN ARRAY ARRAY[
        p_control_role, p_auth_role, p_reconciler_role
    ]::name[]
    LOOP
        SELECT
            role.oid,
            role.rolcanlogin,
            role.rolsuper,
            role.rolinherit,
            role.rolcreaterole,
            role.rolcreatedb,
            role.rolreplication,
            role.rolbypassrls
        INTO attributes
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = candidate;
        IF NOT FOUND
           OR candidate::text !~ '^[a-z][a-z0-9_]{0,62}$'
           OR attributes.rolcanlogin IS NOT TRUE
           OR attributes.rolsuper
           OR attributes.rolinherit
           OR attributes.rolcreaterole
           OR attributes.rolcreatedb
           OR attributes.rolreplication
           OR attributes.rolbypassrls
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
                FROM pg_catalog.pg_parameter_acl AS parameter
                CROSS JOIN LATERAL pg_catalog.aclexplode(
                    parameter.paracl
                ) AS acl
                WHERE acl.grantee IN (0, attributes.oid)
           )
           OR pg_catalog.has_database_privilege(
                candidate,
                current_database(),
                'CREATE'
           )
           OR pg_catalog.has_database_privilege(
                candidate,
                current_database(),
                'TEMPORARY'
           )
           OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_namespace AS namespace
                WHERE pg_catalog.has_schema_privilege(
                    candidate,
                    namespace.oid,
                    'CREATE'
                )
           )
           OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_namespace AS namespace
                WHERE namespace.nspname IN (
                    'control_assurance',
                    'control_assurance_auth',
                    'control_assurance_boundary'
                )
                  AND namespace.nspowner = attributes.oid
           )
           OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_class AS relation
                JOIN pg_catalog.pg_namespace AS namespace
                  ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname IN (
                    'control_assurance',
                    'control_assurance_auth',
                    'control_assurance_boundary'
                )
                  AND relation.relowner = attributes.oid
           )
           OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_proc AS routine
                JOIN pg_catalog.pg_namespace AS namespace
                  ON namespace.oid = routine.pronamespace
                WHERE namespace.nspname IN (
                    'control_assurance',
                    'control_assurance_auth',
                    'control_assurance_boundary'
                )
                  AND routine.proowner = attributes.oid
           ) THEN
            RAISE EXCEPTION 'runtime role is absent or privileged'
                USING ERRCODE = '42501';
        END IF;
    END LOOP;

    FOR existing IN
        SELECT binding.*
        FROM control_assurance_boundary.runtime_role_bindings AS binding
        WHERE binding.tenant_id = p_tenant_id
           OR binding.login_role IN (
                p_control_role, p_auth_role, p_reconciler_role
           )
    LOOP
        IF NOT (
            (
                existing.login_role = p_control_role
                AND existing.tenant_id = p_tenant_id
                AND existing.role_kind = 'control'
            )
            OR (
                existing.login_role = p_auth_role
                AND existing.tenant_id = p_tenant_id
                AND existing.role_kind = 'auth'
            )
            OR (
                existing.login_role = p_reconciler_role
                AND existing.tenant_id = p_tenant_id
                AND existing.role_kind = 'reconciler'
            )
        ) THEN
            RAISE EXCEPTION 'runtime role already has another binding'
                USING ERRCODE = '23505';
        END IF;
    END LOOP;

    INSERT INTO control_assurance_boundary.runtime_role_bindings (
        login_role, tenant_id, role_kind
    ) VALUES
        (p_control_role, p_tenant_id, 'control'),
        (p_auth_role, p_tenant_id, 'auth'),
        (p_reconciler_role, p_tenant_id, 'reconciler')
    ON CONFLICT (login_role) DO NOTHING;

    FOREACH candidate IN ARRAY ARRAY[
        p_control_role, p_auth_role, p_reconciler_role
    ]::name[]
    LOOP
        EXECUTE format(
            'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM %I',
            current_database(),
            candidate
        );
        EXECUTE format(
            'REVOKE ALL ON SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            candidate
        );
        EXECUTE format(
            'REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            candidate
        );
        EXECUTE format(
            'REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            candidate
        );
        EXECUTE format(
            'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            candidate
        );
    END LOOP;

    EXECUTE format(
        'GRANT USAGE ON SCHEMA control_assurance TO %I, %I',
        p_control_role, p_reconciler_role
    );
    EXECUTE format(
        'GRANT SELECT ON control_assurance.schema_migrations TO %I, %I',
        p_control_role, p_reconciler_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION control_assurance.session_tenant(), '
        'control_assurance.runtime_identity() TO %I, %I',
        p_control_role, p_reconciler_role
    );

    EXECUTE format(
        'GRANT SELECT, INSERT ON '
        'control_assurance.control_revisions, '
        'control_assurance.approval_decisions, '
        'control_assurance.active_deployments, '
        'control_assurance.deployment_operations, '
        'control_assurance.control_audit_events TO %I',
        p_control_role
    );
    EXECUTE format(
        'GRANT UPDATE (state, state_version, submitted_at, decided_at) '
        'ON control_assurance.control_revisions TO %I',
        p_control_role
    );
    EXECUTE format(
        'GRANT UPDATE (revision_id, configuration_digest, activated_by, '
        'activated_at, deployment_version) '
        'ON control_assurance.active_deployments TO %I',
        p_control_role
    );

    EXECUTE format(
        'GRANT SELECT ON control_assurance.control_revisions, '
        'control_assurance.deployment_operations, '
        'control_assurance.control_audit_events TO %I',
        p_reconciler_role
    );
    EXECUTE format(
        'GRANT INSERT ON control_assurance.control_audit_events TO %I',
        p_reconciler_role
    );
    EXECUTE format(
        'GRANT UPDATE (state, state_version, attempt_count, lease_fence, '
        'lease_owner, lease_token_digest, leased_at, lease_expires_at, '
        'retry_at, applied_at, applied_configuration_digest, '
        'target_receipt_digest, failed_at, failure_digest) '
        'ON control_assurance.deployment_operations TO %I',
        p_reconciler_role
    );

    EXECUTE format(
        'GRANT USAGE ON SCHEMA control_assurance_auth TO %I',
        p_auth_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION '
        'control_assurance_auth.runtime_identity(), '
        'control_assurance_auth.reserve_login_admission('
        'text,text,timestamptz,integer,integer,integer,integer,integer), '
        'control_assurance_auth.finalize_login_admission('
        'text,text,text,bytea,text,text,timestamptz,timestamptz), '
        'control_assurance_auth.cancel_login_admission(text), '
        'control_assurance_auth.consume_ready_authorization_transaction('
        'text,timestamptz,integer,integer,integer), '
        'control_assurance_auth.create_browser_session('
        'text,text,text,bytea,timestamptz,timestamptz,integer), '
        'control_assurance_auth.read_browser_session(text,timestamptz), '
        'control_assurance_auth.revoke_browser_session(text) TO %I',
        p_auth_role
    );
END;
$function$;

-- Remove legacy/public ACLs before any v6 binding is installed.  This is
-- deliberately fail closed: old shared-role pods lose access at migration 6.
DO $revoke_managed_schema_grantees$
DECLARE
    grantee name;
BEGIN
    FOR grantee IN
        WITH managed_namespaces AS (
            SELECT namespace.oid
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname IN (
                'control_assurance',
                'control_assurance_auth',
                'control_assurance_boundary'
            )
        ),
        grantees AS (
            SELECT acl.grantee
            FROM pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    namespace.nspacl,
                    pg_catalog.acldefault('n', namespace.nspowner)
                )
            ) AS acl
            WHERE namespace.oid IN (SELECT oid FROM managed_namespaces)
            UNION
            SELECT acl.grantee
            FROM pg_catalog.pg_class AS relation
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    relation.relacl,
                    pg_catalog.acldefault(
                        CASE relation.relkind
                            WHEN 'S' THEN 'S'::"char"
                            ELSE 'r'::"char"
                        END,
                        relation.relowner
                    )
                )
            ) AS acl
            WHERE relation.relnamespace IN (
                SELECT oid FROM managed_namespaces
            )
            UNION
            SELECT acl.grantee
            FROM pg_catalog.pg_proc AS routine
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    routine.proacl,
                    pg_catalog.acldefault('f', routine.proowner)
                )
            ) AS acl
            WHERE routine.pronamespace IN (
                SELECT oid FROM managed_namespaces
            )
        )
        SELECT role.rolname
        FROM grantees
        JOIN pg_catalog.pg_roles AS role ON role.oid = grantees.grantee
        WHERE role.rolname <> current_user
    LOOP
        EXECUTE format(
            'REVOKE ALL ON SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            grantee
        );
        EXECUTE format(
            'REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            grantee
        );
        EXECUTE format(
            'REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            grantee
        );
        EXECUTE format(
            'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance, '
            'control_assurance_auth, control_assurance_boundary FROM %I',
            grantee
        );
    END LOOP;
END;
$revoke_managed_schema_grantees$;

REVOKE ALL ON SCHEMA control_assurance FROM PUBLIC;
REVOKE ALL ON SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON SCHEMA control_assurance_boundary FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_boundary FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_assurance_boundary FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_boundary FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_auth
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_auth
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_auth
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_boundary
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_boundary
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_assurance_boundary
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON FUNCTION
    control_assurance_boundary.configure_runtime_roles(text, name, name, name)
    FROM PUBLIC;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (1, 'immutable control-plane revisions, approvals, activation and audit')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (2, 'dedicated one-time OIDC transaction and opaque session state')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (3, 'durable fenced deployment outbox and exact application receipts')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (4, 'immutable deployment retry lineage')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (5, 'distributed bounded OIDC login admission before PKCE protection')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_assurance.schema_migrations (version, description)
VALUES (6, 'session-user tenant binding and separated runtime database roles')
ON CONFLICT (version) DO NOTHING;

DO $migration_check$
DECLARE
    installed_versions integer[];
BEGIN
    SELECT array_agg(version ORDER BY version)
    INTO installed_versions
    FROM control_assurance.schema_migrations;
    IF installed_versions <> ARRAY[1, 2, 3, 4, 5, 6] THEN
        RAISE EXCEPTION 'unsupported control-plane schema lineage';
    END IF;
END;
$migration_check$;

COMMIT;
