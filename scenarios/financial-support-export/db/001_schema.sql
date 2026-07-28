CREATE SCHEMA IF NOT EXISTS identity_store;
CREATE SCHEMA IF NOT EXISTS business;
CREATE SCHEMA IF NOT EXISTS audit_store;

CREATE TABLE identity_store.principals (
    principal_id text PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('support', 'compliance')),
    status text NOT NULL CHECK (status IN ('active', 'quarantined', 'disabled')),
    entitlement_version bigint NOT NULL CHECK (entitlement_version > 0)
);

CREATE TABLE identity_store.entitlements (
    entitlement_id uuid PRIMARY KEY,
    principal_id text NOT NULL REFERENCES identity_store.principals(principal_id),
    resource_type text NOT NULL CHECK (resource_type = 'customer'),
    scope_type text NOT NULL CHECK (scope_type IN ('customer_id', 'wildcard')),
    scope_value text NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    approved_by text NOT NULL,
    approval_ticket text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    CHECK (valid_until > valid_from),
    CHECK (
        (scope_type = 'wildcard' AND scope_value = '*')
        OR
        (scope_type = 'customer_id' AND scope_value LIKE 'SYNTH-CUSTOMER-%')
    )
);

CREATE TABLE identity_store.sessions (
    session_id uuid PRIMARY KEY,
    principal_id text NOT NULL REFERENCES identity_store.principals(principal_id),
    token_digest text NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text,
    CHECK (expires_at > issued_at),
    CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE TABLE identity_store.approved_entitlement_snapshots (
    snapshot_id uuid PRIMARY KEY,
    principal_id text NOT NULL REFERENCES identity_store.principals(principal_id),
    entitlement_version bigint NOT NULL CHECK (entitlement_version > 0),
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
    approved_by text NOT NULL,
    approved_at timestamptz NOT NULL,
    snapshot_document jsonb NOT NULL
);

CREATE TABLE business.customers (
    customer_id text PRIMARY KEY CHECK (customer_id LIKE 'SYNTH-CUSTOMER-%'),
    display_name text NOT NULL CHECK (display_name LIKE 'SYNTH-CUSTOMER-%'),
    email text NOT NULL CHECK (email LIKE '%@example.invalid'),
    customer_type text NOT NULL CHECK (customer_type IN ('person', 'organization')),
    region_code text NOT NULL CHECK (region_code LIKE 'LAB-%'),
    risk_tier text NOT NULL CHECK (risk_tier IN ('standard', 'review', 'heightened')),
    synthetic boolean NOT NULL CHECK (synthetic)
);

CREATE TABLE business.accounts (
    account_id text PRIMARY KEY CHECK (account_id LIKE 'LAB-ACCOUNT-%'),
    customer_id text NOT NULL REFERENCES business.customers(customer_id),
    product_code text NOT NULL CHECK (product_code LIKE 'LAB-%'),
    currency text NOT NULL CHECK (currency = 'LAB'),
    status text NOT NULL CHECK (status IN ('active', 'closed')),
    balance_minor bigint NOT NULL CHECK (balance_minor >= 0)
);

CREATE TABLE business.transactions (
    transaction_id text PRIMARY KEY CHECK (transaction_id LIKE 'LAB-TXN-%'),
    account_id text NOT NULL REFERENCES business.accounts(account_id),
    occurred_at timestamptz NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    direction text NOT NULL CHECK (direction IN ('credit', 'debit')),
    counterparty_token text NOT NULL CHECK (counterparty_token LIKE 'SYNTH-CP-%'),
    channel text NOT NULL CHECK (channel LIKE 'lab-%')
);

CREATE TABLE business.support_cases (
    case_id text PRIMARY KEY CHECK (case_id LIKE 'CASE-%'),
    customer_id text NOT NULL REFERENCES business.customers(customer_id),
    assigned_principal_id text NOT NULL
        REFERENCES identity_store.principals(principal_id),
    purpose text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'closed')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    CHECK (valid_until > valid_from)
);

CREATE TABLE business.release_approvals (
    approval_id uuid PRIMARY KEY,
    principal_id text NOT NULL REFERENCES identity_store.principals(principal_id),
    purpose text NOT NULL,
    customer_scope_digest text NOT NULL
        CHECK (customer_scope_digest ~ '^[a-f0-9]{64}$'),
    max_customers integer NOT NULL CHECK (max_customers > 0),
    max_records integer NOT NULL CHECK (max_records > 0),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    approved_by text NOT NULL,
    CHECK (valid_until > valid_from)
);

CREATE TABLE audit_store.data_access_audit (
    audit_id uuid PRIMARY KEY,
    trace_id text NOT NULL CHECK (trace_id ~ '^[a-f0-9]{32}$'),
    principal_id text NOT NULL,
    requested_customer_count integer NOT NULL CHECK (requested_customer_count >= 0),
    selected_customer_count integer NOT NULL CHECK (selected_customer_count >= 0),
    selected_record_count integer NOT NULL CHECK (selected_record_count >= 0),
    out_of_scope_record_count integer NOT NULL CHECK (out_of_scope_record_count >= 0),
    data_class text NOT NULL CHECK (data_class = 'customer_confidential'),
    occurred_at timestamptz NOT NULL,
    query_digest text NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$')
);

CREATE INDEX accounts_customer_idx ON business.accounts(customer_id);
CREATE INDEX transactions_account_time_idx
    ON business.transactions(account_id, occurred_at);
CREATE INDEX support_cases_principal_status_idx
    ON business.support_cases(assigned_principal_id, status);
CREATE INDEX data_access_audit_trace_idx ON audit_store.data_access_audit(trace_id);
