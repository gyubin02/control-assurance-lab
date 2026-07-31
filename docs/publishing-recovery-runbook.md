# Publishing recovery runbook

An execution that reached `publishing` with a bound execution identity may
already have called a source, signer, or custody system. A new database lease
does not prove that the old worker lost those credentials. The ordinary
runtime path therefore refuses to reclaim this state.

Publishing recovery is a separate authority path. It requires an exact
recovery request, a hard compute-fence attestation, a credential-drain
attestation, independently IdP-signed maker and checker actions, and a
short-lived recovery-authority authorization. The journal consumes that
authorization once and advances the old and successor attempts in one
PostgreSQL transaction.

## Database roles

Use three different identities. The worker and recovery credentials are
dedicated LOGIN roles. The migration owner is authenticated directly only by
the deployment process while installing and provisioning the schema; an
application credential cannot invoke its provisioning functions.

Install the journal only in a database whose `server_encoding` is `UTF8`. The
schema rejects `SQL_ASCII` and other encodings because canonical recovery
documents are parsed and retained as exact UTF-8 bytes.

Migration 5 changes the append-only recovery record from the former
final-authority-only actor facts to independently signed maker/checker
artifacts. The installer deliberately refuses an old migration-4 table shape.
Archive and verify any retained v1 rows under the former trust policy, then
perform an explicit site migration; do not fill new signature columns with
invented values or relabel v1 bytes as v2.

Migration 6 binds each LOGIN credential to one tenant and one capability in
the owner-only `role_entitlements` table. RLS obtains the tenant from
`session_user`; `SET LOCAL control_assurance.tenant_id` no longer carries any
authority.

| Object | Migration owner | Runtime role | Recovery role |
| --- | --- | --- | --- |
| Schema | owner | `USAGE` | `USAGE` |
| `schema_migrations` | owner | `SELECT` | `SELECT` |
| `executions` | owner | `SELECT, INSERT, UPDATE` | `SELECT` |
| `execution_attempts` | owner | `SELECT, INSERT, UPDATE` | `SELECT` |
| Recovery authorizations | owner | none | none |
| Recovery function | owner | none | `EXECUTE` |

The runtime and recovery roles must be separate login roles with
`NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`, and
`NOREPLICATION`. They must have `NOINHERIT` and no role membership at all.
The recovery service uses its own connection pool; an ordinary worker must
never receive that DSN or the recovery role.

After installing `deploy/postgres/execution-journal-schema.sql`, authenticate
directly as the database, schema, and function migration owner. Create the
application roles and let the owner-only function write each insert-once
entitlement and converge its exact grants:

```sql
BEGIN;

CREATE ROLE control_assurance_execution_worker
  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION;
CREATE ROLE control_assurance_execution_recovery
  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION;

SELECT control_assurance_execution.configure_login_role(
  'bank-prod', 'control_assurance_execution_worker', 'worker'
);
SELECT control_assurance_execution.configure_login_role(
  'bank-prod', 'control_assurance_execution_recovery', 'recovery'
);

COMMIT;
```

The grants above are an exact matrix. Admission rejects missing or additional
table/routine privileges as well as `SUPERUSER`, `BYPASSRLS`, database
temporary/create permission, schema creation, role settings or membership,
object ownership, cross-store entitlements or ACLs, and a difference between
`current_user` and `session_user`. The worker never receives the recovery
function. The recovery role receives that function but no direct DML on the
authorization table.

Do not grant direct DML on `publishing_recovery_authorizations`. The
`SECURITY DEFINER` function is the only write path. It retains the exact
canonical request intent, maker action, checker action, fence, drain, final
authorization, every independently signed envelope, and the use claim before
performing the exact compare-and-swap.

PostgreSQL does not verify the Ed25519 signatures. The recovery service must
verify the pinned final, compute-fence, credential-drain, maker-IdP, and
checker-IdP keys immediately before it invokes the function. It must also
enforce the pinned actor audience and separate maker/checker issuer IDs. Its
database credential is consequently part of the recovery trusted computing
base.

## Recovery procedure

1. Stop automatic retries for the affected run. Record the tenant, run,
   control, plan, execution identity, old fence, worker, token digest,
   revision, and `publishing_at` value from the journal.
2. Fence the old workload. The selected hard-fence method must establish the
   condition required by the signed compute-fence record.
3. Query the PAM lifecycle records for every source, signing, and custody
   request bound to the execution. Wait until the signed drain boundary is
   reached.
4. Have the maker create the exact old-attempt/successor/PAM-scope intent and
   sign that action through the pinned maker IdP. A different checker reviews
   the fence and drain evidence, then signs the exact approval intent through
   the separately pinned checker IdP.
5. Sign a short-lived, single-use authorization with the dedicated recovery
   authority. Keep final, fence, drain, maker-IdP, and checker-IdP verification
   keys independently pinned.
6. Build `PublishingRecoveryJournalExpectation` from the durable journal
   fields and the authorized successor claim. Call
   `PostgresExecutionJournal.recover_identity_bound_publication` through the
   dedicated recovery-role pool.
7. Confirm that the old attempt is `uncertain` with
   `recovery-superseded`, the successor is the exact authorized
   `publishing` attempt, and one append-only authorization row exists.

Never edit the old attempt, advance the logical fence, or insert the successor
with direct SQL. Those three writes and authorization consumption must commit
together.

## Failure handling

- A conflict before consumption means the signed authorization, expected
  journal tuple, current state, or replay status did not match. Re-read the
  run and investigate; do not alter the signed document.
- An outcome-unknown error means the database call may have committed. Re-read
  the run by tenant and run ID and have an auditor inspect the authorization
  ID before any retry. Do not issue a second successor claim merely to make the
  error disappear.
- A consumed authorization is never reusable, including after the successor
  begins publishing.
- Key rotation must keep verification material pinned for still-valid
  authorizations and retained audit records. Rotation is not permission to
  rewrite stored recovery bytes.

Audit access to the authorization table should use a separate read-only
auditor role. The recovery service itself does not need that table privilege.
