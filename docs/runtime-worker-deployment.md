# Runtime worker deployment runbook

This runbook turns the runtime catalog, execution journal, exact execution
environment provider, and tenant worker into one Kubernetes service boundary.
It is intentionally split into two identities:

- the one-shot **profile registrar** may append exact, immutable control
  profiles; and
- the long-running **runtime worker** may read profiles and operate scheduled
  runs, but it must not have profile-write privilege.

The manifests are a hardened reference, not a claim that placeholder endpoints
or identity identifiers are production values. Every example image is pinned
by digest, but the all-zero application digest and all-one Vault digest must be
replaced with digests from the organization's admitted image registry.

## Deployment assets

| Asset | Purpose |
|---|---|
| `deploy/kubernetes/profile-release.example.yaml` | Immutable manifest and canonical profile ConfigMap |
| `deploy/kubernetes/profile-registration-manifest.example.json` | Strict, secret-free registrar input |
| `deploy/kubernetes/profile-registrar-job.yaml` | One-shot registrar with a separate database identity |
| `deploy/kubernetes/runtime-worker-config.example.json` | Strict, secret-free worker input |
| `deploy/kubernetes/runtime-release.example.yaml` | Immutable worker configuration ConfigMap |
| `deploy/kubernetes/runtime-worker.yaml` | Two workers, native Vault sidecar, RWX work volume, probes, Service, and PDB |

The example profile is stored in `binaryData`, not a YAML text block. It
therefore mounts as canonical JSON with no trailing newline. Its exact digest
is:

```text
sha256:1f5520f8a2947a96311085303c9063210ed099252a30a08ee773145123013c86
```

The example profile registration manifest has canonical digest:

```text
sha256:e298279144319a96e9284783de26664bb39b503ca2bf0e88d00bd817fa4b8e77
```

The shipped worker example has canonical digest:

```text
sha256:b704eef000feda61016990c6f0454eb749f5cc5f1b1e433509f5d282fc0d3748
```

Those last two values change whenever their inputs change. They are examples,
not reusable release pins.

## Prerequisites

Before a rollout, require all of the following:

1. Kubernetes 1.29 or later with native sidecar containers enabled. The Vault
   Agent is an init container with `restartPolicy: Always`; this gives startup
   ordering and lets the application drain before kubelet terminates the
   token agent.
2. At least two schedulable worker nodes. Required hostname anti-affinity
   deliberately leaves one replica Pending on a single-node cluster.
3. A `ReadWriteMany` volume implementation with stable POSIX ownership,
   regular-file semantics, atomic rename, and immediate cross-node
   visibility. Object-store FUSE and node-local `hostPath` are not acceptable.
4. PostgreSQL primary endpoints for the runtime catalog, execution journal,
   and PAM journal. A migration identity—not either runtime identity—must own
   the schemas.
5. Vault Kubernetes authentication configured for the exact ServiceAccount
   subject and `vault` token audience.
6. Azure workload federation for the exact issuer and subject in the worker
   configuration, plus AWS web-identity trust for the explicit
   `sts.amazonaws.com` ServiceAccount token.
7. The exact Cilium/site-perimeter prerequisites and site egress contract in
   `docs/control-plane-deployment.md`. The contract must cover the three
   PostgreSQL endpoints, Elastic, Azure identity and Key Vault endpoints, AWS
   STS/S3/KMS, Vault, and their exact DNS names/CIDR/ports.

The manifests do not grant Kubernetes API access and set
`automountServiceAccountToken: false`. Azure, AWS, and Vault assertions are
separate, explicit projected volumes with distinct audiences.

## Release contract and pre-apply work

The numbered sections below are review and provisioning order, not a phased
Kubernetes apply. The renderer emits one locked manifest stream containing the
profile Job, worker, reconciler, control plane, public ConfigMaps, and network
policy. This repository does not implement a controller that safely applies
selected phases of that stream.

All configuration and public trust material is released by
`scripts/render-kubernetes-release.py`; the source manifests are not directly
deployable. Prepare the exact seven-file public-input tree and a production
site egress contract documented in `docs/control-plane-deployment.md`, then
render one release:

```bash
python3 scripts/render-kubernetes-release.py render \
  --public-input-dir "$PWD/release-public-inputs" \
  --site-egress-contract "$PWD/site-egress-contract.json" \
  --output-dir build/kubernetes-release \
  --application-image \
    'registry.example.com/security/control-assurance-lab@sha256:<real-digest>' \
  --vault-image 'hashicorp/vault@sha256:<real-digest>'
```

The renderer injects the observed public-file digests into canonical
control/runtime/profile configuration, creates immutable content-addressed
ConfigMaps, patches every workload reference and digest environment variable,
and records all of those bindings in release-lock v3. The same lock also binds
the canonical site contract, full-digest workload selectors, and generated
Cilium network/egress-gateway policies. Keep the printed lock
digest in a separately protected approval record. Before any apply, verify the
release against that external value:

```bash
python3 scripts/render-kubernetes-release.py verify \
  --release-dir build/kubernetes-release \
  --expected-lock-digest 'sha256:<approved-lock-digest>'
```

This form performs the complete verification and prints a bounded success
message. The final apply command below adds `--emit-manifests`; only that form
writes the exact verified manifest bytes to stdout. Do not regenerate
ConfigMaps with `kubectl create`, substitute environment variables afterward,
or approve a lock digest calculated from an unreviewed changed release.
Provision the external Secrets listed in
[`control-plane-deployment.md`](control-plane-deployment.md) before the final
verify-and-apply.

### Pre-apply 1: admit immutable images

Build the `runtime-worker` optional dependency set, scan and sign the image,
then replace every application image placeholder in both workload manifests
with the same admitted digest. Replace the Vault image placeholder with a
separately admitted Vault Agent digest.

The application image must contain the `assurance-runtime-worker` console
entry point and a POSIX shell for the small trust-materialization init
container. Do not use a mutable tag beside the digest.

### Pre-apply 2: apply database schemas as the migration owner

Apply these files to the intended databases before either application
identity is enabled:

```text
deploy/postgres/runtime-schema.sql            -> schema version 3
deploy/postgres/execution-journal-schema.sql  -> schema version 6
deploy/postgres/pam-journal-schema.sql        -> schema version 3
```

Schema ownership stays with the directly authenticated migration role. Create
three distinct runtime-catalog LOGIN roles for the worker, profile registrar,
and deployment reconciler. Create separate execution-worker and PAM-broker
roles in their own databases. All five credentials and their DSNs are distinct;
a credential may not be reused across stores or capabilities. Each role must
be `NOINHERIT`, have no role membership, no per-role settings, no database
temporary/create permission, and no object ownership.

Use the owner-only provisioning functions instead of maintaining hand-written
grants. They write the server-side tenant entitlement and converge the exact
role matrix:

```sql
SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'control_assurance_runtime_worker', 'worker'
);
SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'control_assurance_runtime_registrar', 'registrar'
);
SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'assurance_runtime_reconciler', 'reconciler'
);
SELECT control_assurance_execution.configure_login_role(
  'bank-prod', 'control_assurance_execution_worker', 'worker'
);
SELECT control_assurance_pam.configure_login_role(
  'bank-prod', 'control_assurance_pam_broker', 'broker'
);
```

The registrar can append immutable profiles but cannot update or delete them.
The runtime worker can only read profiles. Explicitly verify:

```sql
SELECT
  has_table_privilege(
    'control_assurance_runtime_worker',
    'control_assurance_runtime.control_profiles',
    'INSERT'
  ) AS worker_can_insert_profile,
  has_table_privilege(
    'control_assurance_runtime_registrar',
    'control_assurance_runtime.control_profiles',
    'INSERT'
  ) AS registrar_can_insert_profile;
```

The required result is `false, true`. Use separate roles for the execution
journal and PAM journal; this is mandatory, not platform-dependent. The
worker receives `RUNTIME_DATABASE_DSN`, `EXECUTION_DATABASE_DSN`, and
`PAM_DATABASE_DSN` because those stores are separate authority and failure
boundaries. The config names the corresponding roles in `runtime_role`,
`execution_journal_role`, and `pam_journal_role`; startup checks the database
authenticated `session_user` against each exact name and server entitlement.

Before starting a PAM broker, register every derived journal namespace as the
migration owner. Namespace rows are insert-once and the broker can ask only
whether a digest belongs to its own tenant; it cannot reverse another digest
to a tenant name. Generate the plan from the same digest-pinned configuration
that will be mounted in the worker:

```bash
ASSURANCE_RUNTIME_CONFIG_DIGEST='sha256:<approved-config-digest>' \
  assurance-runtime-worker pam-namespace-plan \
    --config /etc/control-assurance/runtime-worker.json
```

The command is read-only, resolves no DSN or credential, emits one canonical
JSON line per distinct source, and includes the exact digest, tenant, purpose,
source kind, and source-configuration digest. Review that line and use its
values in the owner session:

```sql
SELECT control_assurance_pam.configure_journal_namespace(
  'sha256:<64 lowercase hex characters>',
  'bank-prod',
  'elastic-jit-api-key'
);
```

### Pre-apply 3: freeze the profile release

Edit the profile and registration manifest as release artifacts. Validate the
manifest through the same strict parser used by the Job:

```bash
assurance-runtime-worker profile-manifest-digest \
  --manifest "$PWD/deploy/kubernetes/profile-registration-manifest.example.json"
```

Generate a new immutable ConfigMap name when the manifest changes. The example
`profile-release.example.yaml` already carries the exact canonical profile as
base64 `binaryData`. Verify the decoded artifact before applying it:

```bash
python - <<'PY'
import base64
import hashlib
from pathlib import Path

import yaml

document = yaml.safe_load(
    Path("deploy/kubernetes/profile-release.example.yaml").read_bytes()
)
value = base64.b64decode(
    document["binaryData"]["elastic-high-severity-alerts-v1.json"],
    validate=True,
)
print("sha256:" + hashlib.sha256(value).hexdigest())
PY
```

Create the namespace and registrar database Secret before the final release.
The profile/configuration and CA ConfigMaps come only from the verified
rendered release; do not recreate them manually:

```bash
kubectl create namespace control-assurance --dry-run=client -o yaml \
  | kubectl apply -f -
```

Provision these Secrets through the organization's secret controller or
encrypted deployment system; do not commit them and do not put passwords in
shell arguments:

| Secret | Key | Required value |
|---|---|---|
| `control-assurance-profile-registrar-database` | `runtime-dsn` | Registrar-only PostgreSQL DSN |

The Job name is derived from the full registration-manifest digest during
rendering. Do not copy a name from this example into automation. After the
single final apply, select it by its component label:

```bash
kubectl -n control-assurance wait \
  --for=condition=complete \
  job -l app.kubernetes.io/component=profile-registrar \
  --timeout=10m
kubectl -n control-assurance logs \
  -l app.kubernetes.io/component=profile-registrar
```

The output contains only profile IDs and digests. A failed Job has
`backoffLimit: 0`; investigate instead of creating an uncontrolled retry loop.
Registering identical profile bytes is idempotent. On an upgrade, remove or
exclude completed old Jobs before using the broad label selector above, and
read the new exact name from the reviewed rendered manifest.

### Pre-apply 4: pin the runtime configuration

Replace every `.example.invalid`, cloud identifier, bucket, key, source
revision, and retention value. The
`custody_runtime.expected_profile_digest` is the digest of the exact live
S3/KMS/Vault deployment profile. It cannot be guessed offline.

Use a two-pass, read-only onboarding run:

1. Leave a syntactically valid placeholder in
   `expected_profile_digest`, calculate the first-pass config digest, and pin
   that digest in the observer environment.
2. In an operator-supplied reconciliation Pod, use the admitted application image,
   runtime ConfigMap, AWS web-identity projection, Vault Agent token sink, and
   copied Vault CA from `runtime-worker.yaml`. Do **not** give this Pod any of
   the three database Secrets. Run:

   ```bash
   ASSURANCE_RUNTIME_CONFIG_DIGEST='sha256:<first-pass-config-digest>' \
     assurance-runtime-worker custody-profile-digests \
     --config /etc/control-assurance/runtime-worker.json \
     > /tmp/custody-profile-observation.jsonl
   ```

   The repository does not ship or apply this observer Pod. Its manifest,
   admission and cleanup remain operator-owned. The command itself inspects
   only public S3 Object Lock/KMS and Vault Transit
   identities. It emits canonical JSONL containing the observed public
   profile, `profile_digest`, the configured expected digest, and
   `matches_expected`. With a placeholder it deliberately exits nonzero with
   `runtime-worker-custody-profile-drift` **after** writing the observation.
   Treat that first nonzero exit as expected only when the JSONL is complete
   and independently retained as a release-review artifact.
3. Review the observed bucket owner, bucket and KMS ARNs, encryption and
   retention bounds, Vault mount/key identity, and public signing-key
   fingerprint. Copy only the reviewed `profile_digest` into
   `expected_profile_digest`.
4. Put the reviewed digest in the source configuration, render and approve a
   new release, then rerun the same command against those final configuration
   bytes. It must report `"matches_expected":true` and exit 0 before the
   verified stream is applied.

Do not use the first-pass placeholder ConfigMap for a worker Deployment.
Discovery is not trust-on-first-use: the command reveals what the endpoints
say, while an operator or policy gate decides whether those identities are the
approved ones. Worker startup performs the same comparison and fails closed
on later drift.

Calculate each canonical config digest with:

```bash
assurance-runtime-worker config-digest \
  --config "$PWD/deploy/kubernetes/runtime-worker-config.example.json"
```

The renderer names the immutable runtime ConfigMap from that digest and places
the exact full digest directly in the verified workload. Do not rename or
update that ConfigMap after rendering.

Provision the runtime Secrets with these exact keys:

| Secret | Key |
|---|---|
| `control-assurance-runtime-database` | `runtime-dsn` |
| `control-assurance-runtime-database` | `execution-journal-dsn` |
| `control-assurance-runtime-database` | `pam-journal-dsn` |
| `control-assurance-runtime-release-pins-<runtime-config-digest-prefix>` | `worker-credential-digest` |
| `control-assurance-runtime-release-pins-<runtime-config-digest-prefix>` | `source-revision` |

Set both Secrets `immutable: true`. `worker-credential-digest` is a public
SHA-256 identity anchor for the admitted worker credential, not the credential
itself. `source-revision` must be an immutable 40-character Git commit or OCI
digest.

Every PostgreSQL DSN, including the registrar DSN, must explicitly contain:

```text
sslmode=verify-full
sslrootcert=/trust/runtime/postgres-ca.pem
target_session_attrs=read-write
```

It must also name an explicit hostname that the certificate covers. The
worker rejects `sslmode=require`, service-file indirection, a relative or
symlinked root certificate, and primary/standby ambiguity. Keep the DSN in the
Secret; it may contain a password.

### Final apply: start the release

Replace `replace-with-rwx-storage-class` in the source before rendering. Before
the only apply, verify that the class supports the required RWX semantics, all
external Secrets exist, the schemas and role bindings pass preflight, custody
identity has been approved, and no older pending deployment operation can race
profile registration.

```bash
set -o pipefail
python3 scripts/render-kubernetes-release.py verify \
  --release-dir build/kubernetes-release \
  --expected-lock-digest 'sha256:<approved-lock-digest>' \
  --emit-manifests |
  kubectl apply --server-side -f -

kubectl -n control-assurance wait \
  --for=condition=complete \
  job -l app.kubernetes.io/component=profile-registrar \
  --timeout=10m
kubectl -n control-assurance rollout status \
  deployment/control-assurance-runtime-worker \
  --timeout=15m
```

The Job and Deployments are created by the same apply. There is no hidden
profile-first apply. Missing profile, database privilege, trust material, or
custody identity must stop registration, readiness, or deployment application
without broadening a credential. For a first deployment, do not approve a
control revision until the profile Job is complete. For an upgrade, register
new profiles before any human creates desired state that references them.

The trust init container copies projected ConfigMap inputs into a pod-local
`emptyDir`, owned by UID/GID 10000, with a `0500` parent and `0400` files. This is
not cosmetic: Kubernetes ConfigMap files are atomic-writer symlinks, while the
Elastic and PostgreSQL trust boundaries require a direct, single-link,
owner-controlled file.

The shared-work init container creates or reopens a volume marker before the
worker starts. Both replicas must see the same marker and the same files.
Changing `volume_id` is a storage migration, not an ordinary rollout.

## Identity and token rotation

- **Azure:** the worker reads the `api://AzureADTokenExchange` projected token
  at point of use. Issuer and subject are exact configuration fields. No Azure
  CLI login or client secret is accepted.
- **AWS:** boto3 receives only `AWS_ROLE_ARN` and the explicit projected
  `AWS_WEB_IDENTITY_TOKEN_FILE`. IMDS is disabled and the manifest points
  shared credential/config files at `/dev/null`. Never add
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN`; startup
  rejects them.
- **Vault:** Vault Agent authenticates with its own `vault`-audience projected
  token, renews the Vault token, and writes a `0400` token to a memory-backed
  volume. The worker reopens that bounded file for signing calls. If the agent
  cannot obtain the first token, its startup probe prevents the application
  from starting. During termination, native-sidecar ordering leaves the agent
  alive while the worker drains.

Rotate a CA, identity, Vault role, or release pin by creating new immutable
objects and a new Deployment revision. Do not overwrite files underneath a
ready worker.

## Health, shutdown, and availability

`/livez` answers whether the service process is alive. `/readyz` becomes 200
only after exact configuration validation, database schema/TLS preflight,
source identity preparation, custody profile verification, shared-volume
validation, and worker-loop startup. It returns 503 during startup and drain.

Readiness is not an evidence freshness SLO and does not prove that every
queued run is progressing. Monitor durable catalog/journal state and alert on
run age separately.

Kubernetes sends SIGTERM to the worker, which flips readiness to 503 and
allows the current `run_once()` call to return before resources close. The
manifest provides a 900-second termination grace period. Set this above the
maximum admitted connector and publication deadline; a shorter platform
deadline turns a drain into a crash.

Two replicas, database fencing, node anti-affinity, a PDB, and a shared durable
work root protect ordinary pod and node loss. They do **not** justify a claim
of complete crash recovery. The current publication journal fails closed:
after publication identity has been durably bound, a SIGKILL before completion
can leave the run requiring operator reconciliation rather than allowing a
higher-fence worker to publish again. This avoids duplicate or contradictory
evidence, but it is an availability boundary.

For that condition:

1. preserve the execution journal and shared work directory;
2. capture the run ID, lease fence, publication identity, custody object
   identity, and receipt state;
3. compare the durable S3 Object Lock object and Vault-backed receipt with the
   journal; and
4. use an approved reconciliation procedure before rescheduling.

Do not delete the journal row, erase the work directory, or blindly retry.
Until an automated reconciler is shipped and exercised, operators must keep
this failure mode in the runbook and on-call alerts.

## Rollout checks

At minimum, gate a production rollout on:

```bash
kubectl -n control-assurance get pods,pvc,pdb
kubectl -n control-assurance get endpoints \
  control-assurance-runtime-worker-health
kubectl -n control-assurance exec \
  deploy/control-assurance-runtime-worker \
  -c runtime-worker -- \
  python -c 'import os; print(os.path.exists("/var/lib/control-assurance/work/.control-assurance-shared-work-root-v1"))'
```

Also verify:

- both replicas are on different nodes and see the same work-root volume ID;
- the worker database role cannot insert, update, or delete profiles;
- the registrar credential is absent from worker Pods;
- no static AWS credential environment variables exist;
- the three DSNs select a read-write primary with hostname-verified TLS;
- Vault token renewal survives longer than one token TTL;
- deleting one worker Pod does not interrupt the other;
- SIGTERM makes `/readyz` fail before the Pod exits; and
- the stuck-publication reconciliation alert is enabled.

The health Service remains cluster-internal. The checked-in base policy is
namespace default-deny; the release renderer requires an installation-specific
site contract and generates exact DNS-query, FQDN/port, and gateway-routing
policy. The accompanying site perimeter must deny every direct external
pod/node path, including an exact FQDN that resolves outside the contracted
CIDR envelope. Its v3 contract includes the exact pod/node source CIDRs,
allow-before-deny order, and an explicitly IPv4-only boundary: Cilium IPv6 and
external IPv6 egress at the perimeter must both be disabled. The live firewall
still requires separate operator evidence. Endpoint addresses are supplied by
the operator rather than fabricated in this repository.
