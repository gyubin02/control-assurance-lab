# 컨트롤 플레인 운영 배포

이 문서는 `assurance-control-plane`을 두 개의 웹 replica로 운영하는 기준을
정리한다. 개발용 로그인, 로컬 SQLite, client secret, Key Vault의 `latest`
별칭은 이 경로에 없다.

웹 프로세스가 직접 소유하는 것은 다음뿐이다.

- PostgreSQL의 승인·감사 상태와 일회용 OIDC 세션 상태
- Microsoft Entra authorization-code + PKCE 로그인 조정
- exact-version Key Vault key를 통한 PKCE envelope wrap/unwrap
- exact-version Key Vault key를 통한 OIDC `private_key_jwt` PS256 서명
- exact-version Key Vault secret에서 읽은 서버 CSRF key

승인된 설정을 런타임 카탈로그로 옮기는 작업은 웹 replica의 권한이 아니다.
`deployment_operations` outbox는 별도 `assurance-deployment-reconciler`가
소비한다. 웹 API의 `active` 표시는 승인된 배포 의도를 뜻하며, reconciler가
exact runtime receipt를 기록한 뒤에야 실제 적용이 완료된다.

## 배포 전에 필요한 것

1. 배포 tenant 하나만을 위한 PostgreSQL database를 만들고 그 database의
   owner를 전용 migration principal로 지정한다. 한 database에 여러 tenant를
   넣는 topology는 지원하지 않는다.
2. 서로 다른 `LOGIN NOINHERIT` role인 control, authentication, deployment
   reconciler role을 만든다. 세 role에는 superuser, `CREATEDB`,
   `CREATEROLE`, replication, `BYPASSRLS`, role setting, role membership,
   parameter `SET` ACL, object ownership, database `CREATE`/`TEMPORARY`, 어떤
   schema의 `CREATE`도 없어야 한다.
3. `deploy/postgres/control-plane-schema.sql`을 database owner와 동일한
   migration login으로 적용한 뒤, 같은 session identity로
   `control_assurance_boundary.configure_runtime_roles(...)`를 호출한다.
   schema 파일을 다시 적용하면 기존 runtime grant를 fail-closed로 제거하므로
   매번 configure 호출도 다시 실행한다.
4. PostgreSQL 서버 인증용 CA bundle을 준비한다.
5. OIDC issuer/JWKS 서버 인증용 CA bundle을 준비한다.
6. Key Vault private endpoint 또는 public endpoint 인증용 CA bundle을
   준비한다.
7. Entra OIDC client에 등록한 RSA certificate의 DER public certificate를
   준비한다. private key는 Key Vault 밖으로 내보내지 않는다.
8. Azure Workload Identity federated credential을 아래 exact subject와
   audience에 묶는다.

```text
subject  = system:serviceaccount:control-assurance:control-assurance-control-plane
audience = api://AzureADTokenExchange
```

Key Vault data-plane 권한은 용도별로 나눈다.

| 대상 | 필요한 작업 |
|---|---|
| PKCE wrapping key version | `keys/wrapKey`, `keys/unwrapKey` |
| OIDC client signing key version | `keys/sign` |
| CSRF secret version | `secrets/get` |

key create, rotate, delete, purge, certificate 관리, 다른 secret 읽기 권한은 웹
identity에 필요하지 않다.

예를 들어 privileged database administrator는 role과 database ownership만
준비하고, 실제 migration과 binding은 migration login으로 수행한다.

```sql
CREATE ROLE assurance_migration_owner
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE assurance_control_runtime
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE assurance_auth_runtime
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE assurance_reconciler_runtime
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
ALTER DATABASE assurance_acme OWNER TO assurance_migration_owner;
```

그 다음 `assurance_migration_owner`로 schema를 적용하고 다음 함수를 호출한다.
role 이름은 예시이며 tenant는 canonical deployment tenant여야 한다.

```sql
SELECT control_assurance_boundary.configure_runtime_roles(
  'acme-bank',
  'assurance_control_runtime'::name,
  'assurance_auth_runtime'::name,
  'assurance_reconciler_runtime'::name
);
```

configure 함수는 database가 이미 다른 tenant에 묶여 있으면 거부하고,
`PUBLIC`의 database `TEMPORARY`도 회수한다. migration owner는 database와
`control_assurance`, `control_assurance_auth`,
`control_assurance_boundary` 안의 모든 schema, relation, function을 정확히
소유해야 한다. 웹, auth, reconciler role에는 `CREATE`, `ALTER`, `DROP`,
ownership 또는 migration table 쓰기 권한을 주지 않는다. 각 프로세스는
schema와 privilege가 정확하지 않으면 시작을 거부할 뿐, 자동 migration이나
권한 승격을 시도하지 않는다.

## CSRF secret 형식

CSRF secret은 32~64 random bytes의 canonical base64url(패딩 없음)이다.
Key Vault secret의 content type은 정확히 다음 값이어야 한다.

```text
application/vnd.control-assurance.csrf-key+base64url
```

예를 들어 32 bytes를 생성할 때는 출력이 로그나 shell history에 남지 않도록
운영 secret 주입 절차 안에서 다음과 같은 변환을 한다.

```bash
openssl rand 32 | basenc --base64url | tr -d '='
```

설정에는 값이 아니라 다음 exact-version reference만 기록한다.

```text
azure-keyvault://<vault>/secrets/<name>/<32-hex-version>
```

## 설정 release 만들기

`deploy/kubernetes/control-plane-config.example.json`은 필드 구조 예시다.
그대로 배포하는 값이 아니다. 다음 항목을 환경의 실제 값으로 바꾼다.

- public origin, issuer, authorization/token/JWKS endpoint
- Entra tenant/client UUID와 AKS issuer
- 세 개 CA bundle의 SHA-256
- OIDC public certificate DER의 SHA-256
- 두 Key Vault key의 exact 32-hex version
- CSRF secret의 exact 32-hex version
- top-level deployment `tenant_id`; 모든 group entitlement의 `tenant_id`도 이
  값과 정확히 같아야 한다
- callback 전에 적용할 global/source별 OIDC login admission 한도와 reservation
  TTL; reverse proxy가 있다면 검토된 `trusted_proxy_cidrs`

파일 digest는 raw file bytes에 대해 계산한다.

```bash
sha256sum postgres-ca.pem oidc-ca.pem key-vault-ca.pem oidc-client.der
```

설정 자체의 canonical digest는 애플리케이션과 같은 parser로 계산한다.

```bash
assurance-control-plane config-digest \
  --config /absolute/path/control-plane.json
```

그 digest는 ConfigMap 내부에 자기 자신을 넣는 방식으로 보호하지 않는다.
renderer가 workload의 `ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST`에 exact value를
넣고 release lock이 설정 bytes, 환경변수, ConfigMap 이름을 함께 묶는다.
ConfigMap을 바꾸고 lock을 다시 승인하지 않으면 배포 검증이 실패하고, 실행
시점에 설정과 환경변수가 다르면 pod가 시작하지 않는다. JSON의 공백이나
줄바꿈은 digest에 영향을 주지 않지만, 파싱된 필드 값은 모두 canonical
model로 정규화한 뒤 digest를 계산한다.

## immutable manifest release

저장소의 workload manifest에는 의도적으로 배포 불가능한 image placeholder가
들어 있다. 애플리케이션은 64개의 `0`, Vault agent는 64개의 `1` digest를
사용한다. 이 파일을 직접 `kubectl apply`하는 절차는 지원하지 않는다.

`scripts/render-kubernetes-release.py`는 네 workload manifest,
`network-policies.yaml`, control/runtime/profile 설정, 공개 신뢰 파일과
site egress 계약을 한 release로 렌더한다. 애플리케이션 image와 Vault
image는 둘 다 tag가 없는
`repository@sha256:<64-hex>`여야 하며, placeholder digest나 `example`
repository는 거부한다.

공개 입력 디렉터리는 아래 exact file set만 허용한다. 이 값들은 비밀이
아니지만 어떤 서버와 identity를 신뢰할지 결정하므로 release 승인 대상이다.
symlink, hard link, group/world-writable file, 빠진 파일과 여분 파일은 모두
거부한다.

```text
release-public-inputs/
├── control/
│   ├── postgres-ca.pem
│   ├── oidc-ca.pem
│   ├── key-vault-ca.pem
│   └── oidc-client.der
└── runtime/
    ├── postgres-ca.pem
    ├── elastic-ca.pem
    └── vault-ca.pem
```

```bash
APP_IMAGE='registry.example.com/security/control-assurance-lab@sha256:<real-digest>'
VAULT_IMAGE='hashicorp/vault@sha256:<real-digest>'
SITE_EGRESS_CONTRACT="$PWD/site-egress-contract.json"

LOCK_DIGEST="$(
  python3 scripts/render-kubernetes-release.py render \
    --public-input-dir "$PWD/release-public-inputs" \
    --site-egress-contract "${SITE_EGRESS_CONTRACT}" \
    --output-dir build/kubernetes-release \
    --application-image "${APP_IMAGE}" \
    --vault-image "${VAULT_IMAGE}"
)"
```

renderer는 설정 속 각 pinned path에 실제 입력의 SHA-256을 주입하고, canonical
설정과 실제 공개 바이트를 content-addressed immutable ConfigMap으로 만든다.
runtime/profile용 ConfigMap은 init container가 UID/GID 10000, mode `0400`인
single-link file로 materialize한다. control plane의 projected file은
root:2000, mode `0440` 정책과 맞는다.

`build/kubernetes-release/manifests/`와 canonical `release-lock.json`은
원자적으로 생성된다. lock v3에는 원본, 렌더된 각 manifest, control/runtime/
profile/site-egress 네 canonical configuration, 일곱 공개 입력, 두 image
identity의 digest가 들어간다.
ConfigMap 이름과 workload volume/env reference도 같은 content identity에서
계산된다. object 이름과 profile Job 이름에는 digest 앞 20 hex(80 bit)를
사용하고, metadata에는 전체 SHA-256 annotation과 전체 256 bit base32 label을
함께 기록한다. 짧은 8/12 hex 이름이나 label을 authority로 사용하지 않는다.
출력 디렉터리가 이미 있으면 덮어쓰지 않는다.

`LOCK_DIGEST`는 렌더 결과 안이 아니라 승인된 release metadata, 서명된
attestation 또는 배포 시스템의 protected variable에 보관한다. 배포 직전에
그 외부 값을 다시 넣어 검증한다.

```bash
set -o pipefail
python3 scripts/render-kubernetes-release.py verify \
  --release-dir build/kubernetes-release \
  --expected-lock-digest "${LOCK_DIGEST}" \
  --emit-manifests |
  kubectl apply --server-side -f -
```

verify는 file set, lock의 canonical encoding, 모든 file digest, 모든
container/initContainer image, ConfigMap immutability, 공개 입력
bytes↔configuration digest↔workload reference 연결과 site egress 계약으로
정확히 재생성한 Cilium 정책을 다시 확인한다. 잠금에 digest만 다시 맞춘
비정규 YAML도 거부한 뒤,
메모리에 보관한 바로 그 bytes를 stdout으로 내보낸다. 따라서 검증 뒤 경로를
다시 읽는 TOCTOU 창을 만들지 않는다. `pipefail`은 검증 실패를 빈 apply
성공으로 오인하지 않게 한다.
lock이나 manifest를 함께 바꾼 뒤 새 digest를 스스로 신뢰하는 절차는 검증이
아니다. CI와 production deployer는 승인 단계에서 전달받은 같은 외부
`LOCK_DIGEST`를 사용해야 한다. cluster admission도 mutable tag와 placeholder
digest를 별도로 거부한다.

## PostgreSQL DSN

control-plane pod는 같은 database endpoint를 가리키는 두 DSN과 두 독립
connection pool을 사용한다. `control_dsn`의 login은 정확히 configured
control role이어야 하고, `auth_dsn`의 login은 정확히 configured auth
role이어야 한다. 두 DSN이 같거나 role이 뒤바뀌거나 database endpoint가
다르면 시작을 거부한다. DSN은 Kubernetes Secret의 `control-dsn`과
`auth-dsn` key에서 환경변수로 주입하고, 설정 파일에는 환경변수 이름만
기록한다.

각 DSN은 최소한 다음 조건을 만족해야 한다.

```text
sslmode=verify-full
sslrootcert=/etc/control-assurance/trust/postgres-ca.pem
target_session_attrs=read-write
host=<certificate와 일치하는 primary endpoint>
dbname=<database>
user=<exact control role 또는 exact auth role>
```

libpq service file은 허용하지 않는다. `sslmode=require`도 허용하지 않는다.
암호화만 하고 서버 identity를 검증하지 않기 때문이다. 여러 HA host를 쓰면
각 host가 같은 CA 아래에서 각 hostname과 일치하는 certificate를 제공해야
한다.

## Kubernetes object 준비

release renderer가 생성하는 ConfigMap과 외부 secret delivery가 생성하는
Secret을 섞지 않는다. renderer가 소유하는 것은 control/runtime/profile
configuration, 일곱 공개 신뢰 파일, OIDC public certificate, site egress
계약과 그 digest binding이다. 이 ConfigMap은 모두 content-addressed이고
immutable이다. `kubectl create configmap`, Kustomize generator, Helm
templating으로 같은 이름을 다시 만들거나 렌더 뒤 내용을 바꾸면 안 된다.

아래 Secret만 renderer 바깥에서 먼저 준비한다. 값은 External Secrets,
sealed secret 또는 조직의 동등한 secret-delivery 경계로 주입한다. 명령행
`--from-literal`은 운영 절차가 아니다.

| Secret | 필요한 key |
|---|---|
| `control-assurance-control-plane-postgres` | `control-dsn`, `auth-dsn` |
| `control-assurance-deployment-reconciler-database` | `control-plane-dsn`, `runtime-catalog-dsn` |
| `control-assurance-deployment-reconciler-identity` | `worker-credential-digest` |
| `control-assurance-profile-registrar-database` | `runtime-dsn` |
| `control-assurance-runtime-database` | `runtime-dsn`, `execution-journal-dsn`, `pam-journal-dsn` |
| `control-assurance-runtime-release-pins-<runtime-config-digest-prefix>` | `worker-credential-digest`, `source-revision` |

마지막 이름의 prefix는 canonical runtime configuration SHA-256의 앞 20
hex다. 두 값은 credential 자체가 아니라 승인된 workload identity와 source의
공개 audit binding이다. Secret은 그래도 renderer가 참조하는 외부 object이므로
조직 정책으로 immutable하게 만들고 변경은 새 release identity로 수행한다.

적용 순서는 다음과 같다.

1. namespace와 위 External Secret resource를 만들고, 모든 Secret이 exact
   이름/key로 materialize됐는지 확인한다.
2. database schema/role, cloud workload identity, private endpoint와 perimeter
   route를 준비하고 preflight를 끝낸다.
3. 최종 source configuration과 공개 입력으로 release를 한 번 렌더하고, 출력된
   lock digest를 별도 승인 기록에 보관한다.
4. 외부 승인 digest로 `verify --emit-manifests`를 실행하고, 그 stdout bytes를
   한 번의 server-side apply로 전달한다.

renderer-owned ConfigMap이나 digest 값을 별도 명령으로 먼저 적용하는
"단계적 release"는 구현돼 있지 않다. Secret 누락, profile 미등록, database
권한 오류 또는 custody identity 불일치는 각 프로세스가 fail closed해야 하며,
그 전제조건을 우회하려고 verified stream 일부만 골라 적용하지 않는다.

manifest는 restricted pod security, read-only root filesystem, 모든 capability
제거, custom projected Azure token, 두 replica, node anti-affinity, zone spread,
PDB `minAvailable: 1`을 포함한다. Ingress는 포함하지 않는다. 조직의 TLS
termination 계층은 외부 HTTPS origin을 제공하고 원래 Host를 보존해야 한다.
애플리케이션은 `X-Forwarded-*`를 신뢰하지 않으며 public origin과 다른 Host를
거부한다.

base manifest에는 `Role`이나 `RoleBinding`도 없다. 웹, reconciler, runtime
프로세스는 Kubernetes API를 호출하지 않으며 ServiceAccount token 자동 mount도
꺼져 있다. Azure/AWS/Vault workload token은 필요한 workload에서 audience를
고정해 별도로 project한다. site overlay가 새로운 Kubernetes API 기능을
추가한다면 그때 필요한 resource와 verb만 별도 RBAC로 부여한다.

## deployment reconciler

`deploy/kubernetes/deployment-reconciler.yaml`은 다음 세 identity를 웹 및
runtime worker와 분리한다.

- control-plane outbox를 lease/ack/fail/read하는 DB role
- runtime catalog의 profile/current deployment/history를 쓰는 DB role
- audit event에 결합하는 reconciler worker identity digest

두 DB DSN은 각각 `sslmode=verify-full`,
`target_session_attrs=read-write`와 서로 맞는 CA 파일을 사용한다. database
DSN과 worker identity digest는 위 외부 Secret에서 오지만 두 CA와 그 digest는
renderer가 공개 입력에서 관측해 immutable trust ConfigMap과 workload
environment에 함께 묶는다. 별도의 CA ConfigMap이나 digest Secret을 수동으로
재생성하지 않는다.

`control-assurance-deployment-reconciler-identity`의
`worker-credential-digest`는 bearer secret이 아니라 승인된 workload
credential의 audit binding이다. 값 자체로 인증하지 않는다. Pod identity,
admission policy와 DB credential 전달 경계가 실제 workload authentication을
담당해야 한다.

release lock digest는 렌더 결과와 다른 승인 채널에서 와야 한다. CA bytes와
digest의 내부 연결은 renderer와 verifier가 확인하고, production deployer는
그 결과 전체를 out-of-band lock digest로 승인한다.
reconciler는 DSN을 파싱한 뒤 연결을 열기 전에 CA가 symlink가 아닌 단일
regular file인지, owner가 root 또는 process uid이고 mode가 정확히 `0400`인지,
size가 맞는지, 읽는 동안 inode와 metadata가
안정적인지, content SHA-256이 out-of-band digest와 같은지 확인한다. 두 DB
schema도 `max(version)`만 보지 않고 각각 정확히 `[1,2,3,4,5,6]`,
`[1,2,3]`인지
확인하므로 migration gap, extra version, downgrade를 모두 시작 실패로
처리한다.

reconciler는 runtime worker와 동일한 digest-pinned runtime release를 읽고,
그 release에 canonical bytes까지 정확히 등록된 configuration만 적용한다.
현재 production composition이 지원하는 범위도 시작 시 고정한다.

- Elastic Security 또는 Defender XDR의 정확히 일치하는 source/runtime
- 32-hex version이 포함된 canonical Azure Key Vault credential reference
- S3 Object Lock custody와 Vault Transit signing
- `legal_hold=false`

AWS/GCP/Vault secret reference, Key Vault `latest`, source/runtime mismatch,
지원하지 않는 custody 또는 `legal_hold=true`가 하나라도 있으면 reconciler는
시작하지 않는다. release에 없는 configuration을 outbox가 가리키면 해당
operation은 `runtime-release-registration-missing`으로 non-retryable 실패가
되며 applied receipt를 만들지 않는다.

두 replica는 active-active다. control-plane DB의 exact row claim/CAS,
`FOR UPDATE SKIP LOCKED`, lease token과 증가하는 fence를 통과한 한 replica만
adapter 호출을 시작한다. process가 target commit 뒤 acknowledgement 전에
죽으면 같은 operation ID와 더 높은 fence로 다시 호출될 수 있다. 따라서 이는
exactly-once network delivery가 아니다. runtime catalog target은 operation
ID를 idempotency key로 보관하고 이미 적용된 exact digest의 receipt를
돌려주며, 낮은 stale fence를 거부해 논리적 중복 적용을 막는다.

## 시작과 readiness

pod는 API socket을 서비스하기 전에 다음 preflight를 모두 통과한다.

1. protected file의 mount containment, owner/group/mode, 읽는 동안의 inode
   안정성, release digest
2. 두 PostgreSQL pool 모두 `verify-full` 연결과 실제 TLS 사용, DSN의
   `session_user`/`current_user`/`current_role` exact login 일치, deployment
   tenant 일치, control lineage `[1,2,3,4,5,6]`과 auth lineage `[2,5,6]`,
   exact migration owner, role posture와 object/column/function ACL의 정확한
   일치
3. PKCE test verifier의 Key Vault wrap + unwrap
4. PS256 test assertion의 Key Vault sign + local certificate verification
5. exact OIDC JWKS URI의 fresh fetch, bounded public JWK 구조

`/health/live`는 process event loop가 살아 있는지만 나타낸다.
`/health/ready`는 위 dependency 결과를 최대 5분 cache한다. cache가 만료된
첫 probe가 single-flight로 다시 검사한다. 즉 replica당 기본 5분마다
Key Vault `sign`, `wrap`, `unwrap`과 JWKS 조회가 발생한다. 이 비용과 감사
event 양을 수용할 수 없는 환경은 단순히 검사를 없애지 말고 검토된 interval로
설정을 바꾼다.

OIDC callback에는 일회용 authorization code가 들어오므로 Uvicorn access log는
항상 꺼져 있다. 애플리케이션 error는 upstream response body, token, DSN,
PKCE verifier를 출력하지 않고 안정적인 stage만 남긴다.

## 종료와 장애

SIGTERM을 받으면 Uvicorn이 새 요청 수락을 중단하고 최대 30초 동안 요청을
drain한다. FastAPI lifespan 종료에서 auth와 control PostgreSQL pool을 모두
닫는다.
`terminationGracePeriodSeconds`는 45초다.

대표적인 시작 실패는 stderr의 다음 stage로 구분한다.

| stage | 확인할 곳 |
|---|---|
| `public-file-digest` | ConfigMap/Secret byte와 release digest |
| `azure-workload-identity` | projected token owner, issuer, subject, audience |
| `csrf-key` | exact secret version, content type, base64url 길이 |
| `database-transport-policy` | DSN의 verify-full, CA path, primary selection |
| `database-trust` | reconciler CA의 0400 mode, stable inode, out-of-band digest |
| `database-role-boundary` | 두 DSN의 endpoint와 exact login role 분리 |
| `database-preflight` | TLS, tenant/role binding, lineage, owner, exact ACL/posture |
| `key-vault-preflight` | exact key version, RBAC, private DNS, certificate match |
| `oidc-jwks-preflight` | exact JWKS endpoint, TLS trust, public JWK document |

reconciler는 `/livez`, `/readyz`를 제공한다. SIGTERM 뒤 새 loop를 시작하지
않고 현재 한 번의 reconcile을 마친 후 health server와 두 DB pool을 닫는다.
두 replica 중 하나가 종료돼도 다른 replica가 만료되지 않은 operation과
pending operation을 계속 claim한다.

## PostgreSQL residual trust

이 경계는 PostgreSQL host와 cluster administrator, 전용 migration/database
owner, DSN이 가리키는 endpoint와 database, release-pinned TLS CA를 신뢰한다.
database owner나 administrator는 binding, RLS, function, ownership, ACL을
바꿀 수 있으므로 trusted computing base 밖으로 제거할 수 없다. migration
credential은 웹, auth, reconciler pod에 절대 전달하지 않는다.

startup과 readiness는 exact login identity, tenant binding, migration
lineage, owner, role attribute/setting/membership, parameter `SET` ACL, raw
schema/table/column/function ACL을 다시 확인한다. 그러나 검사 사이의
privilege 변조를 막는 것은 database administration과
admission/change-control의 책임이다. 연결 pooler를 쓰면 `session_user`를
다른 고객이나 role 사이에서 공유하거나 DSN login을 대리하는 모드를 사용하지
않는다.

## NetworkPolicy와 site egress 경계

`deploy/kubernetes/network-policies.yaml`은 namespace 전체 ingress/egress를
default-deny하고 필요한 ingress만 연다. 이 base manifest에는 DNS나 외부
egress 허용 규칙이 없다. site 계약 없이 source manifest만 적용하면
workload는 외부로 나갈 수 없어야 한다.

- control-plane 8080은 cluster-admin이 표시한 ingress client와 monitoring
  client에서만 받는다.
- reconciler/runtime health 8080은 표시된 monitoring client에서만 받는다.

namespace와 pod에 사용하는 신뢰 label은 일반 workload 작성자가 붙이지 못하게
admission/RBAC로 보호한다.

production render에는 schema
`control-assurance/site-egress-contract/v3`인 절대경로의 canonical
`--site-egress-contract`가 필수다. 이 파일은 symlink/hard link가 아닌
single-link regular file이어야 하고 group/world-writable이면 거부된다.
`deploy/kubernetes/site-egress-contract.example.json`은 구조만 보여 주며
`.invalid`, `replace-*`, `replace-me` 때문에 의도적으로 배포할 수 없다.

실제 계약은 다음 권한을 한 번에 승인한다.

- Cilium stable 1.20 profile과 아래의 exact feature 상태
- Cilium IPv6 비활성화와 외곽 장비의 IPv6 external egress 차단
- `kube-system` DNS pod의 exact namespace/label identity
- 네 workload별 lowercase exact FQDN/TCP port와 별도의 canonical IPv4
  gateway-routing CIDR envelope
- 서로 다른 두 개 이상의 gateway hostname과 explicit egress IP
- 그 gateway IP에서 계약 CIDR로 가는 traffic만 허용하고, workload pod IP와
  일반 node IP의 모든 direct external egress를 거부하는 site perimeter 변경
  기록
- 그 deny가 실제로 덮어야 할 canonical
  `direct_denied_pod_source_cidrs`와
  `direct_denied_node_source_cidrs`

CIDR은 `/24` 또는 그보다 좁아야 하며 가능하면 private endpoint의 `/28`이나
개별 `/32`를 쓴다. `0.0.0.0/0`, provider 전체 `/8`·`/16`, wildcard FQDN은
거부되고, 한 계약의 고유 destination CIDR도 최대 256개다. public provider의
IP가 바뀌면 자동으로 범위를 넓히는 대신 새 authoritative range로 계약을
다시 만들고 별도 lock digest를 승인한다.

direct-deny source CIDR은 destination CIDR과 규칙이 다르다. 실제 pod/node
주소 공간을 표현해야 하므로 canonical IPv4 unicast `/8`~`/32`를 허용하고,
pod와 node 각각 nonempty·최대 64개로 제한한다. 각 목록은 network address
순으로 정렬돼야 하며 중복이나 목록 안/사이의 overlap은 거부된다.

이 contract profile은 IPv4 전용이다. DNS 응답의 AAAA 주소가 IPv4
`destinationCIDRs`와 source CIDR 차단을 우회하지 않도록
`cilium.ipv6_enabled=false`와
`site_perimeter_enforcement.perimeter_ipv6_external_egress_disabled=true`를
둘 다 요구한다. dual-stack cluster를 이 profile로 승인하지 않는다.

renderer는 workload마다 `CiliumNetworkPolicy`를 생성한다. DNS는 계약에
있는 exact `matchName`만 계약에 고정한 kube-dns identity의 53번 포트로
허용한다. 실제 연결도 같은 workload의 exact `toFQDNs.matchName`과 TCP
port로 허용한다. wildcard DNS, `toCIDRSet` 연결 허용, base policy의 공용
DNS 허용은 사용하지 않는다.

cluster-scoped `CiliumEgressGatewayPolicy`는 namespace metadata를 갖지
않는다. 대신 selector에 `io.kubernetes.pod.namespace=control-assurance`,
workload identity와 계약 digest 전체 256 bit를 lowercase base32 52자로
넣는다. route 대상은 계약에 승인한 정적 CIDR의 정확한 합집합이고, 각
gateway는 exact node selector와 `egressIP`만 사용한다. `interface`와
`egressIP`를 함께 쓰는 Cilium 형식은 허용하지 않으며, 이 HA profile은
interface-only 선택도 지원하지 않고 explicit `egressIP`만 받는다. gateway
하나만 두는 계약도 거부된다.

FQDN 연결 정책과 정적 gateway-routing CIDR은 같은 release 계약에 묶이지만
서로 다른 계층이다.

- exact FQDN이 계약 CIDR 안의 주소로 resolve되면 CNP가 그 주소/port를
  허용하고 CEGP가 gateway로 보낸다.
- exact FQDN이 계약 CIDR 밖 주소로 resolve되면 CNP의 FQDN cache에는 들어갈
  수 있지만 CEGP route에는 들지 않는다. site perimeter가 pod/node의 모든
  direct external egress를 막으므로 이 traffic은 fail closed여야 한다.
- 계약 CIDR 안의 주소라도 exact FQDN DNS 관측으로 허용된 주소가 아니면
  CNP가 연결을 허용하지 않는다.

`toFQDNs`도 TLS/SNI를 검사하는 기능은 아니다. Cilium이 exact DNS 응답에서
관측한 IP를 endpoint별 cache에 넣어 L3 허용으로 바꾸므로, 같은 IP의 다른
virtual host를 구별하지 못하고 DNS 관측 뒤 그 IP를 직접 쓰는 연결까지
허용될 수 있다. DNS cache에서 주소가 만료되어도 이미 열린 connection은
종료될 때까지 유지될 수 있으므로 hostname/CIDR 제거를 즉시 session
revocation으로 간주하지 않는다. 그래서 private/dedicated endpoint를
우선하고 애플리케이션의 TLS hostname/certificate 검증을 그대로 유지한다.
release-lock은 FQDN과 CIDR을 같은 계약 bytes에 묶지만 Secret으로 주입되는
DSN이나 외부 endpoint 설정에서 hostname을 자동 추출해 계약 FQDN과
비교하지는 않는다. 운영 승인자는 각 주입값의 hostname이 계약과 일치하고
직접 IP 접속을 쓰지 않는지 별도로 검증해야 한다.

### Cilium과 site perimeter 선행조건

배포 전 live cluster에서 다음을 모두 확인한다. 계약 JSON의 선언이나
release verifier는 cluster의 실제 Cilium 설정을 대신 증명하지 않는다.
근거와 현재 제약은 Cilium의
[Egress Gateway 문서](https://docs.cilium.io/en/stable/network/egress-gateway/egress-gateway/)
및
[L7 DNS policy 문서](https://docs.cilium.io/en/stable/security/policy/layer7/#dns-policy-and-ip-discovery)를
배포 시점의 pinned Cilium version과 대조한다.

- Cilium stable 1.20 이상과 Egress Gateway 기능 활성화
- BPF masquerading, kube-proxy replacement와 L7 proxy 활성화
- Cilium IPv6 비활성화와 site perimeter의 IPv6 external egress 차단
- `enable-lockdown-endpoint-on-policy-overflow=true`; policy map overflow 시
  endpoint 전체를 fail-closed lockdown하고 관련 pressure/lockdown metric을
  경보함
- identity allocation mode `crd`
- `app.kubernetes.io/name`, `app.kubernetes.io/component`,
  `control-assurance.io/egress-contract`,
  `io.kubernetes.pod.namespace`가 Cilium security identity에서 제외되지 않음
- 각 exact hostname selector가 실제 node 하나를 고르고, 계약의 `egressIP`가
  그 node의 network device에 할당돼 있으며 해당 device를 Cilium이 관리함
- Cluster Mesh 비활성화
- CiliumEndpointSlice 비활성화

Cilium Egress Gateway policy는 새 pod가 생긴 직후 identity가 전달될 때까지
짧은 적용 지연이 있을 수 있다. 그래서 site perimeter는 계약의 gateway
egress IP에서 계약 destination CIDR로 가는 exact allow exception을 먼저
적용한다. 그 다음 같은 gateway source가 계약 CIDR 밖으로 가는 traffic을
거부하고, 계약의 pod/node source CIDR에서 시작하는 모든 direct external
egress를 거부한다. gateway egress IP가 node source CIDR 안에 있을 수 있으므로
이 순서는 의미의 일부이며
`gateway_allow_exception_precedes_direct_deny=true`로 고정한다. 이 항목은
public Entra/SaaS가 호출자 source IP를 제한한다는 주장이 아니다. cluster
바깥의 조직 firewall/router가 초기 적용 지연과 DNS-outside-CIDR 경로를
모두 닫는 조건이며,
계약의 `deny_all_direct_external_pod_and_node_egress`는 반드시 `true`다.
`site_perimeter_enforcement.change_reference`는 그 실제 변경의 승인 기록을
가리킨다.
renderer는 source CIDR의 문법·정렬·중복·overlap·개수와 이 ordered
declaration이 release bytes에 묶였는지만 검증한다. change reference가
가리키는 live firewall rule의 존재, 순서, 실제 pod/node 주소 coverage는
증명하지 않으며 배포 전 별도 evidence로 확인해야 한다.
이 profile은 perimeter enforcement point가 추가 SNAT 전에 Cilium
`egressIP`와 pod/node source IP를 직접 구분할 수 있다고 전제한다. cloud NAT
등이 먼저 source를 바꾸는 topology라면 이 계약으로 검증됐다고 표시하지
말고, post-NAT identity까지 표현하는 별도 profile을 만들어야 한다.

두 gateway node와 egress IP는 서로 다른 failure domain에 두고, downstream
route와 firewall에 둘 다 준비한다. 여러 gateway를 써도 endpoint 하나는
CiliumEndpoint UID에 따라 그중 하나만 사용한다. gateway node 집합이 바뀌면
endpoint가 재할당되며 기존 TCP 연결은 끊길 수 있다. 따라서 이를 무중단
active-active session 보장이라고 부르지 않으며, readiness와 client retry가
재연결을 감당해야 한다.

정책과 perimeter 검증을 먼저 끝낸 뒤 같은 release의 workload를 배포한다.
계약을 바꿀 때는 새 content-addressed ConfigMap/CNP/CEGP와 workload selector를
한 release로 적용하고, 새 pod가 ready이며 새 gateway source가 관측된 뒤 이전
계약 object를 제거한다. 장애 대응으로 `0.0.0.0/0`을 여는 배포는 production
promotion 대상이 아니다.

## 회전 순서

PKCE envelope는 생성 당시의 exact key version을 database row에 기록하지만
현재 process는 한 번에 한 unwrap key version만 연다. 따라서 PKCE key 회전은
로그인 유입을 잠시 막고, 최대 authorization transaction TTL(기본 5분,
상한 15분)이 지난 뒤 새 version으로 전체 replica를 교체한다. 이전 version은
burn retention까지 `unwrapKey` 권한을 유지한다. alias로 이 drain 절차를
우회하지 않는다.

OIDC signing key는 새 Key Vault version과 matching Entra certificate를 먼저
등록하고 replica를 교체한 다음, old assertion 최대 lifetime이 지난 뒤 이전
certificate와 `sign` 권한을 제거한다.

CSRF key 회전은 기존 page의 mutation token을 무효화한다. 읽기 session 자체는
남지만 사용자는 page를 새로 열어 새 CSRF token을 받아야 한다.

## 이 manifest가 대신하지 않는 것

- PostgreSQL 자체의 multi-AZ, backup/PITR, connection pooler 설계
- Key Vault private endpoint, firewall, HSM tier, Azure Policy
- live Cilium feature 상태, gateway node/egress IP와 site perimeter firewall
  자체의 설치·HA·변경 승인
- Ingress/WAF/TLS certificate와 DDoS 경계
- image build/sign/SBOM/provenance 및 admission policy
- ingress selector label과 egress contract label을 보호하는 admission/RBAC
  정책

runtime worker가 없거나 runtime release에 exact registration/profile이
없으면 승인된 설정은 실행되지 않는다. 웹 replica를 runtime writer로
승격시키는 방식으로 해결하지 않는다.
