# Azure Workload Identity 운영 경계

이 문서는 `AzureWorkloadIdentityTokenProvider`를 Azure Key Vault 어댑터에
연결하는 방법과, 그 연결이 보장하는 범위를 설명한다. 목표는 애플리케이션
시크릿을 하나 더 만드는 것이 아니라 Kubernetes가 발급한 짧은 OIDC 토큰을
Microsoft Entra가 검증하게 하고, Key Vault 전용 액세스 토큰으로 교환하는
것이다.

```text
Kubernetes projected token
        │  iss / sub / aud / 시간 / 파일 정책 확인
        ▼
Microsoft Entra tenant 전용 token endpoint
        │  client_assertion JWT-bearer exchange
        ▼
https://vault.azure.net/.default 전용 access token
        │
        ▼
version-pinned Azure Key Vault sign / wrap / unwrap
```

클라이언트 시크릿, refresh token, Azure CLI 로그인, 환경변수 기반 credential
chain은 이 경계에 없다.

## 고정되는 값

생성자는 다음 값을 모두 명시적으로 받는다.

| 값 | 예시 | 왜 고정하는가 |
|---|---|---|
| Entra tenant ID | canonical lowercase UUID | `common`, `organizations` 같은 다중 tenant endpoint를 막는다 |
| application/client ID | canonical lowercase UUID | 토큰을 받을 workload identity를 하나로 묶는다 |
| OIDC issuer | AKS cluster의 전체 issuer URL | federated credential의 `issuer`와 byte-for-byte 비교한다 |
| OIDC subject | `system:serviceaccount:<namespace>:<service-account>` | 다른 ServiceAccount 토큰의 대입을 막는다 |
| assertion audience | `api://AzureADTokenExchange` | Microsoft 권장 federation audience 하나만 허용한다 |
| Key Vault scope | `https://vault.azure.net/.default` | Graph나 ARM용 토큰으로 범위가 넓어지는 것을 막는다 |
| token endpoint | `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` | public-cloud Entra origin과 tenant를 동시에 고정한다 |

현재 구현은 Azure public cloud 전용이다. US Government나 별도 authority를
사용해야 한다면 origin만 설정으로 바꾸지 말고, authority와 Key Vault
resource를 하나의 검토된 cloud profile로 추가해야 한다.

## Entra와 AKS 설정

먼저 AKS OIDC issuer를 확인한다.

```bash
az aks show \
  --resource-group <resource-group> \
  --name <cluster> \
  --query oidcIssuerProfile.issuerUrl \
  --output tsv
```

그 전체 문자열을 애플리케이션 설정의 `expected_issuer`와 Entra federated
identity credential 양쪽에 동일하게 넣는다. subject도 축약하거나
정규화하지 않는다.

```bash
az identity federated-credential create \
  --name control-assurance \
  --identity-name <user-assigned-managed-identity> \
  --resource-group <resource-group> \
  --issuer '<exact-aks-oidc-issuer>' \
  --subject 'system:serviceaccount:control-assurance:control-assurance' \
  --audience 'api://AzureADTokenExchange'
```

아래 예시는 token을 직접 projection한다. `defaultMode: 288`은 8진수
`0440`을 10진수로 쓴 값이다. workload는 파일 소유자 root가 아니라
`fsGroup`을 통해 읽으며, provider에는 owner `0`, group `2000`, mode
`0o440`을 그대로 선언한다.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: control-assurance
  namespace: control-assurance
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: control-assurance
  namespace: control-assurance
spec:
  template:
    metadata:
      labels:
        app: control-assurance
    spec:
      serviceAccountName: control-assurance
      securityContext:
        runAsNonRoot: true
        runAsUser: 10000
        runAsGroup: 10000
        fsGroup: 2000
        fsGroupChangePolicy: OnRootMismatch
      containers:
        - name: control-assurance
          image: <immutable-image-reference>
          volumeMounts:
            - name: azure-workload-token
              mountPath: /var/run/control-assurance/azure
              readOnly: true
      volumes:
        - name: azure-workload-token
          projected:
            defaultMode: 288
            sources:
              - serviceAccountToken:
                  audience: api://AzureADTokenExchange
                  expirationSeconds: 3600
                  path: token
```

배포 플랫폼이 projected volume의 owner/group 동작을 다르게 구현하면 먼저
실제 `stat` 값을 확인하고 manifest를 고친다. 검사를 느슨하게 만들기 위해
`0644`나 쓰기 가능한 mode를 허용하는 방식은 지원하지 않는다.

## Python 연결

환경변수에서 값을 찾아오지 않는다. 배포 설정을 검증한 뒤 명시적으로
생성한다.

```python
from pathlib import Path

from assurance_lab.key_management.azure_identity import (
    AzureWorkloadIdentityTokenProvider,
)
from assurance_lab.key_management.azure_key_vault import AzureKeyVaultCryptoClient

provider = AzureWorkloadIdentityTokenProvider(
    tenant_id="11111111-2222-4333-8444-555555555555",
    client_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    token_mount_root=Path("/var/run/control-assurance/azure"),
    token_file=Path("/var/run/control-assurance/azure/token"),
    expected_issuer="https://<aks-oidc-issuer>/",
    expected_subject=(
        "system:serviceaccount:control-assurance:control-assurance"
    ),
    expected_file_owner_uid=0,
    expected_file_group_gid=2000,
    expected_file_mode=0o440,
)

key_vault = AzureKeyVaultCryptoClient(
    provider,
    vault_name="assurance-prod",
    key_name="control-assurance",
    key_version="<32-lowercase-hex-key-version>",
)
```

Key Vault RBAC에는 실제로 필요한 data-plane operation만 부여한다. 현재
어댑터가 쓰는 최소 operation은 별도
[`azure-key-vault-key-management.md`](azure-key-vault-key-management.md)에
정리되어 있다.

## projected file을 읽는 방식

Kubernetes projected volume은 원자적 갱신을 위해 `token -> ..data/token`
같은 상대 symlink를 사용할 수 있다. symlink 자체를 금지하면 정상적인 token
rotation까지 깨진다. 이 provider는 대신 다음 순서로 읽는다.

1. 설정된 token 경로가 설정된 mount root 아래인지 확인한다.
2. symlink를 해석한 최종 파일도 같은 mount root 안에 있는지 확인한다.
3. 최종 경로를 루트부터 component별로 `O_NOFOLLOW`와 함께 연다.
4. regular file, hard-link count 1, owner, 선택적 group, exact mode, 최대
   128 KiB를 확인한다.
5. bounded read 전후의 device, inode, mode, owner, size, mtime, ctime을
   비교한다.
6. 원래 token 경로와 mount root를 다시 해석해 읽는 동안 교체되지 않았는지
   확인한다.

mount 밖으로 향하는 link, 읽는 중 바뀐 파일, hard link, 쓰기 가능한 mode,
owner/group 불일치는 네트워크 요청 전에 실패한다. 원자적 갱신과 경합한
한 번의 요청도 자동 재시도하지 않는다. 다음 상위 작업이 새 deadline으로
다시 시도해야 한다.

## assertion과 access token 정책

projected assertion은 compact JWT의 기본 구조와 canonical base64url,
bounded strict JSON을 통과해야 한다. header는 `RS256`이어야 하며 issuer,
subject, 단일 audience는 설정과 정확히 같아야 한다. `iat`, `nbf`, `exp`는
정수여야 하고 허용 시간 범위는 다음과 같다.

- clock skew: 최대 60초
- assertion age: 최대 3,900초
- assertion lifetime: 최대 3,900초
- 교환 시 남은 수명: 60초 초과

이 로컬 검사는 assertion 서명을 인증하지 않는다. 서명과 federated
credential의 신뢰관계는 Microsoft Entra token endpoint가 검증한다. 로컬
검사의 역할은 잘못 마운트된 token이나 다른 workload의 token을 외부로
보내기 전에 차단하는 것이다.

성공 응답의 access token은 JWT라고 가정하거나 내부 claim을 읽지 않는다.
Microsoft 문서도 Microsoft 소유 API의 token 형식에 의존하지 말라고
명시한다. 여기서는 token을 bounded opaque ASCII 값으로만 보관하고 Key
Vault `Authorization` header를 만들 때만 꺼낸다.

access token은 process memory에만 cache한다. 기본 refresh skew는 120초다.
동시에 여러 thread가 갱신을 요구해도 한 thread만 assertion을 읽고 Entra에
요청한다. 나머지는 같은 token 또는 같은 redacted failure를 받는다. refresh
token은 성공 응답에 포함되어도 거부한다.

Python은 access token이나 assertion의 모든 메모리 복사본을 확실히
zeroize한다고 보장할 수 없다. 이 구현은 영속 저장과 로그 노출을 막지만
confidential-computing 또는 memory-forensics resistance를 주장하지 않는다.

## 네트워크 계약

내장 transport는 다음 조건을 코드로 고정한다.

- system CA와 TLS 1.2 이상
- exact public-cloud Entra token endpoint
- 환경변수 proxy 미사용
- redirect 미추적
- `Accept-Encoding: identity`
- 자동 retry 없음
- 최대 256 KiB response
- `application/json`과 bounded strict JSON
- 성공 응답의 `access_token`, `expires_in`, `token_type` 외에는
  `ext_expires_in`만 허용

assertion이 response body/header에 반사되거나 access token이 response
header에 나타나면 실패한다. upstream body, assertion, access token은
exception text에 포함하지 않는다.

애플리케이션의 허용 목적지는 최소한 다음 exact FQDN/443 조합으로 제한한다.
production Kubernetes profile에서는 pod/node가 이 주소로 직접 나가는 것이
아니라 release-bound Cilium FQDN policy와 정적 CIDR egress gateway를 거치며,
site perimeter가 모든 direct external pod/node egress를 거부한다.

- `login.microsoftonline.com:443`
- 구성한 `<vault>.vault.azure.net:443` 또는 그 private endpoint

조직에서 outbound proxy가 필수라면 환경변수 proxy를 켜지 않는다. 정확한
proxy endpoint, TLS trust, 목적지 allowlist를 별도 transport 경계로
설계하고 같은 negative conformance test를 통과시켜야 한다.

## 장애 해석

| stage | 뜻 | 운영 조치 |
|---|---|---|
| `file` | projection, symlink containment, owner/mode 또는 안정성 실패 | pod volume, `fsGroup`, 실제 `stat`, token rotation event 확인 |
| `assertion` | JWT 구조, identity binding 또는 freshness 실패 | AKS issuer, ServiceAccount subject, audience, node clock 확인 |
| `scope` | Key Vault 이외의 scope 요청 | 호출자 설정 오류로 처리하고 범위를 넓히지 않음 |
| `transport` | pinned Entra endpoint 요청 실패 | exact DNS/FQDN policy, CIDR gateway route, perimeter deny, TLS trust 확인; client secret으로 우회하지 않음 |
| `response` | HTTP status, header, JSON, token 또는 reflection 정책 실패 | Entra sign-in log와 request ID를 외부 운영 채널에서 확인 |
| `deadline` | 시작 전 또는 대기/수신 중 deadline 만료 | 상위 작업의 시간 예산과 네트워크 지연 확인 |

HTTP 429, 5xx, timeout에도 provider 내부 retry는 없다. 여러 단계의 token
교환을 자동 retry하면 응답 유실과 새 assertion 발급이 섞여 원인을 숨길 수
있다. retry 횟수와 backoff가 필요하다면 상위 orchestration 계층에서 새
deadline과 명시적인 운영 지표를 가지고 수행한다.

## 검증 범위

전용 test suite는 다음을 로컬에서 확인한다.

- direct file과 Kubernetes atomic-writer 형태의 in-root symlink
- mount 탈출 symlink, hard link, owner/group/mode/size 불일치
- read 도중 file/path 교체
- JWT algorithm, issuer, subject, audience, claim, 시간 경계
- exact endpoint, scope, form field와 client secret 부재
- redirect, compression, oversized/malformed response와 refresh token 거부
- assertion/access-token reflection redaction
- cache refresh skew와 concurrent single-flight 성공/실패
- 환경 proxy 비활성화와 redirect handler

이것은 실제 Azure tenant, AKS issuer, federated identity credential, Key
Vault RBAC 또는 private endpoint가 맞게 구성되었다는 증명이 아니다. live
검증을 주장하려면 운영자가 소유한 disposable tenant/vault에서 성공과
negative case를 모두 실행하고 Azure sign-in/Key Vault audit log를 별도
증적으로 보관해야 한다.

프로토콜과 설정 기준:

- [Microsoft identity platform client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [AKS Microsoft Entra Workload ID 배포](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster)
- [Federated identity credential 고려사항](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations)
- [RFC 7523: OAuth JWT Assertion Profiles](https://www.rfc-editor.org/rfc/rfc7523.html)
- [Azure Key Vault authentication](https://learn.microsoft.com/en-us/azure/key-vault/general/authentication-requests-and-responses)
