# Production container contract

The repository builds one image for the control plane, runtime worker, profile
registrar, and deployment reconciler. Kubernetes selects the process with an
explicit `command`; the image itself defaults to `assurance-lab --help`.

The image contract is intentionally narrow:

- the Python base is pinned by OCI manifest-list digest;
- build and runtime dependencies are separate, hash-pinned, wheel-only locks;
- the project is installed from its wheel, not from a mutable source checkout;
- the runtime contains no `pip`;
- PID 1 runs as UID/GID 10000 with no passwd entry or login shell;
- `/tmp`, trust material, credentials, and working data are runtime mounts;
- service shutdown is `SIGTERM`; Kubernetes owns liveness/readiness probes;
- the image contains no tenant configuration, credential, token, or private key.

Build the same source tree used for the source-revision label:

```sh
docker build \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  --build-arg IMAGE_VERSION="0.1.1" \
  --tag control-assurance-lab:0.1.1 \
  .
```

## Release boundary

A `vMAJOR.MINOR.PATCH` tag does not publish from the ordinary branch checks by
assumption. The release workflow repeats the source, unit, static, independent
JavaScript, dependency-audit, and distribution checks on the tagged commit.
Only then does a second read-only job build the two-platform OCI layout.

That job has no package-write or OIDC authority. It verifies that the layout is
closed over exactly:

- one `linux/amd64` image and one `linux/arm64` image;
- the expected non-root runtime configuration and source/version labels;
- one BuildKit attestation manifest per platform;
- a digest-pinned SBOM scanner and substantive SPDX/SLSA v1 statements bound
  to each platform manifest and to the release build arguments;
- compressed layer digests, valid tar streams, and their exact uncompressed
  `rootfs.diff_ids`;
- no foreign or unreachable blob.

Trivy's local OCI reader is given a one-manifest index for each architecture.
Both views point to the same content-addressed blobs that will be published.
After both scans, the original multi-platform index is restored and verified
again. The layout is then placed in a deterministic OCI tar. GitHub transfers
that one file without ZIP re-archiving and checks its SHA-256 digest at both job
boundaries.

The final job is the only job with `packages: write`, `id-token: write`, and
`attestations: write`. It does not check out or execute repository source. It:

1. checks the downloaded tar digest and resolves its local OCI index digest;
2. copies those exact bytes to a run-unique candidate tag;
3. resolves the registry index and both platform manifests against the
   pre-scan digests;
4. signs and attests the immutable index digest, then verifies both;
5. creates the version tag from that digest only.

If the version tag already exists at a different digest, promotion stops rather
than rewriting it. Candidate tags are deliberately not deployment tags.
Registry administrators can still delete or retag objects, so production
admission should pin the released digest and verify the expected workflow
identity; a mutable tag is not a trust anchor.

## Verify a published release as a consumer

The first successful container release is `v0.1.1`. Obtain the canonical
`vX.Y.Z` source tag and `sha256:...` index digest from its GitHub Release
record, then verify the immutable subject rather than trusting the version tag:

```sh
REPOSITORY=gyubin02/control-assurance-lab
IMAGE=ghcr.io/${REPOSITORY}
RELEASE_TAG=vX.Y.Z
VERSION=${RELEASE_TAG#v}
DIGEST=sha256:<64-hex-index-digest>
SOURCE_DIGEST=<40-hex-source-commit>

test "$(oras resolve "${IMAGE}:${VERSION}")" = "${DIGEST}"

cosign verify \
  --certificate-identity \
    "https://github.com/${REPOSITORY}/.github/workflows/release-container.yml@refs/tags/${RELEASE_TAG}" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  "${IMAGE}@${DIGEST}"

gh attestation verify \
  "oci://${IMAGE}@${DIGEST}" \
  --repo "${REPOSITORY}" \
  --bundle-from-oci \
  --signer-workflow \
    "${REPOSITORY}/.github/workflows/release-container.yml" \
  --source-ref "refs/tags/${RELEASE_TAG}" \
  --source-digest "${SOURCE_DIGEST}"
```

The first check detects a tag that no longer names the reviewed digest. Cosign
then verifies the keyless workflow identity on that digest, and GitHub CLI
verifies the registry-hosted build provenance against this repository, the
release workflow, the source tag, and the reviewed source commit. An
installation should obtain `SOURCE_DIGEST` from the reviewed GitHub Release
record, compare it with the reviewed tag, and record the accepted image digest,
workflow identity, source ref, and source digest in its release approval. It
should not resolve the tag again during deployment.

The checked-in Kubernetes manifests deliberately use a zero digest and an
example registry. Release automation must replace both with the digest of the
published image. Deployments must keep `runAsNonRoot`, UID/GID 10000,
`readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, and all Linux
capabilities dropped.

Do not mount a Docker socket, Kubernetes admin credential, cloud static key, or
database owner credential into this image. Workload identity and the
least-privilege database roles described by each service's runbook are the
supported production paths.
