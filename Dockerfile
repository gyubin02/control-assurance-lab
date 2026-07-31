# The tag is for readability; the manifest-list digest is the trust anchor.
ARG PYTHON_IMAGE=python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
ARG SOURCE_DATE_EPOCH=0

FROM ${PYTHON_IMAGE} AS builder

ARG SOURCE_DATE_EPOCH
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /build

# Build tooling and runtime dependencies are independently resolved and
# hash-pinned. Neither installation is allowed to fall back to an sdist.
COPY requirements/container-build.lock /tmp/container-build.lock
RUN python -m pip install \
      --only-binary=:all: \
      --require-hashes \
      --requirement /tmp/container-build.lock

RUN python -m venv /opt/control-assurance
COPY requirements/runtime.lock /tmp/runtime.lock
RUN /opt/control-assurance/bin/python -m pip install \
      --only-binary=:all: \
      --require-hashes \
      --requirement /tmp/runtime.lock

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY verifier-js ./verifier-js

RUN python -m hatchling build --target wheel --directory /tmp/dist \
    && /opt/control-assurance/bin/python -m pip install \
         --no-deps \
         /tmp/dist/control_assurance_lab-*.whl \
    && /opt/control-assurance/bin/python -c \
         'from importlib.resources import files; import assurance_lab; assert (files("assurance_lab.control_plane") / "static" / "index.html").is_file()' \
    && test -x /opt/control-assurance/bin/assurance-control-plane \
    && test -x /opt/control-assurance/bin/assurance-runtime-worker \
    && rm -rf \
         /opt/control-assurance/lib/python3.12/site-packages/pip \
         /opt/control-assurance/lib/python3.12/site-packages/pip-*.dist-info \
         /opt/control-assurance/bin/pip \
         /opt/control-assurance/bin/pip3 \
         /opt/control-assurance/bin/pip3.12

FROM ${PYTHON_IMAGE} AS runtime

ARG SOURCE_REVISION=unknown
ARG SOURCE_URL=https://github.com/gyubin02/control-assurance-lab
ARG IMAGE_VERSION=0.1.1

LABEL org.opencontainers.image.title="Control Assurance Lab" \
      org.opencontainers.image.description="Identity-bound control evidence runtime and control plane" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV HOME=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/opt/control-assurance/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

RUN install -d \
         --owner=10000 \
         --group=10000 \
         --mode=0700 \
         /var/lib/control-assurance \
    && rm -rf \
         /usr/local/lib/python3.12/site-packages/pip \
         /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
         /usr/local/lib/python3.12/ensurepip \
         /usr/local/bin/pip \
         /usr/local/bin/pip3 \
         /usr/local/bin/pip3.12

COPY --from=builder --chown=0:0 /opt/control-assurance /opt/control-assurance

# The production image is an immutable application appliance, not a package
# installation environment. Assert this only after the pip-free venv is copied.
RUN ! command -v pip \
    && ! python -m pip --version \
    && ! python -m ensurepip --version

USER 10000:10000
WORKDIR /var/lib/control-assurance

EXPOSE 8080
STOPSIGNAL SIGTERM

# Kubernetes supplies one of the service commands. The safe local default is a
# read-only command that neither opens a listener nor reaches external systems.
CMD ["assurance-lab", "--help"]
