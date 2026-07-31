from __future__ import annotations

import hashlib
import http.client
import os
import socket
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, cast

import pytest

import assurance_lab.runtime.bootstrap as bootstrap_module
import assurance_lab.runtime.service as service_module
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.bootstrap import (
    ProductionRuntimeWorkerFactory,
    RuntimeBootstrapError,
    RuntimeWorkerComponents,
    _validate_database_transport,
    _validate_schema_lineage,
)
from assurance_lab.runtime.deployment_io import (
    initialize_shared_work_root,
    read_protected_file,
    validate_shared_work_root,
)
from assurance_lab.runtime.service import (
    RuntimeHealthServer,
    RuntimeServiceStatus,
    RuntimeWorkerService,
)
from assurance_lab.runtime.service_cli import main as service_main
from assurance_lab.runtime.service_config import (
    AzureWorkloadIdentitySettings,
    ControlRuntimeRegistration,
    CustodyRuntimeSettings,
    DatabaseSettings,
    ElasticRuntimeSettings,
    EnvironmentReference,
    HealthSettings,
    PinnedPublicFileSettings,
    ProtectedFileSettings,
    RuntimeServiceConfigurationError,
    RuntimeWorkerServiceConfig,
    S3CustodySettings,
    SharedWorkRootSettings,
    VaultTransitSettings,
    parse_runtime_worker_service_config,
)
from assurance_lab.runtime.worker import (
    RuntimeWorkerStatus,
    TenantRuntimeWorker,
    WorkerState,
)

_DIGEST = f"sha256:{'1' * 64}"
_SOURCE_REVISION = f"oci:sha256:{'2' * 64}"


def _environment_reference(name: str) -> EnvironmentReference:
    return EnvironmentReference(name=name)


def _protected_file(path: str, mount_root: str) -> ProtectedFileSettings:
    return ProtectedFileSettings(
        path=path,
        mount_root=mount_root,
        owner_uid=os.geteuid(),
        group_gid=os.getegid(),
        mode=0o400,
    )


def _pinned_public_file(
    path: Path,
    *,
    value: bytes,
) -> PinnedPublicFileSettings:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o400)
    return PinnedPublicFileSettings(
        file=_protected_file(str(path), str(path.parent)),
        sha256_digest=f"sha256:{hashlib.sha256(value).hexdigest()}",
    )


def _configuration() -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id="tenant-a",
        control_id="alert-window",
        display_name="Alert completeness",
        description="Re-evaluate one closed alert window.",
        environment="production",
        owner_group="security/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_DIGEST,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.internal.example",
            index_alias=".alerts-security.alerts-payments",
            parent_credential_ref=(
                "azure-keyvault://security-kv/secrets/"
                "elastic-parent/0123456789abcdef0123456789abcdef"
            ),
            ca_bundle_ref=(
                "azure-keyvault://security-kv/secrets/"
                "elastic-ca/abcdef0123456789abcdef0123456789"
            ),
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence-bucket/tenant-a/alerts",
            signing_key_ref="vault-transit://assurance/signing/runtime",
            retention_days=365,
        ),
    )


def _service_configuration(
    tmp_path: Path,
    *,
    health_port: int = 18080,
) -> RuntimeWorkerServiceConfig:
    token_root = tmp_path / "tokens"
    trust_root = tmp_path / "trust"
    configuration = _configuration()
    workload_identity = AzureWorkloadIdentitySettings(
        tenant_id="11111111-2222-4333-8444-555555555555",
        client_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        token=_protected_file(
            str(token_root / "azure"),
            str(token_root),
        ),
        expected_issuer="https://issuer.internal.example",
        expected_subject="system:serviceaccount:assurance:runtime-worker",
    )
    source_runtime = ElasticRuntimeSettings(
        azure_workload_identity=workload_identity,
        ca_bundle=_pinned_public_file(
            trust_root / "elastic-ca.pem",
            value=b"elastic-test-ca",
        ),
    )
    custody_runtime = CustodyRuntimeSettings(
        profile_id="production-custody-v1",
        expected_profile_digest=f"sha256:{'3' * 64}",
        s3=S3CustodySettings(
            region="us-east-1",
            bucket_name="evidence-bucket",
            bucket_arn="arn:aws:s3:::evidence-bucket",
            expected_bucket_owner="123456789012",
            kms_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:key/"
                "11111111-2222-4333-8444-555555555555"
            ),
            minimum_retention_seconds=86_400,
            maximum_retention_seconds=31_536_000,
        ),
        vault_transit=VaultTransitSettings(
            endpoint="https://vault.internal.example",
            mount_path="transit",
            key_name="assurance-runtime",
            key_id="vault-transit:assurance/runtime",
            token=_protected_file(
                str(token_root / "vault"),
                str(token_root),
            ),
            ca_bundle=_pinned_public_file(
                trust_root / "vault-ca.pem",
                value=b"vault-test-ca",
            ),
        ),
    )
    return RuntimeWorkerServiceConfig(
        tenant_id="tenant-a",
        worker_id=_environment_reference("RUNTIME_WORKER_ID"),
        worker_credential_digest=_environment_reference(
            "RUNTIME_WORKER_CREDENTIAL_DIGEST"
        ),
        source_revision=_environment_reference("RUNTIME_SOURCE_REVISION"),
        database=DatabaseSettings(
            runtime_dsn=_environment_reference("RUNTIME_DATABASE_DSN"),
            runtime_role="control_assurance_runtime_worker",
            execution_journal_dsn=_environment_reference(
                "EXECUTION_DATABASE_DSN"
            ),
            execution_journal_role="control_assurance_execution_worker",
            pam_journal_dsn=_environment_reference("PAM_DATABASE_DSN"),
            pam_journal_role="control_assurance_pam_broker",
            ca_bundle=_pinned_public_file(
                trust_root / "postgres-ca.pem",
                value=b"postgres-test-ca",
            ),
        ),
        work_root=SharedWorkRootSettings(
            path=str(tmp_path / "work"),
            volume_id="runtime-rwx-a",
            marker_owner_uid=os.geteuid(),
            marker_group_gid=os.getegid(),
            marker_mode=0o400,
        ),
        health=HealthSettings(bind_host="127.0.0.1", port=health_port),
        registrations=(
            ControlRuntimeRegistration(
                configuration=configuration,
                source_runtime=source_runtime,
                custody_runtime=custody_runtime,
            ),
        ),
    )


def _production_environment(
    configuration: RuntimeWorkerServiceConfig,
) -> dict[str, str]:
    ca_path = configuration.database.ca_bundle.file.path
    dsn = (
        "host=postgres.internal.example "
        "dbname=control_assurance user=runtime "
        "sslmode=verify-full target_session_attrs=read-write "
        f"sslrootcert={ca_path}"
    )
    return {
        "RUNTIME_WORKER_ID": "runtime-worker-0",
        "RUNTIME_WORKER_CREDENTIAL_DIGEST": _DIGEST,
        "RUNTIME_SOURCE_REVISION": _SOURCE_REVISION,
        "RUNTIME_DATABASE_DSN": dsn,
        "EXECUTION_DATABASE_DSN": dsn,
        "PAM_DATABASE_DSN": dsn,
    }


def _worker_status(
    state: WorkerState,
    *,
    stop_requested: bool = False,
) -> RuntimeWorkerStatus:
    return RuntimeWorkerStatus(
        tenant_id="tenant-a",
        state=state,
        stop_requested=stop_requested,
        run_in_progress=False,
        cycles=0,
        materializations=0,
        materialized_runs=0,
        runs_processed=0,
        idle_cycles=0,
        transient_failures=0,
        consecutive_failures=0,
        event_sink_failures=0,
        current_backoff_seconds=0.0,
        last_event_code=None,
        fatal_code=None,
    )


def _http_request(
    server: RuntimeHealthServer,
    path: str,
    *,
    method: str = "GET",
) -> tuple[int, bytes]:
    host, port = server.address
    connection = http.client.HTTPConnection(host, port, timeout=2.0)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_runtime_configuration_is_strict_digest_pinned_and_secret_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configuration = _service_configuration(tmp_path)
    parsed = parse_runtime_worker_service_config(
        configuration.canonical_bytes,
        expected_digest=configuration.digest,
    )

    assert parsed == configuration
    assert b"super-secret" not in configuration.canonical_bytes
    assert configuration.resolve_worker_id(
        {"RUNTIME_WORKER_ID": "runtime-worker-0"}
    ) == "runtime-worker-0"
    assert configuration.resolve_worker_credential_digest(
        {"RUNTIME_WORKER_CREDENTIAL_DIGEST": _DIGEST}
    ) == _DIGEST
    assert configuration.resolve_source_revision(
        {"RUNTIME_SOURCE_REVISION": _SOURCE_REVISION}
    ) == _SOURCE_REVISION

    with pytest.raises(RuntimeServiceConfigurationError, match="digest differs"):
        parse_runtime_worker_service_config(
            configuration.canonical_bytes,
            expected_digest=f"sha256:{'f' * 64}",
        )

    document = configuration.model_dump(mode="json")
    database = cast(dict[str, object], document["database"])
    database["password"] = "super-secret"
    with pytest.raises(RuntimeServiceConfigurationError) as error:
        parse_runtime_worker_service_config(
            canonical_json_bytes(document),
            expected_digest=configuration.digest,
        )
    assert "super-secret" not in str(error.value)

    path = tmp_path / "runtime.json"
    path.write_bytes(configuration.canonical_bytes)
    assert service_main(["config-digest", "--config", str(path)], environment={}) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == configuration.digest
    assert captured.err == ""

    invalid_path = tmp_path / "runtime-with-secret.json"
    invalid_path.write_bytes(canonical_json_bytes(document))
    assert (
        service_main(
            ["config-digest", "--config", str(invalid_path)],
            environment={},
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "runtime-worker-config-invalid"
    assert "super-secret" not in captured.err


def test_pam_namespace_plan_is_exact_secret_free_provisioning_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configuration = _service_configuration(tmp_path)
    path = tmp_path / "runtime.json"
    path.write_bytes(configuration.canonical_bytes)
    environment = {"ASSURANCE_RUNTIME_CONFIG_DIGEST": configuration.digest}

    assert (
        service_main(
            ["pam-namespace-plan", "--config", str(path)],
            environment=environment,
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    document = strict_json_loads(captured.out.encode("utf-8"))
    source = configuration.registrations[0].configuration.source
    source_digest = "sha256:" + hashlib.sha256(
        canonical_json_bytes(source.model_dump(mode="json"))
    ).hexdigest()
    expected_namespace = "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": "control-assurance-pam-journal-namespace",
                "purpose": "elastic-jit-api-key",
                "schema_version": "1.0.0",
                "source_configuration_digest": source_digest,
                "tenant_id": "tenant-a",
            }
        )
    ).hexdigest()
    assert document == {
        "code": "pam-journal-namespace",
        "journal_namespace_digest": expected_namespace,
        "purpose": "elastic-jit-api-key",
        "source_configuration_digest": source_digest,
        "source_kind": "elastic-security",
        "tenant_id": "tenant-a",
    }


def test_runtime_rejects_database_trust_tamper_before_database_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _service_configuration(tmp_path)
    ca_path = Path(configuration.database.ca_bundle.file.path)
    ca_path.chmod(0o600)
    ca_path.write_bytes(b"tampered-postgres-ca")
    ca_path.chmod(0o400)
    network_reached = False

    def must_not_connect(*_args: object, **_kwargs: object) -> None:
        nonlocal network_reached
        network_reached = True
        raise AssertionError("database preflight reached the network")

    monkeypatch.setattr(
        bootstrap_module,
        "_preflight_databases",
        must_not_connect,
    )

    with pytest.raises(RuntimeBootstrapError) as error:
        ProductionRuntimeWorkerFactory(
            configuration,
            environment=_production_environment(configuration),
        ).build()
    assert error.value.stage == "database-trust"
    assert network_reached is False


def test_runtime_rejects_external_trust_tamper_before_any_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _service_configuration(tmp_path)
    source = configuration.registrations[0].source_runtime
    assert type(source) is ElasticRuntimeSettings
    ca_path = Path(source.ca_bundle.file.path)
    ca_path.chmod(0o600)
    ca_path.write_bytes(b"tampered-elastic-ca")
    ca_path.chmod(0o400)
    network_reached = False

    def must_not_connect(*_args: object, **_kwargs: object) -> None:
        nonlocal network_reached
        network_reached = True
        raise AssertionError("database preflight reached the network")

    monkeypatch.setattr(
        bootstrap_module,
        "_preflight_databases",
        must_not_connect,
    )

    with pytest.raises(RuntimeBootstrapError) as error:
        ProductionRuntimeWorkerFactory(
            configuration,
            environment=_production_environment(configuration),
        ).build()
    assert error.value.stage == "public-trust"
    assert network_reached is False


def test_protected_file_allows_only_stable_in_mount_targets(tmp_path: Path) -> None:
    mount_root = tmp_path / "projected"
    data = mount_root / "..2026_07_30"
    data.mkdir(parents=True)
    target = data / "token"
    target.write_bytes(b"bounded-token")
    target.chmod(0o400)
    configured = mount_root / "token"
    configured.symlink_to(Path("..2026_07_30") / "token")
    settings = _protected_file(str(configured), str(mount_root))

    assert read_protected_file(settings) == b"bounded-token"

    target.chmod(0o600)
    with pytest.raises(RuntimeServiceConfigurationError, match="ownership, mode"):
        read_protected_file(settings)

    outside = tmp_path / "outside-token"
    outside.write_bytes(b"must-not-be-read")
    outside.chmod(0o400)
    escaped = mount_root / "escaped"
    escaped.symlink_to(outside)
    escaped_settings = _protected_file(str(escaped), str(mount_root))
    with pytest.raises(RuntimeServiceConfigurationError, match="escaped its mount"):
        read_protected_file(escaped_settings)


def test_shared_work_root_requires_exact_marker_and_remains_writable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "shared-work"
    root.mkdir()
    settings = SharedWorkRootSettings(
        path=str(root),
        volume_id="runtime-rwx-a",
        marker_owner_uid=os.geteuid(),
        marker_group_gid=os.getegid(),
        marker_mode=0o400,
    )

    initialize_shared_work_root(settings)
    assert validate_shared_work_root(settings) == root
    marker = root / ".control-assurance-shared-work-root-v1"
    assert stat.S_IMODE(marker.stat().st_mode) == 0o400
    assert marker.read_bytes() == settings.marker_bytes
    assert not tuple(root.glob(".control-assurance-write-probe-*"))

    marker.chmod(0o600)
    marker.write_bytes(b"tampered")
    marker.chmod(0o400)
    with pytest.raises(RuntimeServiceConfigurationError, match="marker"):
        validate_shared_work_root(settings)


def test_health_endpoints_separate_liveness_from_readiness() -> None:
    current = [RuntimeServiceStatus("starting", False, None)]
    server = RuntimeHealthServer(
        host="127.0.0.1",
        port=0,
        status=lambda: current[0],
    )
    server.start()
    try:
        assert _http_request(server, "/livez") == (200, b'{"status":"ok"}')
        assert _http_request(server, "/readyz") == (
            503,
            b'{"status":"not-ready"}',
        )

        current[0] = RuntimeServiceStatus(
            "running",
            False,
            _worker_status("running"),
        )
        assert _http_request(server, "/readyz") == (200, b'{"status":"ok"}')
        assert _http_request(server, "/unknown") == (
            404,
            b'{"status":"not-found"}',
        )
        assert _http_request(server, "/livez", method="POST") == (
            405,
            b'{"status":"method-not-allowed"}',
        )

        current[0] = RuntimeServiceStatus(
            "draining",
            True,
            _worker_status("stopping", stop_requested=True),
        )
        assert _http_request(server, "/livez") == (200, b'{"status":"ok"}')
        assert _http_request(server, "/readyz") == (
            503,
            b'{"status":"not-ready"}',
        )

        current[0] = RuntimeServiceStatus("stopped", True, None)
        assert _http_request(server, "/livez") == (
            503,
            b'{"status":"not-ready"}',
        )
    finally:
        server.close()


def test_partial_health_request_cannot_serialize_liveness_probes() -> None:
    server = RuntimeHealthServer(
        host="127.0.0.1",
        port=0,
        status=lambda: RuntimeServiceStatus("starting", False, None),
    )
    server.start()
    slow_connection = socket.create_connection(server.address, timeout=1.0)
    try:
        slow_connection.sendall(
            b"GET /livez HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Incomplete: "
        )
        time.sleep(0.05)

        assert _http_request(server, "/livez") == (200, b'{"status":"ok"}')
    finally:
        slow_connection.close()
        server.close()


class _DrainingWorker:
    def __init__(self) -> None:
        self.active = threading.Event()
        self.release = threading.Event()
        self.stop_requested = False
        self.state: WorkerState = "created"

    def request_stop(self) -> None:
        self.stop_requested = True
        self.state = "stopping"

    def status(self) -> RuntimeWorkerStatus:
        return _worker_status(
            self.state,
            stop_requested=self.stop_requested,
        )

    def run_forever(self) -> None:
        self.state = "running"
        self.active.set()
        if not self.release.wait(timeout=5.0):
            raise RuntimeError("test worker was not released")
        self.state = "stopped"


class _Factory:
    def __init__(
        self,
        worker: _DrainingWorker,
        close: Callable[[], None],
    ) -> None:
        self.worker = worker
        self.close = close

    def build(self, *, event_sink: object = None) -> RuntimeWorkerComponents:
        del event_sink
        return RuntimeWorkerComponents(
            worker=cast(TenantRuntimeWorker, self.worker),
            closers=(self.close,),
        )


class _InMemoryHealthServer:
    instances: ClassVar[list[_InMemoryHealthServer]] = []

    def __init__(self, **kwargs: object) -> None:
        del kwargs
        self.started = False
        self.closed = False
        self.instances.append(self)

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True


def test_service_drains_active_work_before_closing_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _InMemoryHealthServer.instances.clear()
    monkeypatch.setattr(
        service_module,
        "RuntimeHealthServer",
        _InMemoryHealthServer,
    )
    worker = _DrainingWorker()
    closed = threading.Event()
    service = RuntimeWorkerService(
        _service_configuration(tmp_path),
        _Factory(worker, closed.set),
    )
    failures: list[BaseException] = []

    def run() -> None:
        try:
            service.run()
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    assert worker.active.wait(timeout=2.0)
    assert service.status().ready is True

    service.request_stop()
    assert service.status().phase == "draining"
    assert service.status().ready is False
    assert thread.is_alive()
    assert not closed.is_set()

    worker.release.set()
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert failures == []
    assert closed.is_set()
    assert service.status().phase == "stopped"
    assert len(_InMemoryHealthServer.instances) == 1
    assert _InMemoryHealthServer.instances[0].started is True
    assert _InMemoryHealthServer.instances[0].closed is True


def test_database_transport_requires_verified_primary_and_pinned_ca(
    tmp_path: Path,
) -> None:
    root_certificate = tmp_path / "postgres-ca.pem"
    root_certificate.write_text("test root certificate")
    root_certificate.chmod(0o444)
    parameters = {
        "host": "postgres.internal.example",
        "sslmode": "verify-full",
        "sslrootcert": str(root_certificate),
        "target_session_attrs": "read-write",
    }

    _validate_database_transport(parameters)

    for key, value in (
        ("sslmode", "require"),
        ("target_session_attrs", "any"),
    ):
        changed = dict(parameters)
        changed[key] = value
        with pytest.raises(RuntimeBootstrapError) as error:
            _validate_database_transport(changed)
        assert error.value.stage == "database-transport-policy"

    root_certificate.chmod(0o666)
    with pytest.raises(RuntimeBootstrapError) as writable_error:
        _validate_database_transport(parameters)
    assert writable_error.value.stage == "database-transport-policy"

    root_certificate.chmod(0o444)
    linked_certificate = tmp_path / "linked-ca.pem"
    linked_certificate.symlink_to(root_certificate)
    changed = dict(parameters)
    changed["sslrootcert"] = str(linked_certificate)
    with pytest.raises(RuntimeBootstrapError) as symlink_error:
        _validate_database_transport(changed)
    assert symlink_error.value.stage == "database-transport-policy"


@pytest.mark.parametrize(
    "lineage",
    (
        [1],
        [2],
        [1, 2, 3],
        [1, 1, 2],
        None,
    ),
)
def test_database_preflight_rejects_nonexact_migration_lineage(
    lineage: object,
) -> None:
    with pytest.raises(RuntimeBootstrapError) as error:
        _validate_schema_lineage(
            {"schema_versions": lineage},
            expected_version=2,
        )
    assert error.value.stage == "database-preflight"

    _validate_schema_lineage(
        {"schema_versions": [1, 2]},
        expected_version=2,
    )
