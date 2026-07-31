from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from assurance_lab.connectors.defender_pam import (
    DefenderPamError,
    DefenderTokenJournal,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticLeaseJournal,
    ElasticPamError,
    ElasticPamPolicy,
)
from assurance_lab.connectors.postgres_pam_journal import (
    PAMExecutionBinding,
    PostgresDefenderTokenJournal,
    PostgresElasticLeaseJournal,
    PostgresPamIssuanceJournal,
    PostgresPamRecoveryError,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime import execution_plan as execution_plan_module
from assurance_lab.runtime.execution_plan import (
    ELASTIC_REQUEST_MEDIA_TYPE,
    ControlRunExecutionPlan,
)
from assurance_lab.runtime.execution_recovery import (
    PAMRecoveryScope,
    publishing_recovery_pam_scope_digest,
)
from assurance_lab.runtime.models import sha256_digest

_LEASE_ID = "a" * 64
_ACQUISITION_ID = "b" * 64
_DIGEST = f"sha256:{'c' * 64}"
_OTHER_DIGEST = f"sha256:{'d' * 64}"
_NAMESPACE_DIGEST = f"sha256:{'e' * 64}"
_CREATED = 1_700_000_000_000


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _pam_plan() -> ControlRunExecutionPlan:
    tenant_id = "bank-a"
    run_id = _digest("5")
    control_id = "high-alert-control"
    configuration_digest = _digest("6")
    connector_request: dict[str, Any] = {}
    connector_request_digest = sha256_digest(canonical_json_bytes(connector_request))
    artifact_set_id = execution_plan_module._logical_identity(
        "control-assurance:managed-evidence-artifact-set:v2",
        run_id=run_id,
        tenant_id=tenant_id,
    )
    custody_scope_id = execution_plan_module._logical_identity(
        "control-assurance:stream-custody-scope:v1",
        run_id=run_id,
        tenant_id=tenant_id,
    )
    executor_receipt_id = execution_plan_module._logical_identity(
        "control-assurance:executor-receipt:v1",
        run_id=run_id,
        tenant_id=tenant_id,
    )
    signing_key_ref = "vault-transit://assurance/runtime"
    custody_ref = "s3-object-lock://evidence/bank-a/high-alerts"
    scopes = execution_plan_module._derived_pam_scopes(
        tenant_id=tenant_id,
        run_id=run_id,
        control_id=control_id,
        configuration_digest=configuration_digest,
        source_kind="elastic-security",
        connector_request_digest=connector_request_digest,
        signing_key_ref=signing_key_ref,
        custody_ref=custody_ref,
        executor_receipt_id=executor_receipt_id,
        custody_scope_id=custody_scope_id,
    )
    window_start = datetime(2026, 7, 29, 1, tzinfo=UTC)
    window_end = window_start + timedelta(minutes=5)
    prepared_at = window_end + timedelta(minutes=2)
    return ControlRunExecutionPlan(
        run_id=run_id,
        tenant_id=tenant_id,
        control_id=control_id,
        deployment_operation_id=_digest("7"),
        deployment_receipt_digest=_digest("8"),
        configuration_digest=configuration_digest,
        control_profile_id="high-alert-window",
        control_profile_digest=_digest("9"),
        artifact_set_id=artifact_set_id,
        custody_scope_id=custody_scope_id,
        executor_receipt_id=executor_receipt_id,
        window_start=window_start,
        window_end=window_end,
        prepared_at=prepared_at,
        custody_retain_until=prepared_at + timedelta(days=365),
        source_revision="test:postgres-pam",
        source_kind="elastic-security",
        capture_id=f"run-{run_id.removeprefix('sha256:')}",
        capture_nonce="ab" * 32,
        connector_request_media_type=ELASTIC_REQUEST_MEDIA_TYPE,
        connector_request_digest=connector_request_digest,
        connector_request=connector_request,
        source_credential_ref="vault://runtime/elastic-parent",
        signing_key_ref=signing_key_ref,
        custody_ref=custody_ref,
        pam_scopes=scopes,
        pam_scope_digest=publishing_recovery_pam_scope_digest(scopes),
    )


_PAM_PLAN = _pam_plan()


def _pam_binding(
    lease_fence: int,
    *,
    lease_expires_at_epoch_millis: int = _CREATED + 10_000_000_000,
) -> PAMExecutionBinding:
    return PAMExecutionBinding.from_execution_plan(
        _PAM_PLAN,
        execution_identity_digest=_digest("4"),
        lease_fence=lease_fence,
        lease_expires_at_epoch_millis=lease_expires_at_epoch_millis,
    )


def _binding_row(
    binding: PAMExecutionBinding,
    *,
    state: str,
) -> dict[str, Any]:
    return {
        "tenant_id": binding.tenant_id,
        "run_id": binding.run_id,
        "execution_plan_digest": binding.execution_plan_digest,
        "execution_identity_digest": binding.execution_identity_digest,
        "lease_fence": binding.lease_fence,
        "lease_expires_at_epoch_millis": binding.lease_expires_at_epoch_millis,
        "pam_scope_digest": binding.pam_scope_digest,
        "execution_binding_digest": binding.execution_binding_digest,
        "state": state,
    }


def _scope_rows(
    binding: PAMExecutionBinding,
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        {
            "authority_class": scope.authority_class,
            "connector_id": scope.connector_id,
            "connector_request_digest": scope.connector_request_digest,
        }
        for scope in binding.pam_scopes
    )


def _lifecycle_row(
    binding: PAMExecutionBinding,
    scope: PAMRecoveryScope,
    *,
    lifecycle_sequence: int,
    lifecycle_record_id: str,
    state: str = "prepared",
    revision: int = 0,
) -> dict[str, Any]:
    issued = _CREATED + 1 if state == "issued" else None
    expires = _CREATED + 101 if state == "issued" else None
    return {
        "lifecycle_sequence": lifecycle_sequence,
        "lifecycle_record_id": lifecycle_record_id,
        "tenant_id": binding.tenant_id,
        "run_id": binding.run_id,
        "execution_plan_digest": binding.execution_plan_digest,
        "execution_identity_digest": binding.execution_identity_digest,
        "lease_fence": binding.lease_fence,
        "pam_scope_digest": binding.pam_scope_digest,
        "execution_binding_digest": binding.execution_binding_digest,
        "authority_class": scope.authority_class,
        "connector_id": scope.connector_id,
        "connector_request_digest": scope.connector_request_digest,
        "credential_reference_digest": None,
        "state": state,
        "revision": revision,
        "created_epoch_millis": _CREATED,
        "issued_epoch_millis": issued,
        "expires_epoch_millis": expires,
        "settled_epoch_millis": None,
        "maximum_residual_exposure_ends_epoch_millis": _CREATED + 101,
    }


class _Cursor:
    def __init__(
        self,
        rows: tuple[Mapping[str, Any], ...] = (),
    ) -> None:
        self._rows = rows

    def fetchone(self) -> Mapping[str, Any] | None:
        return None if not self._rows else self._rows[0]

    def fetchall(self) -> tuple[Mapping[str, Any], ...]:
        return self._rows


class _ScriptedConnection:
    def __init__(
        self,
        script: tuple[tuple[str, _Cursor | BaseException], ...],
        *,
        schema_versions: tuple[int, ...] = (1, 2, 3),
    ) -> None:
        self.script = list(script)
        self.schema_versions = schema_versions
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(
        self,
        query: str,
        params: tuple[object, ...] = (),
    ) -> _Cursor:
        normalized = " ".join(query.split()).lower()
        assert normalized.count("%s") == len(params)
        self.executed.append((normalized, params))
        if normalized.startswith("set transaction isolation level"):
            return _Cursor()
        if "assert_journal_namespace(" in normalized:
            return _Cursor(({"assert_journal_namespace": True},))
        if "select set_config(" in normalized:
            return _Cursor()
        if "control_assurance_pam.schema_migrations" in normalized:
            return _Cursor(
                (
                    {
                        "migration_count": len(self.schema_versions),
                        "minimum_version": (
                            min(self.schema_versions) if self.schema_versions else None
                        ),
                        "maximum_version": (
                            max(self.schema_versions) if self.schema_versions else None
                        ),
                    },
                )
            )
        if not self.script:
            raise AssertionError(f"unexpected SQL: {normalized}")
        expected, outcome = self.script.pop(0)
        assert expected in normalized
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    @contextmanager
    def transaction(self) -> Iterator[object]:
        try:
            yield object()
        except BaseException:
            self.rollbacks += 1
            raise
        else:
            self.commits += 1


class _Pool:
    def __init__(self, connection: _ScriptedConnection) -> None:
        self.connection_value = connection
        self.leases = 0
        self.closed = False

    @contextmanager
    def connection(self) -> Iterator[_ScriptedConnection]:
        self.leases += 1
        yield self.connection_value

    def close(self) -> None:
        self.closed = True


def _elastic_row(
    state: str,
    *,
    revision: int,
    key_id: str | None = None,
    activated: int | None = None,
    revoked: int | None = None,
    attempts: int = 0,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "lease_id": _LEASE_ID,
        "key_name": f"control-assurance-{_LEASE_ID[:32]}",
        "index_alias": ".alerts-security.alerts-default",
        "request_digest": _DIGEST,
        "endpoint_origin_digest": _OTHER_DIGEST,
        "role_descriptor_digest": ElasticPamPolicy(
            ".alerts-security.alerts-default"
        ).role_descriptor_digest,
        "ttl_seconds": 900,
        "state": state,
        "key_id": key_id,
        "expiration_epoch_millis": None if key_id is None else _CREATED + 900_000,
        "created_epoch_millis": _CREATED,
        "activated_epoch_millis": activated,
        "revoked_epoch_millis": revoked,
        "revoke_attempts": attempts,
        "revision": revision,
        "last_error": error,
    }


def _defender_row(
    state: str,
    *,
    revision: int,
    closure: str | None = None,
    issued: int | None = None,
    closed: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "acquisition_id": _ACQUISITION_ID,
        "request_digest": _DIGEST,
        "token_endpoint_digest": _OTHER_DIGEST,
        "graph_origin_digest": _DIGEST,
        "scope_digest": _OTHER_DIGEST,
        "credential_mode": "federated-rs256",
        "credential_reference_digest": _DIGEST,
        "token_request_profile_digest": _OTHER_DIGEST,
        "state": state,
        "closure": closure,
        "created_epoch_millis": _CREATED,
        "issued_epoch_millis": issued,
        "closed_epoch_millis": closed,
        "access_token_expires_epoch_millis": (None if issued is None else issued + 300_000),
        "conservative_exposure_end_epoch_millis": _CREATED + 3_960_000,
        "assertion_id_digest": None if issued is None else _DIGEST,
        "response_request_id_digest": None,
        "revision": revision,
        "last_error": error,
    }


def test_elastic_postgres_journal_uses_immutable_insert_and_fenced_transitions() -> None:
    prepared = _elastic_row("prepared", revision=0)
    active = _elastic_row(
        "active",
        revision=1,
        key_id="elastic-key-id",
        activated=_CREATED + 1,
    )
    pending = _elastic_row(
        "revoke-pending",
        revision=2,
        key_id="elastic-key-id",
        activated=_CREATED + 1,
        attempts=1,
        error="capture failed",
    )
    revoked = _elastic_row(
        "revoked",
        revision=3,
        key_id="elastic-key-id",
        activated=_CREATED + 1,
        revoked=_CREATED + 2,
        attempts=1,
    )
    connection = _ScriptedConnection(
        (
            ("insert into control_assurance_pam.elastic_jit_leases", _Cursor((prepared,))),
            ("update control_assurance_pam.elastic_jit_leases", _Cursor((active,))),
            ("update control_assurance_pam.elastic_jit_leases", _Cursor((pending,))),
            ("update control_assurance_pam.elastic_jit_leases", _Cursor((revoked,))),
            (
                "from control_assurance_pam.elastic_jit_leases",
                _Cursor((prepared, active, pending)),
            ),
        )
    )
    journal = PostgresElasticLeaseJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )
    policy = ElasticPamPolicy(".alerts-security.alerts-default")

    first = journal.prepare(
        lease_id=_LEASE_ID,
        key_name=f"control-assurance-{_LEASE_ID[:32]}",
        policy=policy,
        request_digest=_DIGEST,
        endpoint_origin_digest=_OTHER_DIGEST,
        now_epoch_millis=_CREATED,
    )
    second = journal.activate(
        lease_id=_LEASE_ID,
        expected_revision=first.revision,
        key_id="elastic-key-id",
        expiration_epoch_millis=_CREATED + 900_000,
        now_epoch_millis=_CREATED + 1,
    )
    third = journal.begin_revocation(
        lease_id=_LEASE_ID,
        expected_revision=second.revision,
        reason=" capture \n failed ",
    )
    fourth = journal.mark_revoked(
        lease_id=_LEASE_ID,
        expected_revision=third.revision,
        now_epoch_millis=_CREATED + 2,
    )
    unsettled = journal.unsettled(limit=3)

    assert (first.state, second.state, third.state, fourth.state) == (
        "prepared",
        "active",
        "revoke-pending",
        "revoked",
    )
    assert third.last_error == "capture failed"
    assert [record.revision for record in (first, second, third, fourth)] == [
        0,
        1,
        2,
        3,
    ]
    assert tuple(record.state for record in unsettled) == (
        "prepared",
        "active",
        "revoke-pending",
    )
    assert connection.commits == 5
    assert connection.rollbacks == 0
    assert not connection.script
    assert not any(
        query.startswith(("create ", "alter ", "drop ")) for query, _ in connection.executed
    )
    domain_statements = tuple(
        (query, params)
        for query, params in connection.executed
        if "control_assurance_pam.elastic_jit_leases" in query
    )
    assert all(
        "journal_namespace_digest" in query and _NAMESPACE_DIGEST in params
        for query, params in domain_statements
    )


def test_elastic_cas_failure_rolls_back_and_exposes_no_database_diagnostic() -> None:
    connection = _ScriptedConnection(
        (
            (
                "update control_assurance_pam.elastic_jit_leases",
                _Cursor(),
            ),
        )
    )
    journal = PostgresElasticLeaseJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    with pytest.raises(ElasticPamError, match="lost its state transition") as error:
        journal.activate(
            lease_id=_LEASE_ID,
            expected_revision=0,
            key_id="elastic-key-id",
            expiration_epoch_millis=_CREATED + 900_000,
            now_epoch_millis=_CREATED + 1,
        )

    assert connection.rollbacks == 1
    assert "sql" not in str(error.value).lower()


def test_defender_postgres_journal_recovers_issued_token_once() -> None:
    prepared = _defender_row("prepared", revision=0)
    issued = _defender_row(
        "issued",
        revision=1,
        issued=_CREATED + 1,
    )
    closed = _defender_row(
        "closed",
        revision=2,
        closure="abandoned-after-crash",
        issued=_CREATED + 1,
        closed=_CREATED + 2,
        error="issued token was abandoned after process recovery",
    )
    connection = _ScriptedConnection(
        (
            (
                "insert into control_assurance_pam.defender_token_lifecycle",
                _Cursor((prepared,)),
            ),
            (
                "update control_assurance_pam.defender_token_lifecycle",
                _Cursor((issued,)),
            ),
            (
                "from control_assurance_pam.defender_token_lifecycle",
                _Cursor((issued,)),
            ),
            (
                "update control_assurance_pam.defender_token_lifecycle",
                _Cursor((closed,)),
            ),
            (
                "from control_assurance_pam.defender_token_lifecycle",
                _Cursor(),
            ),
        )
    )
    journal = PostgresDefenderTokenJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    first = journal.prepare(
        acquisition_id=_ACQUISITION_ID,
        request_digest=_DIGEST,
        token_endpoint_digest=_OTHER_DIGEST,
        graph_origin_digest=_DIGEST,
        scope_digest=_OTHER_DIGEST,
        credential_mode="federated-rs256",
        credential_reference_digest=_DIGEST,
        token_request_profile_digest=_OTHER_DIGEST,
        now_epoch_millis=_CREATED,
        conservative_exposure_end_epoch_millis=_CREATED + 3_960_000,
    )
    second = journal.mark_issued(
        acquisition_id=_ACQUISITION_ID,
        expected_revision=first.revision,
        now_epoch_millis=_CREATED + 1,
        expires_epoch_millis=_CREATED + 300_001,
        assertion_id_digest=_DIGEST,
        response_request_id_digest=None,
    )
    assert journal.unsettled() == (second,)
    recovered = journal.close(
        acquisition_id=_ACQUISITION_ID,
        expected_revision=second.revision,
        expected_state="issued",
        closure="abandoned-after-crash",
        now_epoch_millis=_CREATED + 2,
        error="issued token was abandoned after process recovery",
    )

    assert recovered.state == "closed"
    assert recovered.closure == "abandoned-after-crash"
    assert recovered.revision == 2
    assert journal.unsettled() == ()
    assert connection.commits == 5
    assert connection.rollbacks == 0
    assert not connection.script
    domain_statements = tuple(
        (query, params)
        for query, params in connection.executed
        if "control_assurance_pam.defender_token_lifecycle" in query
    )
    assert all(
        "journal_namespace_digest" in query and _NAMESPACE_DIGEST in params
        for query, params in domain_statements
    )


def test_defender_prepared_ambiguity_is_terminal_and_error_is_bounded() -> None:
    uncertain = _defender_row(
        "uncertain",
        revision=1,
        closure="token-request-ambiguous",
        closed=_CREATED + 1,
        error="x" * 384,
    )
    connection = _ScriptedConnection(
        (
            (
                "update control_assurance_pam.defender_token_lifecycle",
                _Cursor((uncertain,)),
            ),
        )
    )
    journal = PostgresDefenderTokenJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    result = journal.mark_uncertain(
        acquisition_id=_ACQUISITION_ID,
        expected_revision=0,
        now_epoch_millis=_CREATED + 1,
        error="x" * 4_000,
    )

    assert result.state == "uncertain"
    update = next(
        params
        for query, params in connection.executed
        if query.startswith("update control_assurance_pam.defender_token_lifecycle")
    )
    assert update[1] == "x" * 384


def test_elastic_recovery_selection_is_scoped_to_one_request_digest() -> None:
    active = _elastic_row(
        "active",
        revision=1,
        key_id="elastic-key-id",
        activated=_CREATED + 1,
    )
    connection = _ScriptedConnection(
        (
            (
                "and request_digest = %s and state != 'revoked'",
                _Cursor((active,)),
            ),
        )
    )
    journal = PostgresElasticLeaseJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    assert journal.records_for_request_digest(
        _DIGEST,
        unsettled_only=True,
    ) == (journal._record(active),)
    query, params = next(
        (query, params)
        for query, params in connection.executed
        if "from control_assurance_pam.elastic_jit_leases" in query
    )
    assert "request_digest = %s" in query
    assert params == (_NAMESPACE_DIGEST, _DIGEST, 1_000)


def test_defender_recovery_selection_is_scoped_to_one_request_digest() -> None:
    issued = _defender_row(
        "issued",
        revision=1,
        issued=_CREATED + 1,
    )
    connection = _ScriptedConnection(
        (
            (
                "and request_digest = %s and state in ('prepared', 'issued')",
                _Cursor((issued,)),
            ),
        )
    )
    journal = PostgresDefenderTokenJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    records = journal.records_for_request_digest(
        _DIGEST,
        unsettled_only=True,
    )

    assert len(records) == 1
    assert records[0].request_digest == _DIGEST
    assert records[0].state == "issued"
    query, params = next(
        (query, params)
        for query, params in connection.executed
        if "from control_assurance_pam.defender_token_lifecycle" in query
    )
    assert "request_digest = %s" in query
    assert params == (_NAMESPACE_DIGEST, _DIGEST, 1_000)


def test_schema_version_and_database_errors_fail_closed_without_raw_details() -> None:
    unsupported = _ScriptedConnection((), schema_versions=(1,))
    with pytest.raises(DefenderPamError, match="schema version"):
        PostgresDefenderTokenJournal(
            _Pool(unsupported),
            journal_namespace_digest=_NAMESPACE_DIGEST,
        ).get(_ACQUISITION_ID)
    assert unsupported.rollbacks == 1

    class _DatabaseFailure(RuntimeError):
        sqlstate = "08006"

    failed = _ScriptedConnection(
        (
            (
                "from control_assurance_pam.elastic_jit_leases",
                _DatabaseFailure("postgres://admin:secret@database/internal"),
            ),
        )
    )
    with pytest.raises(ElasticPamError) as error:
        PostgresElasticLeaseJournal(
            _Pool(failed),
            journal_namespace_digest=_NAMESPACE_DIGEST,
        ).get(_LEASE_ID)
    assert "secret" not in str(error.value)
    assert "postgres://" not in str(error.value)
    assert error.value.__cause__ is None
    assert failed.rollbacks == 1


def test_defender_close_rejects_impossible_state_closure_combinations() -> None:
    journal = PostgresDefenderTokenJournal(
        _Pool(_ScriptedConnection(())),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    with pytest.raises(ValueError, match="prepared token intent"):
        journal.close(
            acquisition_id=_ACQUISITION_ID,
            expected_revision=0,
            expected_state="prepared",
            closure="abandoned-after-crash",
            now_epoch_millis=_CREATED + 1,
            error="crashed",
        )
    with pytest.raises(ValueError, match="requires an error"):
        journal.close(
            acquisition_id=_ACQUISITION_ID,
            expected_revision=1,
            expected_state="issued",
            closure="capture-failed-token-release-only",
            now_epoch_millis=_CREATED + 2,
            error=None,
        )


def test_plan_bound_journal_fences_old_issuance_and_returns_exact_high_watermark() -> None:
    old = _pam_binding(41)
    successor = _pam_binding(42)
    source_request_digest = next(
        scope.connector_request_digest
        for scope in old.pam_scopes
        if scope.authority_class == "source"
    )
    source_scope = old.scope(
        authority_class="source",
        connector_id="elastic-security",
        connector_request_digest=source_request_digest,
    )
    custody_request_digest = next(
        scope.connector_request_digest
        for scope in old.pam_scopes
        if scope.authority_class == "custody"
    )
    custody_scope = old.scope(
        authority_class="custody",
        connector_id="s3-object-lock",
        connector_request_digest=custody_request_digest,
    )
    source_prepared = _lifecycle_row(
        old,
        source_scope,
        lifecycle_sequence=10,
        lifecycle_record_id="elastic:lease-a",
    )
    source_issued = _lifecycle_row(
        old,
        source_scope,
        lifecycle_sequence=10,
        lifecycle_record_id="elastic:lease-a",
        state="issued",
        revision=1,
    )
    custody_prepared = _lifecycle_row(
        old,
        custody_scope,
        lifecycle_sequence=11,
        lifecycle_record_id="custody:object-a",
    )
    successor_prepared = _lifecycle_row(
        successor,
        source_scope,
        lifecycle_sequence=13,
        lifecycle_record_id="elastic:lease-successor",
    )
    operation_digest = _digest("6")
    effective = _CREATED + 10
    fence_row = {
        "operation_digest": operation_digest,
        "fenced_execution_binding_digest": old.execution_binding_digest,
        "successor_execution_binding_digest": successor.execution_binding_digest,
        "snapshot_high_watermark": 12,
        "effective_at_epoch_millis": effective,
        "valid_until_epoch_millis": successor.lease_expires_at_epoch_millis,
    }

    class _DatabaseConflict(RuntimeError):
        sqlstate = "23000"

    connection = _ScriptedConnection(
        (
            ("from control_assurance_pam.execution_bindings", _Cursor()),
            (
                "insert into control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(old, state="active"),)),
            ),
            (
                "insert into control_assurance_pam.execution_binding_scopes",
                _Cursor(_scope_rows(old)),
            ),
            (
                "insert into control_assurance_pam.lifecycle_records",
                _Cursor((source_prepared,)),
            ),
            (
                "update control_assurance_pam.lifecycle_records",
                _Cursor((source_issued,)),
            ),
            (
                "insert into control_assurance_pam.lifecycle_records",
                _Cursor((custody_prepared,)),
            ),
            (
                "from control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(old, state="active"),)),
            ),
            (
                "update control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(old, state="fenced"),)),
            ),
            (
                "insert into control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(successor, state="active"),)),
            ),
            (
                "insert into control_assurance_pam.execution_binding_scopes",
                _Cursor(_scope_rows(successor)),
            ),
            (
                "select nextval",
                _Cursor(({"snapshot_high_watermark": 12},)),
            ),
            (
                "insert into control_assurance_pam.issuance_fences",
                _Cursor((fence_row,)),
            ),
            (
                "insert into control_assurance_pam.lifecycle_records",
                _DatabaseConflict("old binding fenced"),
            ),
            (
                "update control_assurance_pam.lifecycle_records",
                _DatabaseConflict("old binding fenced"),
            ),
            (
                "insert into control_assurance_pam.lifecycle_records",
                _Cursor((successor_prepared,)),
            ),
            (
                "from control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(old, state="fenced"),)),
            ),
            (
                "from control_assurance_pam.issuance_fences",
                _Cursor((fence_row,)),
            ),
            (
                "from control_assurance_pam.execution_binding_scopes",
                _Cursor(_scope_rows(old)),
            ),
            (
                "count(*) filter",
                _Cursor(
                    (
                        {
                            "matching_record_count": 2,
                            "records_after_high_watermark": 0,
                        },
                    )
                ),
            ),
            (
                "from control_assurance_pam.lifecycle_records",
                _Cursor((source_issued, custody_prepared)),
            ),
        )
    )
    journal = PostgresPamIssuanceJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    assert (
        journal.register_execution_binding(
            old,
            registered_at_epoch_millis=_CREATED,
        )
        == old
    )
    prepared = journal.prepare_lifecycle(
        old,
        source_scope,
        lifecycle_record_id="elastic:lease-a",
        credential_reference_digest=None,
        created_epoch_millis=_CREATED,
        maximum_residual_exposure_ends_epoch_millis=_CREATED + 101,
    )
    issued = journal.mark_lifecycle_issued(
        old,
        lifecycle_record_id=prepared.lifecycle_record_id,
        expected_revision=prepared.revision,
        issued_epoch_millis=_CREATED + 1,
        expires_epoch_millis=_CREATED + 101,
        maximum_residual_exposure_ends_epoch_millis=_CREATED + 101,
    )
    custody = journal.prepare_lifecycle(
        old,
        custody_scope,
        lifecycle_record_id="custody:object-a",
        credential_reference_digest=None,
        created_epoch_millis=_CREATED,
        maximum_residual_exposure_ends_epoch_millis=_CREATED + 101,
    )
    fence = journal.install_recovery_issuance_fence(
        old,
        successor,
        operation_digest=operation_digest,
        effective_at_epoch_millis=effective,
        valid_until_epoch_millis=successor.lease_expires_at_epoch_millis,
    )

    with pytest.raises(PostgresPamRecoveryError, match="write conflicted"):
        journal.prepare_lifecycle(
            old,
            source_scope,
            lifecycle_record_id="elastic:stale-prepare",
            credential_reference_digest=None,
            created_epoch_millis=effective,
            maximum_residual_exposure_ends_epoch_millis=effective + 100,
        )
    with pytest.raises(PostgresPamRecoveryError, match="write conflicted"):
        journal.mark_lifecycle_issued(
            old,
            lifecycle_record_id=custody.lifecycle_record_id,
            expected_revision=custody.revision,
            issued_epoch_millis=effective + 1,
            expires_epoch_millis=effective + 2,
            maximum_residual_exposure_ends_epoch_millis=effective + 2,
        )

    successor_record = journal.prepare_lifecycle(
        successor,
        source_scope,
        lifecycle_record_id="elastic:lease-successor",
        credential_reference_digest=None,
        created_epoch_millis=effective,
        maximum_residual_exposure_ends_epoch_millis=effective + 100,
    )
    snapshot = journal.lifecycle_snapshot(old)

    assert (issued.lifecycle_sequence, custody.lifecycle_sequence) == (10, 11)
    assert fence.snapshot_high_watermark == 12
    assert successor_record.lifecycle_sequence == 13
    assert snapshot.snapshot_high_watermark == 12
    assert snapshot.matching_record_count == 2
    assert tuple(record.lifecycle_sequence for record in snapshot.records) == (10, 11)
    assert tuple(record.state for record in snapshot.records) == ("issued", "prepared")
    assert not snapshot.all_matching_records_settled
    assert connection.commits == 7
    assert connection.rollbacks == 2
    assert not connection.script


def test_lifecycle_snapshot_rejects_any_difference_from_database_count() -> None:
    old = _pam_binding(51)
    successor = _pam_binding(52)
    source_scope = old.pam_scopes[-1]
    record = _lifecycle_row(
        old,
        source_scope,
        lifecycle_sequence=100,
        lifecycle_record_id="source:one",
    )
    fence_row = {
        "operation_digest": _digest("7"),
        "fenced_execution_binding_digest": old.execution_binding_digest,
        "successor_execution_binding_digest": successor.execution_binding_digest,
        "snapshot_high_watermark": 101,
        "effective_at_epoch_millis": _CREATED,
        "valid_until_epoch_millis": successor.lease_expires_at_epoch_millis,
    }
    connection = _ScriptedConnection(
        (
            (
                "from control_assurance_pam.execution_bindings",
                _Cursor((_binding_row(old, state="fenced"),)),
            ),
            (
                "from control_assurance_pam.issuance_fences",
                _Cursor((fence_row,)),
            ),
            (
                "from control_assurance_pam.execution_binding_scopes",
                _Cursor(_scope_rows(old)),
            ),
            (
                "count(*) filter",
                _Cursor(
                    (
                        {
                            "matching_record_count": 2,
                            "records_after_high_watermark": 0,
                        },
                    )
                ),
            ),
            (
                "from control_assurance_pam.lifecycle_records",
                _Cursor((record,)),
            ),
        )
    )
    journal = PostgresPamIssuanceJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    with pytest.raises(PostgresPamRecoveryError, match="differ from the DB count"):
        journal.lifecycle_snapshot(old)

    assert connection.rollbacks == 1


@pytest.mark.parametrize(
    "schema_versions",
    [(), (1,), (2,), (1, 2, 4)],
)
def test_schema_migration_lineage_must_be_exact_and_contiguous(
    schema_versions: tuple[int, ...],
) -> None:
    connection = _ScriptedConnection((), schema_versions=schema_versions)
    journal = PostgresPamIssuanceJournal(
        _Pool(connection),
        journal_namespace_digest=_NAMESPACE_DIGEST,
    )

    with pytest.raises(PostgresPamRecoveryError, match="schema version"):
        journal.register_execution_binding(
            _pam_binding(61),
            registered_at_epoch_millis=_CREATED,
        )

    assert connection.rollbacks == 1


def test_schema_declares_expiry_fences_append_only_evidence_and_no_public_api() -> None:
    schema = (
        Path(__file__).parents[1] / "deploy" / "postgres" / "pam-journal-schema.sql"
    ).read_text(encoding="utf-8")

    assert "MAXVALUE 9007199254740991" in schema
    assert "execution_binding_registration_precedes_expiry" in schema
    assert "clock_timestamp()" in schema
    assert "PAM issuance binding is fenced, expired, or absent" in schema
    assert "PAM recovery evidence is append-only" in schema
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_pam FROM PUBLIC" in schema


def test_postgres_journals_satisfy_the_existing_broker_protocols() -> None:
    pool = _Pool(_ScriptedConnection(()))

    assert isinstance(
        PostgresElasticLeaseJournal(
            pool,
            journal_namespace_digest=_NAMESPACE_DIGEST,
        ),
        ElasticLeaseJournal,
    )
    assert isinstance(
        PostgresDefenderTokenJournal(
            pool,
            journal_namespace_digest=_NAMESPACE_DIGEST,
        ),
        DefenderTokenJournal,
    )


@pytest.mark.parametrize(
    "journal_type",
    [PostgresElasticLeaseJournal, PostgresDefenderTokenJournal],
)
def test_postgres_journals_require_a_canonical_namespace_digest(
    journal_type: type[PostgresElasticLeaseJournal] | type[PostgresDefenderTokenJournal],
) -> None:
    with pytest.raises(ValueError, match="journal namespace digest"):
        journal_type(
            _Pool(_ScriptedConnection(())),
            journal_namespace_digest="tenant-name",
        )


@pytest.mark.parametrize(
    ("journal_type", "error_type"),
    [
        (PostgresElasticLeaseJournal, ElasticPamError),
        (PostgresDefenderTokenJournal, DefenderPamError),
    ],
)
def test_pool_startup_errors_cannot_reflect_the_dsn(
    monkeypatch: pytest.MonkeyPatch,
    journal_type: type[PostgresElasticLeaseJournal] | type[PostgresDefenderTokenJournal],
    error_type: type[ElasticPamError] | type[DefenderPamError],
) -> None:
    class _FailingPool:
        def __init__(self, **_kwargs: object) -> None:
            raise ValueError("postgresql://admin:supersecret@database/pam")

    def import_module(name: str) -> object:
        if name == "psycopg_pool":
            return SimpleNamespace(ConnectionPool=_FailingPool)
        if name == "psycopg.rows":
            return SimpleNamespace(dict_row=object())
        raise AssertionError(f"unexpected import: {name}")

    monkeypatch.setattr(
        "assurance_lab.connectors.postgres_pam_journal.importlib.import_module",
        import_module,
    )

    with pytest.raises(error_type) as error:
        journal_type.from_dsn(
            "postgresql://admin:supersecret@database/pam",
            journal_namespace_digest=_NAMESPACE_DIGEST,
        )

    assert "supersecret" not in str(error.value)
    assert "postgresql://" not in str(error.value)
    assert error.value.__cause__ is None
