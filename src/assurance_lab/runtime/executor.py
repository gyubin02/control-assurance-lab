"""Durable execution of one frozen managed SIEM or EDR observation.

The scheduler lease is intentionally not treated as durable execution state.
Before any secret lookup or vendor call, this executor stores one immutable
connector plan in the PostgreSQL execution journal and advances that attempt
to ``publishing``.  Every retry reopens those exact bytes.  A completed Object
Lock closure is returned from the journal without calling the source again.

The environment provider is the deployment seam for secret resolution,
short-lived authorization, custody, and signing.  None of its credential
material is accepted by, or persisted through, this module.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from assurance_lab._version import __version__
from assurance_lab.evidence.admission import ReceiptSigner
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.stream_custody import StreamCustodyAdapter
from assurance_lab.runtime.evidence_publication import (
    ManagedEvidencePublication,
    publish_managed_evidence,
)
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    ExecutionEnvironmentIdentityError,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_journal import (
    ExecutionJournalConflict,
    ExecutionJournalIntegrityError,
    ExecutionJournalNotFound,
    ExecutionJournalOutcomeUnknown,
    ExecutionJournalRecord,
    ExecutionJournalUnavailable,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    ControlRunExecutionPlanError,
    create_control_run_execution_plan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import PreparedManagedSource
from assurance_lab.runtime.models import (
    ControlRunExecutionError,
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunOutcomeUnknown,
    sha256_digest,
    utc_second,
)

_PORTABLE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_STAGE_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_INTEGRITY_STAGES = frozenset(
    {
        "authorization",
        "configuration",
        "descriptor",
        "execution-identity",
        "input",
        "integrity",
        "job",
        "plan",
        "profile",
        "request",
        "snapshot",
        "source-binding",
        "source-registration",
        "source-registry",
        "custody-runtime",
        "verification",
    }
)


class ExecutionJournal(Protocol):
    """Minimal fenced journal surface consumed by the executor."""

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        *,
        worker_id: str,
        lease_token_digest: str,
        execution_plan_bytes: bytes | None,
    ) -> ExecutionJournalRecord: ...

    def get(self, *, tenant_id: str, run_id: str) -> ExecutionJournalRecord: ...

    def begin_publishing(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
    ) -> ExecutionJournalRecord: ...

    def bind_execution_identity(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        execution_identity_digest: str,
        execution_identity_bytes: bytes,
    ) -> ExecutionJournalRecord: ...

    def mark_failed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        error_code: str,
    ) -> ExecutionJournalRecord: ...

    def mark_uncertain(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        error_code: str,
    ) -> ExecutionJournalRecord: ...

    def mark_completed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        result: ControlRunExecutionResult,
        executor_receipt_bytes: bytes,
    ) -> ExecutionJournalRecord: ...


@dataclass(frozen=True, slots=True)
class PreparedExecutionEnvironment:
    """Secret handles plus the public identity that must be journaled first."""

    source: PreparedManagedSource
    custody: StreamCustodyAdapter
    receipt_signer: ReceiptSigner
    execution_identity_bytes: bytes
    execution_identity_digest: str
    execution_identity_media_type: str
    custody_deployment_profile_digest: str

    def __post_init__(self) -> None:
        if type(self.source) is not PreparedManagedSource:
            raise TypeError("execution environment source must be exact")
        for name in (
            "put_bytes",
            "put_file",
            "verify_acknowledgement_scope",
            "reverify_acknowledgement",
        ):
            if not callable(getattr(self.custody, name, None)):
                raise TypeError("execution environment custody adapter is invalid")
        if (
            not callable(getattr(self.receipt_signer, "sign", None))
            or not hasattr(self.receipt_signer, "key_id")
            or not hasattr(self.receipt_signer, "public_key_bytes")
        ):
            raise TypeError("execution environment receipt signer is invalid")
        try:
            identity = parse_execution_environment_identity(
                self.execution_identity_bytes
            )
        except ExecutionEnvironmentIdentityError as exc:
            raise ValueError("execution environment identity is invalid") from exc
        if (
            identity.digest != self.execution_identity_digest
            or self.execution_identity_media_type
            != EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
            or identity.custody_deployment_profile_digest
            != self.custody_deployment_profile_digest
        ):
            raise ValueError("execution environment identity fields differ")


class ExecutionEnvironmentProvider(Protocol):
    """Resolve exact runtime dependencies without returning credential bytes."""

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedExecutionEnvironment: ...


PublicationCallable = Callable[
    ...,
    ManagedEvidencePublication,
]


def _system_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _attempt_token_digest(
    *,
    request: ControlRunExecutionRequest,
    worker_id: str,
) -> str:
    """Derive a stable same-fence CAS identity, not an authentication secret."""

    return sha256_digest(
        canonical_json_bytes(
            {
                "domain": "control-assurance:execution-attempt-cas:v1",
                "lease_fence": request.lease_fence,
                "run_id": request.run_id,
                "tenant_id": request.tenant_id,
                "worker_id": worker_id,
            }
        )
    )


def _publication_failure(exc: BaseException) -> tuple[str, bool]:
    if isinstance(exc, (TypeError, ValueError)):
        return "executor-publication-integrity", False
    stage = getattr(exc, "stage", None)
    if type(stage) is not str or _STAGE_RE.fullmatch(stage) is None:
        return "executor-publication-unknown", True
    code = f"executor-{stage}"
    return code, stage not in _INTEGRITY_STAGES


class DurableControlRunExecutor:
    """Fenced, retry-safe implementation of the runtime executor protocol."""

    __slots__ = (
        "_environment_provider",
        "_journal",
        "_nonce_bytes",
        "_now",
        "_publish",
        "_source_revision",
        "_work_root",
        "_worker_id",
    )

    def __init__(
        self,
        journal: ExecutionJournal,
        environment_provider: ExecutionEnvironmentProvider,
        *,
        work_root: Path,
        worker_id: str,
        source_revision: str = __version__,
        now: Callable[[], datetime] | None = None,
        nonce_bytes: Callable[[int], bytes] | None = None,
        publish: PublicationCallable = publish_managed_evidence,
    ) -> None:
        journal_methods = (
            "prepare",
            "get",
            "begin_publishing",
            "bind_execution_identity",
            "mark_failed",
            "mark_uncertain",
            "mark_completed",
        )
        if any(not callable(getattr(journal, name, None)) for name in journal_methods):
            raise TypeError("execution journal does not implement the required surface")
        if not callable(getattr(environment_provider, "prepare", None)):
            raise TypeError("execution environment provider is invalid")
        if not isinstance(work_root, Path) or not work_root.is_absolute():
            raise ValueError("execution work root must be an absolute pathlib.Path")
        if type(worker_id) is not str or _PORTABLE_ID_RE.fullmatch(worker_id) is None:
            raise ValueError("executor worker id is not portable")
        if (
            type(source_revision) is not str
            or not source_revision
            or len(source_revision) > 256
        ):
            raise ValueError("executor source revision is invalid")
        if not callable(publish):
            raise TypeError("managed evidence publisher must be callable")
        self._journal = journal
        self._environment_provider = environment_provider
        self._work_root = work_root
        self._worker_id = worker_id
        self._source_revision = source_revision
        self._now = now or _system_now
        self._nonce_bytes = nonce_bytes or secrets.token_bytes
        self._publish = publish

    def _time(self) -> datetime:
        try:
            return utc_second(self._now(), label="executor clock")
        except (TypeError, ValueError) as exc:
            raise ControlRunExecutionError(
                "executor-clock-invalid",
                retryable=False,
            ) from exc

    def _new_plan(self, request: ControlRunExecutionRequest) -> ControlRunExecutionPlan:
        nonce = self._nonce_bytes(32)
        if type(nonce) is not bytes or len(nonce) != 32:
            raise ControlRunExecutionError(
                "executor-entropy-invalid",
                retryable=False,
            )
        try:
            return create_control_run_execution_plan(
                request,
                capture_nonce=nonce.hex(),
                prepared_at=self._time(),
                source_revision=self._source_revision,
            )
        except ControlRunExecutionPlanError as exc:
            raise ControlRunExecutionError(
                "executor-plan-invalid",
                retryable=False,
            ) from exc

    def _prepare(
        self,
        request: ControlRunExecutionRequest,
        *,
        attempt_token: str,
    ) -> ExecutionJournalRecord:
        try:
            return self._journal.prepare(
                request,
                worker_id=self._worker_id,
                lease_token_digest=attempt_token,
                execution_plan_bytes=None,
            )
        except ExecutionJournalNotFound:
            plan = self._new_plan(request)
            try:
                return self._journal.prepare(
                    request,
                    worker_id=self._worker_id,
                    lease_token_digest=attempt_token,
                    execution_plan_bytes=plan.canonical_bytes(),
                )
            except ExecutionJournalConflict:
                # Another HA worker may have won the insert.  Only the durable
                # plan is authoritative; never reuse the losing nonce.
                return self._journal.prepare(
                    request,
                    worker_id=self._worker_id,
                    lease_token_digest=attempt_token,
                    execution_plan_bytes=None,
                )

    @staticmethod
    def _result_for_request(
        record: ExecutionJournalRecord,
        request: ControlRunExecutionRequest,
    ) -> ControlRunExecutionResult:
        if (
            record.evidence_digest is None
            or record.executor_receipt_digest is None
            or record.executor_receipt_bytes is None
            or sha256_digest(record.executor_receipt_bytes)
            != record.executor_receipt_digest
        ):
            raise ControlRunExecutionError(
                "executor-journal-integrity",
                retryable=False,
            )
        return ControlRunExecutionResult(
            run_id=request.run_id,
            lease_fence=request.lease_fence,
            evidence_digest=record.evidence_digest,
            executor_receipt_digest=record.executor_receipt_digest,
        )

    def _reread_completed(
        self,
        request: ControlRunExecutionRequest,
        *,
        expected_receipt_bytes: bytes | None = None,
    ) -> ControlRunExecutionResult | None:
        current = self._journal.get(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
        )
        if current.state != "completed":
            return None
        if (
            expected_receipt_bytes is not None
            and current.executor_receipt_bytes != expected_receipt_bytes
        ):
            raise ControlRunExecutionError(
                "executor-result-conflict",
                retryable=False,
            )
        return self._result_for_request(current, request)

    def _mark_prepublication_failure(
        self,
        record: ExecutionJournalRecord,
        request: ControlRunExecutionRequest,
        *,
        attempt_token: str,
        code: str,
    ) -> None:
        try:
            self._journal.mark_failed(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                lease_fence=request.lease_fence,
                worker_id=self._worker_id,
                lease_token_digest=attempt_token,
                expected_revision=record.revision,
                error_code=code,
            )
        except (
            ExecutionJournalConflict,
            ExecutionJournalOutcomeUnknown,
            ExecutionJournalUnavailable,
        ) as exc:
            raise ControlRunOutcomeUnknown("executor-journal-outcome-unknown") from exc

    def _mark_publication_uncertain(
        self,
        record: ExecutionJournalRecord,
        request: ControlRunExecutionRequest,
        *,
        attempt_token: str,
        code: str,
    ) -> None:
        try:
            self._journal.mark_uncertain(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                lease_fence=request.lease_fence,
                worker_id=self._worker_id,
                lease_token_digest=attempt_token,
                expected_revision=record.revision,
                error_code=code,
            )
        except (
            ExecutionJournalConflict,
            ExecutionJournalOutcomeUnknown,
            ExecutionJournalUnavailable,
        ) as exc:
            raise ControlRunOutcomeUnknown("executor-journal-outcome-unknown") from exc

    @staticmethod
    def _validate_environment(
        environment: PreparedExecutionEnvironment,
        *,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        expected_identity_bytes: bytes | None,
    ) -> None:
        if type(environment) is not PreparedExecutionEnvironment:
            raise TypeError("environment provider returned an invalid value")
        try:
            identity = parse_execution_environment_identity(
                environment.execution_identity_bytes
            )
        except ExecutionEnvironmentIdentityError as exc:
            raise ValueError("execution environment identity is invalid") from exc
        if (
            identity.run_id != request.run_id
            or identity.tenant_id != request.tenant_id
            or identity.control_id != request.control_id
            or identity.configuration_digest != request.configuration_digest
            or identity.execution_plan_digest != plan.digest
            or identity.source_revision != plan.source_revision
            or identity.digest != environment.execution_identity_digest
            or (
                expected_identity_bytes is not None
                and environment.execution_identity_bytes
                != expected_identity_bytes
            )
        ):
            raise ValueError(
                "execution environment crossed the frozen execution boundary"
            )

    def _bind_execution_environment(
        self,
        record: ExecutionJournalRecord,
        request: ControlRunExecutionRequest,
        environment: PreparedExecutionEnvironment,
        *,
        attempt_token: str,
    ) -> ExecutionJournalRecord:
        """Durably bind public composition before any external side effect."""

        identity_bytes = environment.execution_identity_bytes
        identity_digest = environment.execution_identity_digest
        try:
            bound = self._journal.bind_execution_identity(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                lease_fence=request.lease_fence,
                worker_id=self._worker_id,
                lease_token_digest=attempt_token,
                expected_revision=record.revision,
                execution_identity_digest=identity_digest,
                execution_identity_bytes=identity_bytes,
            )
        except (ExecutionJournalOutcomeUnknown, ExecutionJournalConflict) as exc:
            try:
                current = self._journal.get(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                )
            except (
                ExecutionJournalIntegrityError,
                ExecutionJournalNotFound,
                ExecutionJournalUnavailable,
            ) as read_exc:
                raise ControlRunOutcomeUnknown(
                    "executor-identity-outcome-unknown"
                ) from read_exc
            if (
                current.state not in {"publishing", "completed"}
                or current.highest_lease_fence != request.lease_fence
                or current.request.lease_fence != request.lease_fence
                or current.worker_id != self._worker_id
                or current.lease_token_digest != attempt_token
                or current.execution_identity_digest != identity_digest
                or current.execution_identity_bytes != identity_bytes
            ):
                if isinstance(exc, ExecutionJournalConflict):
                    raise ControlRunExecutionError(
                        "executor-identity-conflict",
                        retryable=False,
                    ) from exc
                raise ControlRunOutcomeUnknown(
                    "executor-identity-outcome-unknown"
                ) from exc
            bound = current
        except ExecutionJournalIntegrityError as exc:
            raise ControlRunExecutionError(
                "executor-journal-integrity",
                retryable=False,
            ) from exc
        except ExecutionJournalUnavailable as exc:
            raise ControlRunOutcomeUnknown(
                "executor-identity-outcome-unknown"
            ) from exc
        if (
            bound.execution_identity_digest != identity_digest
            or bound.execution_identity_bytes != identity_bytes
            or bound.state not in {"publishing", "completed"}
        ):
            raise ControlRunExecutionError(
                "executor-identity-conflict",
                retryable=False,
            )
        return bound

    def ensure_executed(
        self,
        request: ControlRunExecutionRequest,
    ) -> ControlRunExecutionResult:
        """Return the sole durable result for ``request.run_id``."""

        if type(request) is not ControlRunExecutionRequest:
            raise TypeError("execution request must be exact")
        attempt_token = _attempt_token_digest(
            request=request,
            worker_id=self._worker_id,
        )
        try:
            record = self._prepare(request, attempt_token=attempt_token)
        except ExecutionJournalIntegrityError as exc:
            raise ControlRunExecutionError(
                "executor-journal-integrity",
                retryable=False,
            ) from exc
        except ExecutionJournalConflict as exc:
            raise ControlRunExecutionError(
                "executor-journal-conflict",
                retryable=True,
            ) from exc
        except (
            ExecutionJournalOutcomeUnknown,
            ExecutionJournalUnavailable,
        ) as exc:
            raise ControlRunOutcomeUnknown("executor-journal-outcome-unknown") from exc

        if record.state == "completed":
            return self._result_for_request(record, request)
        if record.state == "uncertain":
            raise ControlRunOutcomeUnknown("executor-recovery-required")
        if record.state == "failed":
            raise ControlRunExecutionError(
                record.error_code or "executor-attempt-failed",
                retryable=True,
            )

        try:
            plan, _connector_request = verify_control_run_execution_plan(
                record.execution_plan_bytes,
                expected_request=request,
            )
        except ControlRunExecutionPlanError as exc:
            raise ControlRunExecutionError(
                "executor-journal-integrity",
                retryable=False,
            ) from exc
        if plan.source_revision != self._source_revision:
            if record.state == "prepared":
                self._mark_prepublication_failure(
                    record,
                    request,
                    attempt_token=attempt_token,
                    code="executor-revision-mismatch",
                )
            raise ControlRunExecutionError(
                "executor-revision-mismatch",
                retryable=False,
            )
        if plan.custody_retain_until <= self._time():
            if record.state == "prepared":
                self._mark_prepublication_failure(
                    record,
                    request,
                    attempt_token=attempt_token,
                    code="executor-plan-expired",
                )
            raise ControlRunExecutionError(
                "executor-plan-expired",
                retryable=False,
            )

        if record.state == "prepared":
            try:
                record = self._journal.begin_publishing(
                    tenant_id=request.tenant_id,
                    run_id=request.run_id,
                    lease_fence=request.lease_fence,
                    worker_id=self._worker_id,
                    lease_token_digest=attempt_token,
                    expected_revision=record.revision,
                )
            except ExecutionJournalOutcomeUnknown:
                try:
                    recovered = self._reread_completed(request)
                    if recovered is not None:
                        return recovered
                    record = self._journal.get(
                        tenant_id=request.tenant_id,
                        run_id=request.run_id,
                    )
                except (
                    ExecutionJournalConflict,
                    ExecutionJournalIntegrityError,
                    ExecutionJournalNotFound,
                    ExecutionJournalUnavailable,
                ) as exc:
                    raise ControlRunOutcomeUnknown(
                        "executor-journal-outcome-unknown"
                    ) from exc
            except ExecutionJournalConflict as exc:
                raise ControlRunExecutionError(
                    "executor-journal-conflict",
                    retryable=True,
                ) from exc
            except ExecutionJournalIntegrityError as exc:
                raise ControlRunExecutionError(
                    "executor-journal-integrity",
                    retryable=False,
                ) from exc
            except ExecutionJournalUnavailable as exc:
                raise ControlRunOutcomeUnknown(
                    "executor-journal-outcome-unknown"
                ) from exc
        if record.state == "completed":
            return self._result_for_request(record, request)
        if record.state != "publishing":
            raise ControlRunOutcomeUnknown("executor-recovery-required")

        try:
            environment = self._environment_provider.prepare(
                request,
                plan,
                expected_identity_bytes=record.execution_identity_bytes,
            )
            self._validate_environment(
                environment,
                request=request,
                plan=plan,
                expected_identity_bytes=record.execution_identity_bytes,
            )
        except Exception as exc:
            code, retryable = _publication_failure(exc)
            self._mark_prepublication_failure(
                record,
                request,
                attempt_token=attempt_token,
                code=code,
            )
            raise ControlRunExecutionError(code, retryable=retryable) from exc

        record = self._bind_execution_environment(
            record,
            request,
            environment,
            attempt_token=attempt_token,
        )
        if record.state == "completed":
            return self._result_for_request(record, request)

        try:
            publication = self._publish(
                request,
                plan,
                environment.source,
                work_root=self._work_root,
                custody=environment.custody,
                receipt_signer=environment.receipt_signer,
                source_revision=plan.source_revision,
                execution_environment_identity_bytes=(
                    environment.execution_identity_bytes
                ),
            )
            if (
                type(publication) is not ManagedEvidencePublication
                or publication.run_id != request.run_id
                or publication.artifact_set_id != plan.artifact_set_id
                or publication.custody_scope_id != plan.custody_scope_id
                or publication.executor_receipt_id != plan.executor_receipt_id
                or sha256_digest(publication.executor_receipt_bytes)
                != publication.executor_receipt_digest
            ):
                raise ValueError("publication crossed the frozen execution boundary")
        except Exception as exc:
            code, retryable = _publication_failure(exc)
            self._mark_publication_uncertain(
                record,
                request,
                attempt_token=attempt_token,
                code=code,
            )
            raise ControlRunExecutionError(code, retryable=retryable) from exc

        result = ControlRunExecutionResult(
            run_id=request.run_id,
            lease_fence=request.lease_fence,
            evidence_digest=publication.evidence_digest,
            executor_receipt_digest=publication.executor_receipt_digest,
        )
        try:
            completed = self._journal.mark_completed(
                tenant_id=request.tenant_id,
                run_id=request.run_id,
                lease_fence=request.lease_fence,
                worker_id=self._worker_id,
                lease_token_digest=attempt_token,
                expected_revision=record.revision,
                result=result,
                executor_receipt_bytes=publication.executor_receipt_bytes,
            )
        except ExecutionJournalOutcomeUnknown:
            try:
                recovered = self._reread_completed(
                    request,
                    expected_receipt_bytes=publication.executor_receipt_bytes,
                )
            except (
                ExecutionJournalIntegrityError,
                ExecutionJournalNotFound,
                ExecutionJournalUnavailable,
            ) as exc:
                raise ControlRunOutcomeUnknown(
                    "executor-journal-outcome-unknown"
                ) from exc
            if recovered is None:
                raise ControlRunOutcomeUnknown(
                    "executor-journal-outcome-unknown"
                ) from None
            return recovered
        except ExecutionJournalConflict as exc:
            try:
                recovered = self._reread_completed(
                    request,
                    expected_receipt_bytes=publication.executor_receipt_bytes,
                )
            except (
                ExecutionJournalIntegrityError,
                ExecutionJournalNotFound,
                ExecutionJournalUnavailable,
            ):
                recovered = None
            if recovered is not None:
                return recovered
            raise ControlRunExecutionError(
                "executor-result-conflict",
                retryable=False,
            ) from exc
        except ExecutionJournalIntegrityError as exc:
            raise ControlRunExecutionError(
                "executor-journal-integrity",
                retryable=False,
            ) from exc
        except ExecutionJournalUnavailable as exc:
            raise ControlRunOutcomeUnknown(
                "executor-journal-outcome-unknown"
            ) from exc
        if completed.state != "completed":
            raise ControlRunOutcomeUnknown("executor-journal-outcome-unknown")
        return self._result_for_request(completed, request)


__all__ = [
    "DurableControlRunExecutor",
    "ExecutionEnvironmentProvider",
    "ExecutionJournal",
    "PreparedExecutionEnvironment",
]
