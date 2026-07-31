from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.control_plane.models import Actor
from assurance_lab.control_plane.oidc import (
    AuthorizationTransaction,
    OIDCError,
    OIDCLoginAdmissionPolicy,
    OIDCStateStore,
    SessionRecord,
)
from assurance_lab.control_plane.postgres_oidc_store import (
    PostgresOIDCStateStore,
    ProtectedCodeVerifier,
)

_NOW = datetime(2026, 7, 29, 4, 0, tzinfo=UTC)
_TRANSACTION_DIGEST = f"sha256:{'1' * 64}"
_STATE_DIGEST = f"sha256:{'2' * 64}"
_NONCE_DIGEST = f"sha256:{'3' * 64}"
_SESSION_DIGEST = f"sha256:{'4' * 64}"
_SOURCE_DIGEST = f"hmac-sha256:{'5' * 64}"
_VERIFIER = "A" * 43
_ADMISSION = OIDCLoginAdmissionPolicy()
_DATABASE_ROLE = "assurance_auth_runtime"


class _Cursor:
    def __init__(
        self,
        rows: Sequence[Mapping[str, Any]] = (),
        *,
        rowcount: int = 0,
    ) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self) -> Mapping[str, Any] | None:
        return None if not self._rows else self._rows[0]

    def fetchall(self) -> Sequence[Mapping[str, Any]]:
        return tuple(self._rows)


class _Connection:
    def __init__(
        self,
        script: Sequence[tuple[str, _Cursor]],
        *,
        schema_versions: Sequence[int] = (2, 5, 6),
    ) -> None:
        self.script = list(script)
        self.schema_versions = list(schema_versions)
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.in_transaction = False
        self.commits = 0
        self.rollbacks = 0

    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> _Cursor:
        normalized = " ".join(query.split()).lower()
        self.executed.append((normalized, tuple(params)))
        if normalized.startswith("set transaction isolation level"):
            return _Cursor()
        if "select set_config(" in normalized:
            return _Cursor()
        if "control_assurance_auth.runtime_identity()" in normalized:
            return _Cursor(
                (
                    {
                        "session_user": _DATABASE_ROLE,
                        "current_user": _DATABASE_ROLE,
                        "current_role": _DATABASE_ROLE,
                        "login_role": _DATABASE_ROLE,
                        "tenant_id": "acme-bank",
                        "role_kind": "auth",
                        "schema_versions": self.schema_versions,
                    },
                )
            )
        if not self.script:
            raise AssertionError(f"unexpected SQL: {normalized}")
        expected, cursor = self.script.pop(0)
        assert expected in normalized
        return cursor

    @contextmanager
    def transaction(self) -> Iterator[object]:
        assert not self.in_transaction
        self.in_transaction = True
        try:
            yield object()
        except BaseException:
            self.rollbacks += 1
            raise
        else:
            self.commits += 1
        finally:
            self.in_transaction = False


class _Pool:
    def __init__(self, connection: _Connection) -> None:
        self.connection_value = connection
        self.leases = 0
        self.close_calls = 0

    @contextmanager
    def connection(self) -> Iterator[_Connection]:
        self.leases += 1
        yield self.connection_value

    def close(self) -> None:
        self.close_calls += 1


class _Protector:
    def __init__(self, connection: _Connection, *, fail_protect: bool = False) -> None:
        self.connection = connection
        self.fail_protect = fail_protect
        self.protect_calls = 0
        self.unprotect_calls = 0

    def protect(
        self,
        *,
        code_verifier: str,
        transaction_digest: str,
    ) -> ProtectedCodeVerifier:
        assert not self.connection.in_transaction
        self.protect_calls += 1
        if self.fail_protect:
            raise RuntimeError("private KMS diagnostic")
        payload = hashlib.sha256(transaction_digest.encode()).digest() + code_verifier.encode()
        return ProtectedCodeVerifier(
            ciphertext=payload,
            key_reference="test-kms://oidc/pkce/v1",
            algorithm="TEST-SHA256-BOUND",
        )

    def unprotect(
        self,
        *,
        protected: ProtectedCodeVerifier,
        transaction_digest: str,
    ) -> str:
        assert not self.connection.in_transaction
        self.unprotect_calls += 1
        prefix = hashlib.sha256(transaction_digest.encode()).digest()
        assert protected.ciphertext.startswith(prefix)
        return protected.ciphertext[len(prefix) :].decode()


def _store(
    pool: _Pool,
    *,
    protector: _Protector,
    **kwargs: Any,
) -> PostgresOIDCStateStore:
    return PostgresOIDCStateStore(
        pool,
        tenant_id="acme-bank",
        expected_role=_DATABASE_ROLE,
        protector=protector,
        **kwargs,
    )


def _transaction() -> AuthorizationTransaction:
    return AuthorizationTransaction(
        transaction_digest=_TRANSACTION_DIGEST,
        state_digest=_STATE_DIGEST,
        nonce_digest=_NONCE_DIGEST,
        code_verifier=_VERIFIER,
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )


def _actor() -> Actor:
    return Actor(
        tenant_id="acme-bank",
        subject="oidc:alice",
        display_name="Alice",
        roles=frozenset({"viewer", "editor"}),
        groups=("secops/platform",),
        authenticated_at=_NOW,
        session_id_digest=_SESSION_DIGEST,
        mfa=True,
    )


def _session() -> SessionRecord:
    return SessionRecord(
        session_id_digest=_SESSION_DIGEST,
        actor=_actor(),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=8),
    )


def _consumed_row() -> dict[str, object]:
    prefix = hashlib.sha256(_TRANSACTION_DIGEST.encode()).digest()
    return {
        "transaction_digest": _TRANSACTION_DIGEST,
        "state_digest": _STATE_DIGEST,
        "nonce_digest": _NONCE_DIGEST,
        "verifier_ciphertext": prefix + _VERIFIER.encode(),
        "verifier_key_reference": "test-kms://oidc/pkce/v1",
        "verifier_algorithm": "TEST-SHA256-BOUND",
        "created_at": _NOW,
        "expires_at": _NOW + timedelta(minutes=5),
    }


def test_store_structurally_implements_oidc_state_protocol() -> None:
    def accepts_store(store: OIDCStateStore) -> OIDCStateStore:
        return store

    connection = _Connection(())
    store = _store(
        _Pool(connection),
        protector=_Protector(connection),
    )
    assert accepts_store(store) is store


def test_create_reserves_before_protection_then_atomically_finalizes() -> None:
    connection = _Connection(
        (
            ("reserve_login_admission", _Cursor(({"outcome": "reserved"},))),
            ("finalize_login_admission", _Cursor(({"finalized": True},))),
        )
    )
    protector = _Protector(connection)
    pool = _Pool(connection)
    store = _store(
        pool,
        protector=protector,
        cleanup_batch_size=37,
    )

    store.create_transaction(
        _transaction(),
        source_digest=_SOURCE_DIGEST,
        admission_policy=_ADMISSION,
    )

    assert protector.protect_calls == 1
    assert connection.commits == 2
    reservation_params = next(
        params
        for query, params in connection.executed
        if "reserve_login_admission" in query
    )
    assert reservation_params[0] == _TRANSACTION_DIGEST
    assert reservation_params[1] == _SOURCE_DIGEST
    function_params = next(
        params
        for query, params in connection.executed
        if "finalize_login_admission" in query
    )
    assert _VERIFIER not in function_params
    assert _VERIFIER.encode() not in function_params
    assert function_params[0] == _TRANSACTION_DIGEST
    assert reservation_params[-1] == 37
    assert not connection.script
    store.close()
    assert pool.close_calls == 0


def test_denied_admission_never_calls_protector() -> None:
    connection = _Connection(
        (("reserve_login_admission", _Cursor(({"outcome": "source-limit"},))),)
    )
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)

    with pytest.raises(OIDCError, match="login_admission_limited"):
        store.create_transaction(
            _transaction(),
            source_digest=_SOURCE_DIGEST,
            admission_policy=_ADMISSION,
        )

    assert protector.protect_calls == 0
    assert connection.commits == 1
    assert not connection.script


@pytest.mark.parametrize(
    "versions",
    [
        (2, 5),
        (1, 2, 5, 6),
    ],
)
def test_store_requires_exact_append_only_migration_lineage(
    versions: tuple[int, ...],
) -> None:
    connection = _Connection((), schema_versions=versions)
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)

    with pytest.raises(OIDCError, match="state_store_unavailable"):
        store.create_transaction(
            _transaction(),
            source_digest=_SOURCE_DIGEST,
            admission_policy=_ADMISSION,
        )

    assert protector.protect_calls == 0


def test_protection_failure_cancels_the_reserved_slot() -> None:
    connection = _Connection(
        (
            ("reserve_login_admission", _Cursor(({"outcome": "reserved"},))),
            ("cancel_login_admission", _Cursor(({"cancelled": True},))),
        )
    )
    protector = _Protector(connection, fail_protect=True)
    store = _store(_Pool(connection), protector=protector)

    with pytest.raises(OIDCError, match="state_store_protection_failed"):
        store.create_transaction(
            _transaction(),
            source_digest=_SOURCE_DIGEST,
            admission_policy=_ADMISSION,
        )

    assert protector.protect_calls == 1
    assert connection.commits == 2
    assert not connection.script


def test_expired_reservation_is_cancelled_and_never_becomes_ready() -> None:
    connection = _Connection(
        (
            ("reserve_login_admission", _Cursor(({"outcome": "reserved"},))),
            ("finalize_login_admission", _Cursor(({"finalized": False},))),
            ("cancel_login_admission", _Cursor(({"cancelled": False},))),
        )
    )
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)

    with pytest.raises(OIDCError, match="state_store_unavailable"):
        store.create_transaction(
            _transaction(),
            source_digest=_SOURCE_DIGEST,
            admission_policy=_ADMISSION,
        )

    assert protector.protect_calls == 1
    assert connection.commits == 3
    assert not connection.script


def test_invalid_state_commits_burn_and_never_decrypts() -> None:
    connection = _Connection(
        (
            ("consume_ready_authorization_transaction", _Cursor((_consumed_row(),))),
            ("consume_ready_authorization_transaction", _Cursor()),
        )
    )
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)

    with pytest.raises(OIDCError, match="invalid_transaction"):
        store.consume_transaction(
            transaction_digest=_TRANSACTION_DIGEST,
            state_digest=f"sha256:{'9' * 64}",
            consumed_at=_NOW,
        )
    with pytest.raises(OIDCError, match="invalid_transaction"):
        store.consume_transaction(
            transaction_digest=_TRANSACTION_DIGEST,
            state_digest=_STATE_DIGEST,
            consumed_at=_NOW,
        )

    assert connection.commits == 2
    assert connection.rollbacks == 0
    assert protector.unprotect_calls == 0
    assert not connection.script


def test_valid_consume_decrypts_only_after_burn_commit() -> None:
    connection = _Connection(
        (("consume_ready_authorization_transaction", _Cursor((_consumed_row(),))),)
    )
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)

    transaction = store.consume_transaction(
        transaction_digest=_TRANSACTION_DIGEST,
        state_digest=_STATE_DIGEST,
        consumed_at=_NOW,
    )

    assert transaction == _transaction()
    assert connection.commits == 1
    assert protector.unprotect_calls == 1


def test_session_round_trip_uses_canonical_actor_and_exact_revoke() -> None:
    actor = _actor()
    actor_bytes = actor.model_dump_json().encode()
    # The store requires canonical bytes, so obtain the exact inserted value
    # after create and feed that value back from the scripted database.
    connection = _Connection(
        (
            ("create_browser_session", _Cursor(({"created": True},))),
            (
                "read_browser_session",
                _Cursor(
                    (
                        {
                            "session_id_digest": _SESSION_DIGEST,
                            "tenant_id": actor.tenant_id,
                            "actor_digest": "",
                            "actor_bytes": actor_bytes,
                            "issued_at": _NOW,
                            "expires_at": _NOW + timedelta(hours=8),
                        },
                    )
                ),
            ),
            ("revoke_browser_session", _Cursor(({"revoked": True},))),
            ("revoke_browser_session", _Cursor(({"revoked": False},))),
        )
    )
    protector = _Protector(connection)
    store = _store(_Pool(connection), protector=protector)
    store.create_session(_session())
    inserted = next(
        params
        for query, params in connection.executed
        if "create_browser_session" in query
    )
    canonical_actor = inserted[3]
    assert isinstance(canonical_actor, bytes)
    read_row_cursor = connection.script[0][1]
    read_row = read_row_cursor._rows[0]
    assert isinstance(read_row, dict)
    read_row["actor_bytes"] = canonical_actor
    read_row["actor_digest"] = inserted[2]

    assert store.read_session(
        session_id_digest=_SESSION_DIGEST,
        read_at=_NOW,
    ) == _session()
    assert store.revoke_session(session_id_digest=_SESSION_DIGEST) is True
    assert store.revoke_session(session_id_digest=_SESSION_DIGEST) is False
    assert not connection.script


def test_corrupt_actor_binding_fails_closed() -> None:
    actor = _actor()
    actor_bytes = actor.model_dump_json().encode()
    connection = _Connection(
        (
            (
                "read_browser_session",
                _Cursor(
                    (
                        {
                            "session_id_digest": _SESSION_DIGEST,
                            "tenant_id": "other-bank",
                            "actor_digest": f"sha256:{hashlib.sha256(actor_bytes).hexdigest()}",
                            "actor_bytes": actor_bytes,
                            "issued_at": _NOW,
                            "expires_at": _NOW + timedelta(hours=8),
                        },
                    )
                ),
            ),
        )
    )
    store = _store(
        _Pool(connection),
        protector=_Protector(connection),
    )
    with pytest.raises(OIDCError, match="state_store_integrity_failure"):
        store.read_session(
            session_id_digest=_SESSION_DIGEST,
            read_at=_NOW,
        )


def test_cross_tenant_session_is_rejected_before_pool_lease() -> None:
    connection = _Connection(())
    pool = _Pool(connection)
    store = _store(pool, protector=_Protector(connection))
    other_actor = _actor().model_copy(update={"tenant_id": "other-bank"})

    with pytest.raises(OIDCError, match="invalid_session"):
        store.create_session(
            SessionRecord(
                session_id_digest=_SESSION_DIGEST,
                actor=other_actor,
                issued_at=_NOW,
                expires_at=_NOW + timedelta(hours=8),
            )
        )

    assert pool.leases == 0
    assert connection.executed == []


def test_schema_keeps_auth_outside_tenant_rls_and_exposes_only_routines() -> None:
    schema = (
        Path(__file__).parents[1]
        / "deploy"
        / "postgres"
        / "control-plane-schema.sql"
    ).read_text(encoding="utf-8")

    assert "CREATE SCHEMA IF NOT EXISTS control_assurance_auth" in schema
    assert "REVOKE ALL ON SCHEMA control_assurance_auth FROM PUBLIC" in schema
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA control_assurance_auth FROM PUBLIC" in schema
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_assurance_auth FROM PUBLIC" in schema
    assert "SECURITY DEFINER" in schema
    assert "SET search_path = pg_catalog, control_assurance_auth" in schema
    assert "reserve_login_admission" in schema
    assert "finalize_login_admission" in schema
    assert "cancel_login_admission" in schema
    assert "consume_ready_authorization_transaction" in schema
    assert (
        "DROP FUNCTION IF EXISTS\n"
        "    control_assurance_auth.create_authorization_transaction"
    ) in schema
    assert (
        "DROP FUNCTION IF EXISTS\n"
        "    control_assurance_auth.consume_authorization_transaction"
    ) in schema
    assert "phase = 'ready'" in schema
    assert "oidc_login_admissions" in schema
    assert "authorization_transaction_burns" in schema
    assert "control_revisions FORCE ROW LEVEL SECURITY" in schema
    assert "control_assurance_boundary.bound_tenant" in schema
    assert "control_assurance_auth.runtime_identity()" in schema
    assert "control_assurance_boundary.deployment_tenant" in schema
    assert "VALUES (2, 'dedicated one-time OIDC transaction" in schema
    assert "VALUES (5, 'distributed bounded OIDC login admission" in schema
    assert "installed_versions <> ARRAY[1, 2, 3, 4, 5, 6]" in schema
