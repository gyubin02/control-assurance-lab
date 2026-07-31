"""Opt-in PostgreSQL OIDC replay, concurrency, and reconnect test."""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from assurance_lab.control_plane.models import Actor
from assurance_lab.control_plane.oidc import (
    AuthorizationTransaction,
    OIDCError,
    OIDCLoginAdmissionPolicy,
    SessionRecord,
)
from assurance_lab.control_plane.postgres_oidc_store import (
    PostgresOIDCStateStore,
    ProtectedCodeVerifier,
)

_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_DSN")
_MIGRATION_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_TENANT")
_DATABASE_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE")
_CONTROL_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE")
_RECONCILER_ROLE = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE"
)
pytestmark = pytest.mark.skipif(
    not all(
        (
            _DSN,
            _MIGRATION_DSN,
            _TENANT_ID,
            _DATABASE_ROLE,
            _CONTROL_ROLE,
            _RECONCILER_ROLE,
        )
    ),
    reason="separated authentication PostgreSQL DSNs are not configured",
)
_SOURCE_DIGEST = f"hmac-sha256:{'1' * 64}"
_ADMISSION = OIDCLoginAdmissionPolicy(
    global_active_limit=8,
    source_active_limit=2,
    burn_capacity=64,
)


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _opaque(seed: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest()).rstrip(
        b"="
    ).decode()


class _AESProtector:
    """Test-only local equivalent of a transaction-bound KMS envelope."""

    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(key)
        self.protect_calls = 0

    def protect(
        self,
        *,
        code_verifier: str,
        transaction_digest: str,
    ) -> ProtectedCodeVerifier:
        self.protect_calls += 1
        nonce = os.urandom(12)
        ciphertext = nonce + self._aead.encrypt(
            nonce,
            code_verifier.encode(),
            transaction_digest.encode(),
        )
        return ProtectedCodeVerifier(
            ciphertext=ciphertext,
            key_reference="test-local-envelope-key/v1",
            algorithm="AES-256-GCM",
        )

    def unprotect(
        self,
        *,
        protected: ProtectedCodeVerifier,
        transaction_digest: str,
    ) -> str:
        nonce = protected.ciphertext[:12]
        return self._aead.decrypt(
            nonce,
            protected.ciphertext[12:],
            transaction_digest.encode(),
        ).decode()


def _install_schema(dsn: str) -> None:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - opt-in environment only
        pytest.skip(f"psycopg is not installed: {exc}")
    schema = (
        Path(__file__).parents[2]
        / "deploy"
        / "postgres"
        / "control-plane-schema.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            """
            DROP SCHEMA IF EXISTS
                control_assurance_boundary,
                control_assurance_auth,
                control_assurance
            CASCADE
            """
        )
        connection.execute(schema)
        connection.execute(
            """
            SELECT control_assurance_boundary.configure_runtime_roles(
                %s,
                %s::name,
                %s::name,
                %s::name
            )
            """,
            (
                _TENANT_ID,
                _CONTROL_ROLE,
                _DATABASE_ROLE,
                _RECONCILER_ROLE,
            ),
        )


def _transaction(
    seed: str,
    *,
    now: datetime,
) -> tuple[AuthorizationTransaction, str]:
    transaction_handle = _opaque(f"transaction:{seed}")
    state_handle = _opaque(f"state:{seed}")
    nonce_handle = _opaque(f"nonce:{seed}")
    verifier = _opaque(f"verifier:{seed}")
    return (
        AuthorizationTransaction(
            transaction_digest=_digest(transaction_handle),
            state_digest=_digest(state_handle),
            nonce_digest=_digest(nonce_handle),
            code_verifier=verifier,
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        ),
        state_handle,
    )


def test_live_one_time_burn_session_revoke_and_pool_reconnect() -> None:
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    assert _TENANT_ID is not None
    assert _DATABASE_ROLE is not None
    _install_schema(_MIGRATION_DSN)
    now = datetime.now(UTC).replace(microsecond=0)
    unique = uuid.uuid4().hex
    key = hashlib.sha256(f"key:{unique}".encode()).digest()
    protector = _AESProtector(key)
    store = PostgresOIDCStateStore.from_dsn(
        _DSN,
        tenant_id=_TENANT_ID,
        expected_role=_DATABASE_ROLE,
        protector=protector,
        burn_capacity=_ADMISSION.burn_capacity,
        min_size=2,
        max_size=4,
    )

    winner_transaction, winner_state = _transaction(f"winner:{unique}", now=now)
    store.create_transaction(
        winner_transaction,
        source_digest=_SOURCE_DIGEST,
        admission_policy=_ADMISSION,
    )

    def consume_once() -> str:
        try:
            value = store.consume_transaction(
                transaction_digest=winner_transaction.transaction_digest,
                state_digest=_digest(winner_state),
                consumed_at=now,
            )
        except OIDCError as exc:
            assert exc.code == "invalid_transaction"
            return "replay-denied"
        assert value.code_verifier == winner_transaction.code_verifier
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: consume_once(), range(2)))
    assert sorted(outcomes) == ["consumed", "replay-denied"]

    burned, _ = _transaction(f"burned:{unique}", now=now)
    store.create_transaction(
        burned,
        source_digest=_SOURCE_DIGEST,
        admission_policy=_ADMISSION,
    )
    with pytest.raises(OIDCError, match="invalid_transaction"):
        store.consume_transaction(
            transaction_digest=burned.transaction_digest,
            state_digest=f"sha256:{'9' * 64}",
            consumed_at=now,
        )
    with pytest.raises(OIDCError, match="invalid_transaction"):
        store.consume_transaction(
            transaction_digest=burned.transaction_digest,
            state_digest=burned.state_digest,
            consumed_at=now,
        )

    session_handle = _opaque(f"session:{unique}")
    session_digest = _digest(session_handle)
    actor = Actor(
        tenant_id=_TENANT_ID,
        subject="oidc:live-alice",
        display_name="Live Alice",
        roles=frozenset({"viewer", "editor"}),
        groups=("secops/platform",),
        authenticated_at=now,
        session_id_digest=session_digest,
        mfa=True,
    )
    session = SessionRecord(
        session_id_digest=session_digest,
        actor=actor,
        issued_at=now,
        expires_at=now + timedelta(hours=8),
    )
    store.create_session(session)
    assert store.read_session(session_id_digest=session_digest, read_at=now) == session
    store.close()

    reopened = PostgresOIDCStateStore.from_dsn(
        _DSN,
        tenant_id=_TENANT_ID,
        expected_role=_DATABASE_ROLE,
        protector=_AESProtector(key),
        burn_capacity=_ADMISSION.burn_capacity,
        min_size=2,
        max_size=4,
    )
    try:
        assert reopened.read_session(
            session_id_digest=session_digest,
            read_at=now,
        ) == session

        def revoke_once() -> bool:
            return reopened.revoke_session(session_id_digest=session_digest)

        with ThreadPoolExecutor(max_workers=2) as executor:
            revoked = tuple(executor.map(lambda _: revoke_once(), range(2)))
        assert sorted(revoked) == [False, True]
        with pytest.raises(OIDCError, match="invalid_session"):
            reopened.read_session(
                session_id_digest=session_digest,
                read_at=now,
            )
    finally:
        reopened.close()


def test_live_two_replica_admission_races_before_protection() -> None:
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    assert _TENANT_ID is not None
    assert _DATABASE_ROLE is not None
    _install_schema(_MIGRATION_DSN)
    now = datetime.now(UTC).replace(microsecond=0)
    unique = uuid.uuid4().hex
    key = hashlib.sha256(f"race-key:{unique}".encode()).digest()
    policy = OIDCLoginAdmissionPolicy(
        global_active_limit=1,
        source_active_limit=1,
        burn_capacity=64,
    )
    protectors = (_AESProtector(key), _AESProtector(key))
    stores = tuple(
        PostgresOIDCStateStore.from_dsn(
            _DSN,
            tenant_id=_TENANT_ID,
            expected_role=_DATABASE_ROLE,
            protector=protector,
            min_size=1,
            max_size=2,
            burn_capacity=policy.burn_capacity,
        )
        for protector in protectors
    )
    transactions = tuple(
        _transaction(f"replica-{index}:{unique}", now=now)[0]
        for index in range(2)
    )
    sources = (
        f"hmac-sha256:{'2' * 64}",
        f"hmac-sha256:{'3' * 64}",
    )

    def create(index: int) -> tuple[str, int]:
        try:
            stores[index].create_transaction(
                transactions[index],
                source_digest=sources[index],
                admission_policy=policy,
            )
        except OIDCError as exc:
            return exc.code, index
        return "accepted", index

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(create, range(2)))
        assert sorted(outcome for outcome, _ in outcomes) == [
            "accepted",
            "login_admission_limited",
        ]
        assert sum(item.protect_calls for item in protectors) == 1
        winner = next(index for outcome, index in outcomes if outcome == "accepted")
        stores[winner].consume_transaction(
            transaction_digest=transactions[winner].transaction_digest,
            state_digest=transactions[winner].state_digest,
            consumed_at=now,
        )
    finally:
        for store in stores:
            store.close()


def test_live_reservation_is_not_consumable_and_cancel_or_expiry_removes_it() -> None:
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    _install_schema(_MIGRATION_DSN)
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - opt-in environment only
        pytest.skip(f"psycopg is not installed: {exc}")
    now = datetime.now(UTC).replace(microsecond=0)
    unique = uuid.uuid4().hex
    reserved_digest = _digest(f"reserved:{unique}")
    expired_digest = _digest(f"expired:{unique}")
    source_digest = f"hmac-sha256:{'4' * 64}"

    with psycopg.connect(_DSN, autocommit=True) as connection:
        reserved = connection.execute(
            """
            SELECT control_assurance_auth.reserve_login_admission(
                %s, %s, %s, 30, 8, 2, 64, 32
            )
            """,
            (reserved_digest, source_digest, now + timedelta(minutes=5)),
        ).fetchone()
        assert reserved == ("reserved",)
        unfinalized = connection.execute(
            """
            SELECT *
            FROM control_assurance_auth.consume_ready_authorization_transaction(
                %s, %s, 3600, 32, 64
            )
            """,
            (reserved_digest, now),
        ).fetchall()
        assert unfinalized == []
        cancelled = connection.execute(
            "SELECT control_assurance_auth.cancel_login_admission(%s)",
            (reserved_digest,),
        ).fetchone()
        assert cancelled == (True,)

    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        connection.execute(
            """
            INSERT INTO control_assurance_auth.oidc_login_admissions (
                transaction_digest,
                source_digest,
                phase,
                admitted_at,
                reservation_expires_at,
                transaction_expires_at
            ) VALUES (%s, %s, 'reserved', %s, %s, %s)
            """,
            (
                expired_digest,
                source_digest,
                now - timedelta(seconds=10),
                now - timedelta(seconds=5),
                now + timedelta(minutes=5),
            ),
        )

    with psycopg.connect(_DSN, autocommit=True) as connection:
        finalized = connection.execute(
            """
            SELECT control_assurance_auth.finalize_login_admission(
                %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                expired_digest,
                _digest(f"state:{unique}"),
                _digest(f"nonce:{unique}"),
                b"x" * 32,
                "test-key/v1",
                "TEST",
                now - timedelta(seconds=10),
                now + timedelta(minutes=5),
            ),
        ).fetchone()
        assert finalized == (False,)

    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        remaining = connection.execute(
            """
            SELECT count(*)
            FROM control_assurance_auth.oidc_login_admissions
            WHERE transaction_digest IN (%s, %s)
            """,
            (reserved_digest, expired_digest),
        ).fetchone()
        assert remaining == (0,)


def test_live_minimum_runtime_role_can_only_execute_admission_routines() -> None:
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    _install_schema(_MIGRATION_DSN)
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - opt-in environment only
        pytest.skip(f"psycopg is not installed: {exc}")

    with psycopg.connect(_DSN, autocommit=True) as connection:
        identity = connection.execute(
            """
            SELECT
                role_kind,
                tenant_id,
                schema_versions
            FROM control_assurance_auth.runtime_identity()
            """
        ).fetchone()
        assert identity == ("auth", _TENANT_ID, [2, 5, 6])
        privileges = connection.execute(
            """
            SELECT
                has_schema_privilege(
                    current_user,
                    'control_assurance',
                    'USAGE'
                ),
                has_table_privilege(
                    current_user,
                    'control_assurance_auth.oidc_login_admissions',
                    'SELECT'
                ),
                has_table_privilege(
                    current_user,
                    'control_assurance_auth.authorization_transactions',
                    'INSERT'
                ),
                has_function_privilege(
                    current_user,
                    'control_assurance_auth.reserve_login_admission('
                    'text,text,timestamptz,integer,integer,integer,'
                    'integer,integer)',
                    'EXECUTE'
                ),
                has_function_privilege(
                    current_user,
                    'control_assurance_auth.reserve_login_admission_v5('
                    'text,text,timestamptz,integer,integer,integer,'
                    'integer,integer)',
                    'EXECUTE'
                )
            """
        ).fetchone()
        assert privileges == (False, False, False, True, False)
