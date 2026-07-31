from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from assurance_lab.control_plane import (
    Actor,
    ConfigurationRevision,
    ControlConfiguration,
    ControlPlaneAuthorizationError,
    ControlPlaneConflict,
    ControlPlaneIntegrityError,
    ControlPlaneService,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
    SQLiteControlPlaneStore,
)
from assurance_lab.control_plane.models import Role

_NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
_SESSION_DIGEST = f"sha256:{'1' * 64}"
_PROFILE_DIGEST = f"sha256:{'2' * 64}"


def _actor(
    subject: str,
    *roles: Role,
    tenant_id: str = "acme-bank",
    groups: tuple[str, ...] = (),
    mfa: bool = True,
    authenticated_at: datetime = _NOW,
) -> Actor:
    return Actor(
        tenant_id=tenant_id,
        subject=subject,
        display_name=subject,
        roles=frozenset(roles),
        groups=groups,
        authenticated_at=authenticated_at,
        session_id_digest=_SESSION_DIGEST,
        mfa=mfa,
    )


def _configuration(
    *,
    control_id: str = "elastic-alert-completeness",
    tenant_id: str = "acme-bank",
    display_name: str = "Elastic alert completeness",
) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id=tenant_id,
        control_id=control_id,
        display_name=display_name,
        description="Proves that the declared alert window closes without partial shards.",
        environment="production",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_PROFILE_DIGEST,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example/",
            index_alias=".alerts-security.alerts-default",
            parent_credential_ref="vault://kv/secops/elastic-jit-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://assurance-evidence/acme-bank/elastic",
            signing_key_ref="vault-transit://assurance/signing/elastic-prod",
            retention_days=365,
        ),
    )


def _service(tmp_path: Path) -> tuple[ControlPlaneService, SQLiteControlPlaneStore]:
    store = SQLiteControlPlaneStore(tmp_path / "control-plane.sqlite3")
    return ControlPlaneService(store, now=lambda: _NOW), store


def _approved_revision(
    service: ControlPlaneService,
    *,
    configuration: ControlConfiguration | None = None,
) -> tuple[Actor, Actor, Actor, ConfigurationRevision]:
    editor = _actor(
        "oidc:alice",
        "viewer",
        "editor",
        groups=("secops/platform",),
    )
    approver = _actor("oidc:bob", "viewer", "approver")
    deployer = _actor("oidc:carol", "viewer", "deployer")
    revision = service.create_revision(
        editor,
        configuration or _configuration(),
        expected_parent_revision_id=None,
    )
    revision = service.submit_revision(
        editor,
        revision.revision_id,
        expected_state_version=revision.state_version,
    )
    revision, _ = service.decide_revision(
        approver,
        revision.revision_id,
        expected_state_version=revision.state_version,
        decision="approved",
        comment="Scope is read-only and the recovery plan is attached.",
    )
    return editor, approver, deployer, revision


def test_configuration_is_canonical_secret_free_and_strict() -> None:
    configuration = _configuration()
    assert isinstance(configuration.source, ElasticSourceConfiguration)
    assert configuration.source.endpoint_origin == "https://elastic.acme.example"
    assert configuration.digest.startswith("sha256:")
    assert configuration.canonical_bytes() == configuration.canonical_bytes()
    assert b"password" not in configuration.canonical_bytes().lower()

    with pytest.raises(ValidationError, match="extra_forbidden"):
        ElasticSourceConfiguration.model_validate(
            {
                "endpoint_origin": "https://elastic.acme.example",
                "index_alias": ".alerts-security.alerts-default",
                "parent_credential_ref": "vault://kv/secops/elastic",
                "password": "must-never-enter-config",
            }
        )
    with pytest.raises(ValidationError, match="credential-free HTTPS origin"):
        ElasticSourceConfiguration(
            endpoint_origin="https://elastic:secret@acme.example",
            parent_credential_ref="vault://kv/secops/elastic",
        )
    with pytest.raises(ValidationError, match="approved secret-free reference"):
        ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example",
            parent_credential_ref="https://vault.example/v1/secret?token=raw",
        )
    with pytest.raises(ValidationError, match="exact Security alert alias"):
        ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example",
            index_alias=".alerts-security.alerts-*",
            parent_credential_ref="vault://kv/secops/elastic",
        )


def test_defender_configuration_fixes_permission_table_and_cloud() -> None:
    source = DefenderSourceConfiguration(
        tenant_id="01234567-89ab-4def-8abc-0123456789ab",
        client_id="11234567-89ab-4def-8abc-0123456789ab",
        client_credential_ref="azure-keyvault://security/defender-client",
    )
    assert source.permission == "ThreatHunting.Read.All"
    assert source.table == "AlertInfo"
    with pytest.raises(ValidationError, match="literal_error"):
        DefenderSourceConfiguration(
            tenant_id=source.tenant_id,
            client_id=source.client_id,
            client_credential_ref=source.client_credential_ref,
            permission="SecurityEvents.ReadWrite.All",  # type: ignore[arg-type]
        )


def test_full_maker_checker_activation_and_audit_chain(tmp_path: Path) -> None:
    service, store = _service(tmp_path)
    editor, approver, deployer, approved = _approved_revision(service)

    deployment = service.activate_revision(
        deployer,
        approved.revision_id,
        expected_deployment_version=None,
    )

    assert deployment.revision_id == approved.revision_id
    assert deployment.configuration_digest == _configuration().digest
    assert deployment.deployment_version == 1
    assert service.active_deployment(deployer, approved.control_id) == deployment
    summaries = service.list_controls(deployer)
    assert len(summaries) == 1
    assert summaries[0].latest_revision.revision_id == approved.revision_id
    assert summaries[0].active_deployment == deployment
    events = service.audit_events(
        _actor("oidc:audit", "auditor"),
    )
    assert [event.action for event in events] == [
        "revision-created",
        "revision-submitted",
        "revision-approved",
        "revision-activated",
    ]
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    assert events[0].previous_event_digest == f"sha256:{'0' * 64}"
    assert all(
        events[index].previous_event_digest == events[index - 1].event_digest
        for index in range(1, len(events))
    )
    assert service.verify_audit_chain(_actor("oidc:audit", "auditor")) == (
        4,
        events[-1].event_digest,
    )
    assert store.list_revisions(
        tenant_id=editor.tenant_id,
        control_id=approved.control_id,
    )[0].state == "approved"
    assert approver.subject != approved.created_by


def test_author_cannot_approve_or_activate_own_revision(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    maker = _actor(
        "oidc:maker",
        "viewer",
        "editor",
        "approver",
        "deployer",
        groups=("secops/platform",),
    )
    revision = service.create_revision(
        maker,
        _configuration(),
        expected_parent_revision_id=None,
    )
    revision = service.submit_revision(
        maker,
        revision.revision_id,
        expected_state_version=revision.state_version,
    )
    with pytest.raises(ControlPlaneAuthorizationError, match="own change"):
        service.decide_revision(
            maker,
            revision.revision_id,
            expected_state_version=revision.state_version,
            decision="approved",
            comment="I approve my own change.",
        )


def test_privileged_actions_require_recent_mfa(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    editor = _actor(
        "oidc:alice",
        "editor",
        groups=("secops/platform",),
    )
    revision = service.create_revision(
        editor,
        _configuration(),
        expected_parent_revision_id=None,
    )
    revision = service.submit_revision(
        editor,
        revision.revision_id,
        expected_state_version=revision.state_version,
    )

    without_mfa = _actor("oidc:bob", "approver", mfa=False)
    with pytest.raises(ControlPlaneAuthorizationError, match="fresh MFA"):
        service.decide_revision(
            without_mfa,
            revision.revision_id,
            expected_state_version=revision.state_version,
            decision="approved",
            comment="No MFA.",
        )
    stale = _actor(
        "oidc:bob",
        "approver",
        authenticated_at=_NOW - timedelta(hours=2),
    )
    with pytest.raises(ControlPlaneAuthorizationError, match="fresh MFA"):
        service.decide_revision(
            stale,
            revision.revision_id,
            expected_state_version=revision.state_version,
            decision="approved",
            comment="Stale session.",
        )


def test_tenant_and_owner_group_boundaries_are_enforced(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    outsider = _actor("oidc:outsider", "editor", groups=("another/group",))
    with pytest.raises(ControlPlaneAuthorizationError, match="owner group"):
        service.create_revision(
            outsider,
            _configuration(),
            expected_parent_revision_id=None,
        )
    foreign = _actor(
        "oidc:foreign",
        "editor",
        tenant_id="other-bank",
        groups=("secops/platform",),
    )
    with pytest.raises(ControlPlaneAuthorizationError, match="cross-tenant"):
        service.create_revision(
            foreign,
            _configuration(),
            expected_parent_revision_id=None,
        )
    assert (
        service.list_controls(
            _actor("oidc:foreign-viewer", "viewer", tenant_id="other-bank")
        )
        == ()
    )


def test_state_and_lineage_compare_and_swap_prevent_lost_updates(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path)
    editor = _actor(
        "oidc:alice",
        "editor",
        groups=("secops/platform",),
    )
    first = service.create_revision(
        editor,
        _configuration(),
        expected_parent_revision_id=None,
    )
    submitted = service.submit_revision(
        editor,
        first.revision_id,
        expected_state_version=0,
    )
    with pytest.raises(ControlPlaneConflict, match="concurrently"):
        service.submit_revision(
            editor,
            first.revision_id,
            expected_state_version=0,
        )
    approver = _actor("oidc:bob", "approver")
    rejected, _ = service.decide_revision(
        approver,
        submitted.revision_id,
        expected_state_version=submitted.state_version,
        decision="rejected",
        comment="Endpoint ownership evidence is missing.",
    )
    second_config = _configuration(display_name="Elastic completeness v2")
    with pytest.raises(ControlPlaneConflict, match="latest generation"):
        service.create_revision(
            editor,
            second_config,
            expected_parent_revision_id=f"sha256:{'f' * 64}",
        )
    second = service.create_revision(
        editor,
        second_config,
        expected_parent_revision_id=rejected.revision_id,
    )
    assert second.generation == 2
    assert second.parent_revision_id == rejected.revision_id
    assert second.revision_id != first.revision_id


def test_database_triggers_block_history_rewrite_and_verifier_detects_tamper(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    editor = _actor(
        "oidc:alice",
        "editor",
        groups=("secops/platform",),
    )
    revision = service.create_revision(
        editor,
        _configuration(),
        expected_parent_revision_id=None,
    )
    database = tmp_path / "control-plane.sqlite3"
    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM control_revisions WHERE revision_id = ?",
                (revision.revision_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """
                UPDATE control_revisions
                SET configuration_bytes = ?
                WHERE revision_id = ?
                """,
                (b"{}", revision.revision_id),
            )
        connection.rollback()

        connection.execute("DROP TRIGGER audit_no_update")
        connection.execute(
            """
            UPDATE control_audit_events
            SET previous_event_digest = ?
            WHERE tenant_id = ? AND sequence = 1
            """,
            (f"sha256:{'9' * 64}", editor.tenant_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ControlPlaneIntegrityError, match="stored audit event"):
        store.verify_audit_chain(tenant_id=editor.tenant_id)


def test_database_file_must_be_owner_only(tmp_path: Path) -> None:
    database = tmp_path / "control-plane.sqlite3"
    database.write_bytes(b"")
    database.chmod(0o644)
    with pytest.raises(RuntimeError, match="owner-only"):
        SQLiteControlPlaneStore(database)
