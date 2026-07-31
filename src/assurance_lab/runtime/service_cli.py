"""Non-interactive entry point for the production runtime worker."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.bootstrap import (
    ProductionRuntimeWorkerFactory,
    RuntimeBootstrapError,
    inspect_custody_deployment_profiles,
    plan_pam_journal_namespaces,
)
from assurance_lab.runtime.deployment_io import initialize_shared_work_root
from assurance_lab.runtime.models import sha256_digest
from assurance_lab.runtime.profile_registrar import (
    RuntimeProfileRegistrationManifest,
    load_profile_registration_manifest,
    register_control_profiles,
)
from assurance_lab.runtime.service import (
    JSONLineRuntimeWorkerEventSink,
    RuntimeWorkerService,
)
from assurance_lab.runtime.service_config import (
    RuntimeServiceConfigurationError,
    RuntimeWorkerServiceConfig,
    load_runtime_worker_service_config,
)

_DIGEST_ENVIRONMENT = "ASSURANCE_RUNTIME_CONFIG_DIGEST"
_PROFILE_MANIFEST_DIGEST_ENVIRONMENT = (
    "ASSURANCE_PROFILE_REGISTRATION_MANIFEST_DIGEST"
)
_DIGEST_LIMITS = JSONLimits(
    max_bytes=4 * 1024 * 1024,
    max_line_bytes=4 * 1024 * 1024,
    max_depth=32,
    max_collection_items=16_384,
    max_string_length=1024 * 1024,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance-runtime-worker")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in (
        "run",
        "init-work-root",
        "config-digest",
        "custody-profile-digests",
        "pam-namespace-plan",
    ):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
    for name in ("register-profiles", "profile-manifest-digest"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", required=True)
    return parser


def _config_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeServiceConfigurationError(
            "runtime worker config path must be absolute"
        )
    return path


def _expected_digest(environment: Mapping[str, str]) -> str:
    value = environment.get(_DIGEST_ENVIRONMENT)
    if type(value) is not str:
        raise RuntimeServiceConfigurationError(
            "runtime worker config digest environment reference is absent"
        )
    return value


def _calculate_digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            value = stream.read(_DIGEST_LIMITS.max_bytes + 1)
        if len(value) > _DIGEST_LIMITS.max_bytes:
            raise ValueError
        document = strict_json_loads(value, limits=_DIGEST_LIMITS)
        if not isinstance(document, dict):
            raise ValueError
        configuration = RuntimeWorkerServiceConfig.model_validate_json(value)
    except (OSError, StrictJSONError, TypeError, ValueError):
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration is invalid"
        ) from None
    return sha256_digest(
        canonical_json_bytes(configuration.model_dump(mode="json"))
    )


def _calculate_profile_manifest_digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            value = stream.read(_DIGEST_LIMITS.max_bytes + 1)
        if len(value) > _DIGEST_LIMITS.max_bytes:
            raise ValueError
        document = strict_json_loads(value, limits=_DIGEST_LIMITS)
        if not isinstance(document, dict):
            raise ValueError
        manifest = RuntimeProfileRegistrationManifest.model_validate_json(value)
    except (OSError, StrictJSONError, TypeError, ValueError):
        raise RuntimeServiceConfigurationError(
            "profile registration manifest is invalid"
        ) from None
    return manifest.digest


def _load(
    path: Path,
    environment: Mapping[str, str],
) -> RuntimeWorkerServiceConfig:
    return load_runtime_worker_service_config(
        path,
        expected_digest=_expected_digest(environment),
    )


def _run(
    configuration: RuntimeWorkerServiceConfig,
    environment: Mapping[str, str],
) -> None:
    sink = JSONLineRuntimeWorkerEventSink(sys.stdout.buffer)
    factory = ProductionRuntimeWorkerFactory(
        configuration,
        environment=environment,
    )
    service = RuntimeWorkerService(
        configuration,
        factory,
        event_sink=sink,
    )
    previous: dict[signal.Signals, Any] = {}

    def stop(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        service.request_stop()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, stop)
    try:
        service.run()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    selected_environment = os.environ if environment is None else environment
    try:
        selected_path = (
            arguments.manifest
            if arguments.command
            in {"register-profiles", "profile-manifest-digest"}
            else arguments.config
        )
        path = _config_path(selected_path)
        if arguments.command == "config-digest":
            print(_calculate_digest(path))
            return 0
        if arguments.command == "profile-manifest-digest":
            print(_calculate_profile_manifest_digest(path))
            return 0
        if arguments.command == "register-profiles":
            manifest_digest = selected_environment.get(
                _PROFILE_MANIFEST_DIGEST_ENVIRONMENT
            )
            if type(manifest_digest) is not str:
                raise RuntimeServiceConfigurationError(
                    "profile registration manifest digest is absent"
                )
            manifest = load_profile_registration_manifest(
                path,
                expected_digest=manifest_digest,
            )
            registered = register_control_profiles(
                manifest,
                environment=selected_environment,
            )
            for registered_profile in registered:
                sys.stdout.buffer.write(
                    canonical_json_bytes(
                        {
                            "code": "profile-registered",
                            "profile_digest": (
                                registered_profile.profile_digest
                            ),
                            "profile_id": registered_profile.profile_id,
                            "tenant_id": registered_profile.tenant_id,
                        }
                    )
                    + b"\n"
                )
            sys.stdout.buffer.flush()
            return 0
        configuration = _load(path, selected_environment)
        if arguments.command == "pam-namespace-plan":
            for namespace in plan_pam_journal_namespaces(configuration):
                sys.stdout.buffer.write(
                    canonical_json_bytes(
                        {
                            "code": "pam-journal-namespace",
                            "journal_namespace_digest": (
                                namespace.journal_namespace_digest
                            ),
                            "purpose": namespace.purpose,
                            "source_configuration_digest": (
                                namespace.source_configuration_digest
                            ),
                            "source_kind": namespace.source_kind,
                            "tenant_id": namespace.tenant_id,
                        }
                    )
                    + b"\n"
                )
            sys.stdout.buffer.flush()
            return 0
        if arguments.command == "custody-profile-digests":
            profiles = inspect_custody_deployment_profiles(
                configuration,
                environment=selected_environment,
            )
            drifted = False
            for registration, custody_profile in zip(
                configuration.registrations,
                profiles,
                strict=True,
            ):
                expected = (
                    registration.custody_runtime.expected_profile_digest
                )
                matches = custody_profile.digest == expected
                drifted = drifted or not matches
                sys.stdout.buffer.write(
                    canonical_json_bytes(
                        {
                            "code": "custody-profile-observed",
                            "expected_profile_digest": expected,
                            "matches_expected": matches,
                            "profile": custody_profile.model_dump(
                                mode="json"
                            ),
                            "profile_digest": custody_profile.digest,
                        }
                    )
                    + b"\n"
                )
            sys.stdout.buffer.flush()
            if drifted:
                raise RuntimeBootstrapError("custody-profile-drift")
            return 0
        if arguments.command == "init-work-root":
            initialize_shared_work_root(configuration.work_root)
            return 0
        _run(configuration, selected_environment)
        return 0
    except RuntimeServiceConfigurationError:
        print("runtime-worker-config-invalid", file=sys.stderr)
        return 2
    except RuntimeBootstrapError as exc:
        print(f"runtime-worker-{exc.stage}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("runtime-worker-unexpected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
