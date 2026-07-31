"""Non-interactive entry point for the production control-plane API."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from assurance_lab.control_plane.bootstrap import (
    ControlPlaneBootstrapError,
    ProductionControlPlaneFactory,
)
from assurance_lab.control_plane.service_config import (
    ControlPlaneConfigurationError,
    ControlPlaneServiceConfig,
    load_control_plane_service_config,
)
from assurance_lab.evidence.canonical import JSONLimits, StrictJSONError, strict_json_loads

_DIGEST_ENVIRONMENT = "ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST"
_CONFIG_LIMITS = JSONLimits(
    max_bytes=2 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_collection_items=4_096,
    max_string_length=64 * 1024,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance-control-plane")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "config-digest"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
    return parser


def _config_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ControlPlaneConfigurationError(
            "control-plane config path must be absolute"
        )
    return path


def _expected_digest(environment: Mapping[str, str]) -> str:
    value = environment.get(_DIGEST_ENVIRONMENT)
    if type(value) is not str:
        raise ControlPlaneConfigurationError(
            "control-plane config digest environment reference is absent"
        )
    return value


def _configuration_digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_CONFIG_LIMITS.max_bytes + 1)
        if len(payload) > _CONFIG_LIMITS.max_bytes:
            raise ValueError
        document = strict_json_loads(payload, limits=_CONFIG_LIMITS)
        if not isinstance(document, dict):
            raise ValueError
        configuration = ControlPlaneServiceConfig.model_validate(document)
    except (OSError, StrictJSONError, TypeError, ValueError):
        raise ControlPlaneConfigurationError(
            "control-plane configuration is invalid"
        ) from None
    return configuration.digest


def _serve(configuration: ControlPlaneServiceConfig, environment: Mapping[str, str]) -> None:
    try:
        import uvicorn
    except ImportError:
        raise ControlPlaneBootstrapError("uvicorn-unavailable") from None
    components = ProductionControlPlaneFactory(
        configuration,
        environment=environment,
    ).build()
    server = uvicorn.Server(
        uvicorn.Config(
            components.application,
            host=configuration.http.bind_host,
            port=configuration.http.port,
            workers=1,
            access_log=False,
            date_header=False,
            server_header=False,
            proxy_headers=False,
            forwarded_allow_ips="",
            timeout_keep_alive=5,
            timeout_graceful_shutdown=30,
            limit_concurrency=(
                configuration.http.offload_workers
                + configuration.http.offload_queue_capacity
                + 32
            ),
            h11_max_incomplete_event_size=64 * 1024,
            log_level="warning",
        )
    )
    try:
        server.run()
    finally:
        # Uvicorn normally closes through the application lifespan.  This is
        # idempotent and covers startup interruption before lifespan entry.
        components.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    selected_environment = os.environ if environment is None else environment
    try:
        path = _config_path(arguments.config)
        if arguments.command == "config-digest":
            print(_configuration_digest(path))
            return 0
        configuration = load_control_plane_service_config(
            path,
            expected_digest=_expected_digest(selected_environment),
        )
        _serve(configuration, selected_environment)
        return 0
    except ControlPlaneConfigurationError:
        print("control-plane-config-invalid", file=sys.stderr)
        return 2
    except ControlPlaneBootstrapError as exc:
        print(f"control-plane-startup-failed:{exc.stage}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("control-plane-failed", file=sys.stderr)
        return 1


__all__ = ["main"]
