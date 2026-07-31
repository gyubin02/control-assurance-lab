"""Non-interactive entry point for the deployment outbox reconciler."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from assurance_lab.control_plane.reconciler_service import (
    run_deployment_reconciler,
)
from assurance_lab.runtime.bootstrap import RuntimeBootstrapError
from assurance_lab.runtime.service_config import (
    RuntimeServiceConfigurationError,
    load_runtime_worker_service_config,
)

_RUNTIME_CONFIG_DIGEST_ENVIRONMENT = "ASSURANCE_RUNTIME_CONFIG_DIGEST"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance-deployment-reconciler")
    parser.add_argument("command", choices=("run",))
    parser.add_argument("--runtime-config", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    selected_environment = os.environ if environment is None else environment
    try:
        path = Path(arguments.runtime_config)
        if not path.is_absolute():
            raise RuntimeServiceConfigurationError(
                "runtime worker configuration path must be absolute"
            )
        expected_digest = selected_environment.get(
            _RUNTIME_CONFIG_DIGEST_ENVIRONMENT
        )
        if type(expected_digest) is not str:
            raise RuntimeServiceConfigurationError(
                "runtime worker configuration digest is absent"
            )
        configuration = load_runtime_worker_service_config(
            path,
            expected_digest=expected_digest,
        )
        run_deployment_reconciler(
            configuration,
            environment=selected_environment,
        )
        return 0
    except RuntimeServiceConfigurationError:
        print("deployment-reconciler-config-invalid", file=sys.stderr)
        return 2
    except RuntimeBootstrapError as exc:
        print(f"deployment-reconciler-startup-failed:{exc.stage}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("deployment-reconciler-failed", file=sys.stderr)
        return 1


__all__ = ["main"]
