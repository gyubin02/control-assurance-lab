"""Installed package version."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("control-assurance-lab")
except PackageNotFoundError:  # pragma: no cover - source tree without an installation
    __version__ = "0+unknown"

__all__ = ["__version__"]
