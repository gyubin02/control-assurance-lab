"""Process lifecycle and health contract for the tenant runtime worker."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import IO, Any, Literal, Protocol

from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.bootstrap import (
    RuntimeBootstrapError,
    RuntimeWorkerComponents,
)
from assurance_lab.runtime.service_config import RuntimeWorkerServiceConfig
from assurance_lab.runtime.worker import (
    RuntimeWorkerEvent,
    RuntimeWorkerEventSink,
    RuntimeWorkerStatus,
)

ServicePhase = Literal[
    "created",
    "starting",
    "running",
    "draining",
    "stopped",
    "failed",
]


class RuntimeWorkerComponentFactory(Protocol):
    def build(
        self,
        *,
        event_sink: RuntimeWorkerEventSink | None = None,
    ) -> RuntimeWorkerComponents: ...


@dataclass(frozen=True, slots=True)
class RuntimeServiceStatus:
    phase: ServicePhase
    stop_requested: bool
    worker: RuntimeWorkerStatus | None

    @property
    def live(self) -> bool:
        return self.phase in {"starting", "running", "draining"}

    @property
    def ready(self) -> bool:
        return (
            self.phase == "running"
            and self.worker is not None
            and self.worker.state == "running"
            and not self.worker.stop_requested
        )


class JSONLineRuntimeWorkerEventSink:
    """Write only the worker's bounded event vocabulary as canonical JSONL."""

    __slots__ = ("_lock", "_stream")

    def __init__(self, stream: IO[bytes]) -> None:
        if not callable(getattr(stream, "write", None)):
            raise TypeError("runtime event stream must be writable")
        self._stream = stream
        self._lock = threading.Lock()

    @staticmethod
    def _time(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def __call__(self, event: RuntimeWorkerEvent) -> None:
        if type(event) is not RuntimeWorkerEvent:
            raise TypeError("runtime event must be exact")
        value = canonical_json_bytes(
            {
                "code": event.code,
                "observed_at": self._time(event.observed_at),
                "sequence": event.sequence,
                "tenant_id": event.tenant_id,
                "value": event.value,
            }
        ) + b"\n"
        with self._lock:
            self._stream.write(value)
            flush = getattr(self._stream, "flush", None)
            if callable(flush):
                flush()


class _HealthServer(ThreadingMixIn, HTTPServer):
    """Bound slow clients without letting them serialize every health probe."""

    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True
    request_queue_size = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
    ) -> None:
        self._connection_timeout_seconds = 2.0
        self._connection_slots = threading.BoundedSemaphore(32)
        super().__init__(server_address, handler)

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(self._connection_timeout_seconds)
        return request, client_address

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class RuntimeHealthServer:
    """Two-endpoint HTTP server with no configuration or exception exposure."""

    __slots__ = ("_server", "_thread")

    def __init__(
        self,
        *,
        host: str,
        port: int,
        status: Callable[[], RuntimeServiceStatus],
    ) -> None:
        if not callable(status):
            raise TypeError("health status source must be callable")

        class Handler(BaseHTTPRequestHandler):
            server_version = "control-assurance"
            sys_version = ""
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                if self.path == "/livez":
                    healthy = status().live
                elif self.path == "/readyz":
                    healthy = status().ready
                else:
                    self._respond(404, b'{"status":"not-found"}')
                    return
                if healthy:
                    self._respond(200, b'{"status":"ok"}')
                else:
                    self._respond(503, b'{"status":"not-ready"}')

            def do_HEAD(self) -> None:
                self._respond(405, b"")

            def do_POST(self) -> None:
                self._respond(405, b'{"status":"method-not-allowed"}')

            def _respond(self, code: int, body: bytes) -> None:
                try:
                    self.send_response(code)
                    self.send_header(
                        "Content-Type",
                        "application/json; charset=utf-8",
                    )
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if self.command != "HEAD" and body:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, TimeoutError):
                    pass
                finally:
                    self.close_connection = True

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        try:
            self._server = _HealthServer((host, port), Handler)
        except OSError:
            raise RuntimeBootstrapError("health-bind") from None
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="runtime-health",
            daemon=False,
        )

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=10.0)
        self._server.server_close()
        if self._thread.is_alive():
            raise RuntimeBootstrapError("health-shutdown")


class RuntimeWorkerService:
    """Own bootstrap, readiness, graceful drain, and resource closure."""

    __slots__ = (
        "_components",
        "_configuration",
        "_event_sink",
        "_factory",
        "_health",
        "_lock",
        "_phase",
        "_run_started",
        "_stop_requested",
    )

    def __init__(
        self,
        configuration: RuntimeWorkerServiceConfig,
        factory: RuntimeWorkerComponentFactory,
        *,
        event_sink: RuntimeWorkerEventSink | None = None,
    ) -> None:
        if type(configuration) is not RuntimeWorkerServiceConfig:
            raise TypeError("runtime service configuration must be exact")
        if not callable(getattr(factory, "build", None)):
            raise TypeError("runtime component factory must implement build()")
        if event_sink is not None and not callable(event_sink):
            raise TypeError("runtime event sink must be callable")
        self._configuration = configuration
        self._factory = factory
        self._event_sink = event_sink
        self._lock = threading.Lock()
        self._phase: ServicePhase = "created"
        self._stop_requested = False
        self._run_started = False
        self._components: RuntimeWorkerComponents | None = None
        self._health: RuntimeHealthServer | None = None

    def status(self) -> RuntimeServiceStatus:
        with self._lock:
            components = self._components
            return RuntimeServiceStatus(
                phase=self._phase,
                stop_requested=self._stop_requested,
                worker=(
                    None
                    if components is None
                    else components.worker.status()
                ),
            )

    def request_stop(self) -> None:
        """Thread-safe SIGTERM target: stop claiming after the active call."""

        with self._lock:
            self._stop_requested = True
            if self._phase in {"starting", "running"}:
                self._phase = "draining"
            components = self._components
        if components is not None:
            components.worker.request_stop()

    def _start_health(self) -> RuntimeHealthServer:
        health = RuntimeHealthServer(
            host=self._configuration.health.bind_host,
            port=self._configuration.health.port,
            status=self.status,
        )
        health.start()
        with self._lock:
            self._health = health
        return health

    def run(self) -> None:
        with self._lock:
            if self._run_started:
                raise RuntimeError("runtime service is single-use")
            self._run_started = True
            self._phase = "draining" if self._stop_requested else "starting"
        health: RuntimeHealthServer | None = None
        components: RuntimeWorkerComponents | None = None
        failure: BaseException | None = None
        try:
            health = self._start_health()
            with self._lock:
                if self._stop_requested:
                    self._phase = "stopped"
                    return
            components = self._factory.build(event_sink=self._event_sink)
            with self._lock:
                self._components = components
                stop_requested = self._stop_requested
                self._phase = "draining" if stop_requested else "running"
            if stop_requested:
                components.worker.request_stop()
            components.worker.run_forever()
            with self._lock:
                self._phase = "stopped"
        except BaseException as exc:
            failure = exc
            with self._lock:
                self._phase = "failed"
            raise
        finally:
            close_failure: BaseException | None = None
            if components is not None:
                try:
                    components.close()
                except BaseException as exc:
                    close_failure = exc
            if health is not None:
                try:
                    health.close()
                except BaseException as exc:
                    if close_failure is None:
                        close_failure = exc
            if close_failure is not None and failure is None:
                with self._lock:
                    self._phase = "failed"
                raise close_failure


__all__ = [
    "JSONLineRuntimeWorkerEventSink",
    "RuntimeHealthServer",
    "RuntimeServiceStatus",
    "RuntimeWorkerComponentFactory",
    "RuntimeWorkerService",
]
