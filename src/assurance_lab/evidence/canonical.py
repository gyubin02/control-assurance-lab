"""Strict JSON parsing and RFC 8785 canonical serialization."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import islice
from typing import IO, Any, NoReturn, cast

import rfc8785

I_JSON_MAX_INTEGER = (2**53) - 1


class StrictJSONError(ValueError):
    """Raised when JSON is valid enough to parse but unsafe for canonical evidence."""


@dataclass(frozen=True, slots=True)
class JSONLimits:
    max_bytes: int = 16 * 1024 * 1024
    max_line_bytes: int = 2 * 1024 * 1024
    max_depth: int = 64
    max_collection_items: int = 100_000
    max_string_length: int = 2 * 1024 * 1024


DEFAULT_JSON_LIMITS = JSONLimits()


class _BoundedSink:
    def __init__(self, maximum: int) -> None:
        self._maximum = maximum
        self._content = bytearray()

    def write(self, value: bytes) -> int:
        if len(self._content) + len(value) > self._maximum:
            raise StrictJSONError("canonical JSON exceeds the configured byte limit")
        self._content.extend(value)
        return len(value)

    def getvalue(self) -> bytes:
        return bytes(self._content)


def _reject_constant(value: str) -> NoReturn:
    raise StrictJSONError(f"non-finite JSON number is not allowed: {value}")


def _parse_int(value: str) -> int:
    if value == "-0":
        raise StrictJSONError("negative zero is not allowed")
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > len(str(I_JSON_MAX_INTEGER)):
        raise StrictJSONError("JSON integer exceeds the interoperable I-JSON range")
    try:
        parsed = int(value)
    except ValueError as exc:
        # Python limits decimal-to-integer conversion length.  A hostile JSON
        # number must remain a parser decision, not escape as a runtime error.
        raise StrictJSONError("JSON integer exceeds the parser resource limit") from exc
    if abs(parsed) > I_JSON_MAX_INTEGER:
        raise StrictJSONError("JSON integer exceeds the interoperable I-JSON range")
    return parsed


def _parse_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictJSONError("non-finite JSON number is not allowed")
    if parsed == 0 and value.startswith("-"):
        raise StrictJSONError("negative zero is not allowed")
    significand = value.lower().partition("e")[0]
    if parsed == 0 and any(digit in significand for digit in "123456789"):
        raise StrictJSONError("JSON number underflows binary64")
    return parsed


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _record_id(record: dict[str, Any]) -> str:
    identity = record.get("id")
    if not isinstance(identity, str):
        raise StrictJSONError("JSONL records require string ids")
    return identity


def _reject_surrogates(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise StrictJSONError("Unicode surrogate code points are not allowed")


def _validate_tree(value: Any, limits: JSONLimits, depth: int = 0) -> None:
    if depth > limits.max_depth:
        raise StrictJSONError("JSON nesting exceeds the configured limit")
    if isinstance(value, str):
        if len(value) > limits.max_string_length:
            raise StrictJSONError("JSON string exceeds the configured limit")
        _reject_surrogates(value)
        return
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > I_JSON_MAX_INTEGER:
            raise StrictJSONError("JSON integer exceeds the interoperable I-JSON range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise StrictJSONError("non-finite JSON number is not allowed")
        if value == 0 and math.copysign(1.0, value) < 0:
            raise StrictJSONError("negative zero is not allowed")
        if value.is_integer() and abs(value) > I_JSON_MAX_INTEGER:
            raise StrictJSONError("integral JSON number exceeds the interoperable I-JSON range")
        return
    if isinstance(value, list):
        if len(value) > limits.max_collection_items:
            raise StrictJSONError("JSON array exceeds the configured item limit")
        for item in value:
            _validate_tree(item, limits, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > limits.max_collection_items:
            raise StrictJSONError("JSON object exceeds the configured member limit")
        for key, item in value.items():
            if type(key) is not str:
                raise StrictJSONError("JSON object keys must be strings")
            _reject_surrogates(key)
            if len(key) > limits.max_string_length:
                raise StrictJSONError("JSON object key exceeds the configured limit")
            _validate_tree(item, limits, depth + 1)
        return
    raise StrictJSONError(f"unsupported JSON value type: {type(value).__name__}")


def strict_json_loads(
    payload: bytes,
    *,
    limits: JSONLimits = DEFAULT_JSON_LIMITS,
) -> Any:
    if len(payload) > limits.max_bytes:
        raise StrictJSONError("JSON payload exceeds the configured byte limit")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("UTF-8 byte-order marks are not allowed")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("JSON payload is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise StrictJSONError("JSON nesting exceeds the parser limit") from exc
    _validate_tree(value, limits)
    return value


def canonical_json_bytes(
    value: Any,
    *,
    limits: JSONLimits = DEFAULT_JSON_LIMITS,
) -> bytes:
    _validate_tree(value, limits)
    sink = _BoundedSink(limits.max_bytes)
    try:
        rfc8785.dump(value, cast(IO[bytes], sink))
    except (rfc8785.CanonicalizationError, rfc8785.FloatDomainError) as exc:
        raise StrictJSONError(str(exc)) from exc
    return sink.getvalue()


def canonical_jsonl_bytes(
    records: Iterable[dict[str, Any]],
    *,
    sort_key: Callable[[dict[str, Any]], str] = _record_id,
    limits: JSONLimits = DEFAULT_JSON_LIMITS,
) -> bytes:
    materialized = list(islice(records, limits.max_collection_items + 1))
    if len(materialized) > limits.max_collection_items:
        raise StrictJSONError("JSONL record count exceeds the configured limit")
    keyed: list[tuple[str, dict[str, Any]]] = []
    for record in materialized:
        if not isinstance(record, dict):
            raise StrictJSONError("JSONL records must be objects")
        try:
            identity = sort_key(record)
        except (KeyError, TypeError, ValueError) as exc:
            raise StrictJSONError("JSONL record has no valid canonical sort key") from exc
        if not isinstance(identity, str):
            raise StrictJSONError("JSONL canonical sort keys must be strings")
        keyed.append((identity, record))
    ordered = sorted(keyed, key=lambda item: item[0])
    identities = [identity for identity, _ in ordered]
    if len(set(identities)) != len(identities):
        raise StrictJSONError("JSONL records have duplicate canonical sort keys")
    encoded = bytearray()
    for _, record in ordered:
        line = canonical_json_bytes(record, limits=limits)
        if len(line) > limits.max_line_bytes:
            raise StrictJSONError("JSONL line exceeds the configured byte limit")
        if len(encoded) + len(line) + 1 > limits.max_bytes:
            raise StrictJSONError("canonical JSONL exceeds the configured byte limit")
        encoded.extend(line)
        encoded.append(0x0A)
    return bytes(encoded)


def strict_jsonl_loads(
    payload: bytes,
    *,
    limits: JSONLimits = DEFAULT_JSON_LIMITS,
    require_sorted_ids: bool = False,
) -> list[dict[str, Any]]:
    if len(payload) > limits.max_bytes:
        raise StrictJSONError("JSONL payload exceeds the configured byte limit")
    if b"\r" in payload:
        raise StrictJSONError("canonical JSONL permits LF line endings only")
    if payload and not payload.endswith(b"\n"):
        raise StrictJSONError("canonical JSONL requires one final LF")
    records: list[dict[str, Any]] = []
    previous_id: str | None = None
    for line_number, line in enumerate(payload.split(b"\n")[:-1], start=1):
        if not line:
            raise StrictJSONError(f"blank JSONL line at {line_number}")
        if line.isspace():
            raise StrictJSONError(f"whitespace-only JSONL line at {line_number}")
        if len(line) > limits.max_line_bytes:
            raise StrictJSONError(f"JSONL line {line_number} exceeds the byte limit")
        value = strict_json_loads(line, limits=limits)
        if not isinstance(value, dict):
            raise StrictJSONError(f"JSONL line {line_number} is not an object")
        if canonical_json_bytes(value, limits=limits) != line:
            raise StrictJSONError(f"JSONL line {line_number} is not canonical JSON")
        if len(records) >= limits.max_collection_items:
            raise StrictJSONError("JSONL record count exceeds the configured limit")
        if require_sorted_ids:
            identity = value.get("id")
            if not isinstance(identity, str):
                raise StrictJSONError(f"JSONL line {line_number} requires a string id")
            if previous_id is not None and identity == previous_id:
                raise StrictJSONError(f"duplicate JSONL id at line {line_number}")
            if previous_id is not None and identity < previous_id:
                raise StrictJSONError("JSONL records are not sorted by id")
            previous_id = identity
        records.append(value)
    return records
