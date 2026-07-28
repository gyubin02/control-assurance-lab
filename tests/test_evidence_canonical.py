import math
from collections.abc import Iterator
from decimal import Decimal

import pytest

from assurance_lab.evidence.canonical import (
    I_JSON_MAX_INTEGER,
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)


def test_key_order_and_whitespace_do_not_change_canonical_bytes() -> None:
    left = strict_json_loads(b'{ "z": 2, "a": [true, null] }')
    right = strict_json_loads(b'{"a":[true,null],"z":2}')

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(left) == b'{"a":[true,null],"z":2}'


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"\\u0061":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":-0}',
        b'{"value":-0.0}',
        b'{"value":-0e100}',
        b'{"value":1e-9999}',
        b'{"value":-1e-9999}',
        f'{{"value":{I_JSON_MAX_INTEGER + 1}}}'.encode(),
        f'{{"value":{-I_JSON_MAX_INTEGER - 1}}}'.encode(),
        b'{"value":"\\ud800"}',
        b'{"\\udfff":true}',
        b"\xef\xbb\xbf{}",
        b"\xff",
    ],
)
def test_strict_parser_rejects_ambiguous_or_non_interoperable_json(
    payload: bytes,
) -> None:
    with pytest.raises(StrictJSONError):
        strict_json_loads(payload)


@pytest.mark.parametrize(
    "value",
    [
        {"value": -0.0},
        {"value": math.nan},
        {"value": math.inf},
        {"value": I_JSON_MAX_INTEGER + 1},
        {"value": float(I_JSON_MAX_INTEGER + 1)},
        {"value": "\ud800"},
        {1: "non-string-key"},
        {"measurement": Decimal("1.25")},
    ],
)
def test_canonical_writer_rejects_unsafe_python_values(value: object) -> None:
    with pytest.raises(StrictJSONError):
        canonical_json_bytes(value)


def test_exact_decimal_values_are_encoded_as_strings() -> None:
    assert canonical_json_bytes({"measurement": "1.2500"}) == (
        b'{"measurement":"1.2500"}'
    )


def test_jsonl_is_sorted_and_requires_unique_ids() -> None:
    encoded = canonical_jsonl_bytes(
        [
            {"id": "event:2", "value": 2},
            {"id": "event:1", "value": 1},
        ]
    )

    assert encoded == (
        b'{"id":"event:1","value":1}\n'
        b'{"id":"event:2","value":2}\n'
    )
    assert [
        record["id"]
        for record in strict_jsonl_loads(encoded, require_sorted_ids=True)
    ] == ["event:1", "event:2"]

    with pytest.raises(StrictJSONError):
        canonical_jsonl_bytes(
            [
                {"id": "event:1", "value": 1},
                {"id": "event:1", "value": 2},
            ]
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"id":"event:1"}',
        b'{"id":"event:1"}\n\n',
        b'{"id":"event:1"}\r\n',
        b" \n",
        b'["not-an-object"]\n',
        b'{"id": "event:1"}\n',
        b'{"value":1,"id":"event:1"}\n',
    ],
)
def test_noncanonical_jsonl_is_rejected(payload: bytes) -> None:
    with pytest.raises(StrictJSONError):
        strict_jsonl_loads(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"id":"event:2"}\n{"id":"event:1"}\n',
        b'{"id":"event:1"}\n{"id":"event:1"}\n',
        b'{"value":1}\n',
    ],
)
def test_bundle_style_jsonl_requires_sorted_unique_string_ids(
    payload: bytes,
) -> None:
    with pytest.raises(StrictJSONError):
        strict_jsonl_loads(payload, require_sorted_ids=True)


def test_jsonl_writer_consumes_at_most_limit_plus_one_records() -> None:
    consumed = 0

    def records() -> Iterator[dict[str, str]]:
        nonlocal consumed
        while True:
            consumed += 1
            yield {"id": str(consumed)}

    with pytest.raises(StrictJSONError, match="record count"):
        canonical_jsonl_bytes(
            records(),
            limits=JSONLimits(max_collection_items=2),
        )

    assert consumed == 3


def test_jsonl_writer_enforces_total_size_while_encoding() -> None:
    with pytest.raises(StrictJSONError, match="byte limit"):
        canonical_jsonl_bytes(
            [{"id": "one"}, {"id": "two"}],
            limits=JSONLimits(max_bytes=20),
        )


def test_json_writer_enforces_size_during_serialization() -> None:
    with pytest.raises(StrictJSONError, match="byte limit"):
        canonical_json_bytes(
            {"value": "x" * 100},
            limits=JSONLimits(max_bytes=20),
        )


def test_jsonl_writer_requires_string_ids() -> None:
    with pytest.raises(StrictJSONError, match="sort key"):
        canonical_jsonl_bytes([{"id": 1}])


def test_excessive_parser_recursion_is_reported_as_strict_json_error() -> None:
    payload = (b"[" * 2_000) + b"0" + (b"]" * 2_000)

    with pytest.raises(StrictJSONError, match="nesting"):
        strict_json_loads(payload)
