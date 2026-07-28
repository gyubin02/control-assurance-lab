"""Deterministic synthetic records for the financial support scenario."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

GENERATOR_VERSION = "financial-support-data/v1"


class DatasetProfile(StrEnum):
    SMOKE = "smoke"
    DEFAULT = "default"
    BENCHMARK = "benchmark"


@dataclass(frozen=True, slots=True)
class DatasetSize:
    customers: int
    accounts: int
    transactions: int
    support_cases: int
    support_principals: int
    compliance_principals: int


PROFILE_SIZES = {
    DatasetProfile.SMOKE: DatasetSize(
        customers=40,
        accounts=80,
        transactions=500,
        support_cases=20,
        support_principals=4,
        compliance_principals=1,
    ),
    DatasetProfile.DEFAULT: DatasetSize(
        customers=2_000,
        accounts=4_000,
        transactions=50_000,
        support_cases=200,
        support_principals=20,
        compliance_principals=2,
    ),
    DatasetProfile.BENCHMARK: DatasetSize(
        customers=20_000,
        accounts=40_000,
        transactions=1_000_000,
        support_cases=2_000,
        support_principals=100,
        compliance_principals=10,
    ),
}


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    role: str
    status: str
    entitlement_version: int


@dataclass(frozen=True, slots=True)
class Customer:
    customer_id: str
    display_name: str
    email: str
    customer_type: str
    region_code: str
    risk_tier: str
    synthetic: bool


@dataclass(frozen=True, slots=True)
class Account:
    account_id: str
    customer_id: str
    product_code: str
    currency: str
    status: str
    balance_minor: int


@dataclass(frozen=True, slots=True)
class Transaction:
    transaction_id: str
    account_id: str
    occurred_offset_seconds: int
    amount_minor: int
    direction: str
    counterparty_token: str
    channel: str


@dataclass(frozen=True, slots=True)
class SupportCase:
    case_id: str
    customer_id: str
    assigned_principal_id: str
    purpose: str
    status: str
    valid_from_offset_seconds: int
    valid_until_offset_seconds: int


DatasetRow = Principal | Customer | Account | Transaction | SupportCase


@dataclass(frozen=True, slots=True)
class SyntheticDataset:
    generator_version: str
    seed: int
    profile: DatasetProfile
    principals: tuple[Principal, ...]
    customers: tuple[Customer, ...]
    accounts: tuple[Account, ...]
    transactions: tuple[Transaction, ...]
    support_cases: tuple[SupportCase, ...]

    def tables(self) -> dict[str, tuple[DatasetRow, ...]]:
        return {
            "principals": self.principals,
            "customers": self.customers,
            "accounts": self.accounts,
            "transactions": self.transactions,
            "support_cases": self.support_cases,
        }

    def logical_digest(self) -> str:
        digest = hashlib.sha256()
        header = {
            "generator_version": self.generator_version,
            "profile": self.profile.value,
            "seed": self.seed,
        }
        digest.update(_canonical_json(header))
        digest.update(b"\n")
        for table_name, rows in sorted(self.tables().items()):
            for row in sorted(rows, key=_primary_key):
                digest.update(table_name.encode())
                digest.update(b"\0")
                digest.update(_canonical_json(asdict(row)))
                digest.update(b"\n")
        return digest.hexdigest()

    def manifest(self) -> dict[str, Any]:
        return {
            "schema": "assurance.synthetic-dataset/v1",
            "generator_version": self.generator_version,
            "seed": self.seed,
            "profile": self.profile.value,
            "counts": {name: len(rows) for name, rows in sorted(self.tables().items())},
            "logical_digest": self.logical_digest(),
        }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _primary_key(row: DatasetRow) -> str:
    if isinstance(row, Principal):
        return row.principal_id
    if isinstance(row, Customer):
        return row.customer_id
    if isinstance(row, Account):
        return row.account_id
    if isinstance(row, Transaction):
        return row.transaction_id
    if isinstance(row, SupportCase):
        return row.case_id
    raise TypeError(f"unsupported dataset row: {type(row).__name__}")


def generate_dataset(
    *,
    seed: int,
    profile: DatasetProfile = DatasetProfile.DEFAULT,
) -> SyntheticDataset:
    """Generate a dataset whose identifiers are deliberately unusable as real PII."""

    size = PROFILE_SIZES[profile]
    if size.accounts < size.customers:
        raise ValueError("each customer requires at least one account")
    if size.support_cases > size.customers:
        raise ValueError("support cases cannot exceed customer count")
    rng = random.Random(seed)

    support_principals = tuple(
        Principal(
            principal_id=f"support-{index:03d}",
            role="support",
            status="active",
            entitlement_version=1,
        )
        for index in range(1, size.support_principals + 1)
    )
    compliance_principals = tuple(
        Principal(
            principal_id=f"compliance-{index:03d}",
            role="compliance",
            status="active",
            entitlement_version=1,
        )
        for index in range(1, size.compliance_principals + 1)
    )
    customers = tuple(
        Customer(
            customer_id=f"SYNTH-CUSTOMER-{index:06d}",
            display_name=f"SYNTH-CUSTOMER-{index:06d}",
            email=f"customer-{index:06d}@example.invalid",
            customer_type="person" if index % 5 else "organization",
            region_code=f"LAB-{(index % 8) + 1:02d}",
            risk_tier=("standard", "review", "heightened")[index % 3],
            synthetic=True,
        )
        for index in range(1, size.customers + 1)
    )

    accounts_list: list[Account] = []
    for index in range(1, size.accounts + 1):
        customer = customers[(index - 1) % len(customers)]
        accounts_list.append(
            Account(
                account_id=f"LAB-ACCOUNT-{index:07d}",
                customer_id=customer.customer_id,
                product_code=("LAB-CASH", "LAB-SAVINGS", "LAB-BROKERAGE")[index % 3],
                currency="LAB",
                status="active",
                balance_minor=rng.randint(0, 50_000_000),
            )
        )
    accounts = tuple(accounts_list)

    hotspot_count = max(1, len(accounts) // 20)
    transactions_list: list[Transaction] = []
    for index in range(1, size.transactions + 1):
        if rng.random() < 0.35:
            account = accounts[rng.randrange(hotspot_count)]
        else:
            account = accounts[rng.randrange(len(accounts))]
        direction = "credit" if rng.random() < 0.48 else "debit"
        transactions_list.append(
            Transaction(
                transaction_id=f"LAB-TXN-{index:09d}",
                account_id=account.account_id,
                occurred_offset_seconds=rng.randrange(0, 30 * 24 * 60 * 60),
                amount_minor=rng.randint(100, 2_000_000),
                direction=direction,
                counterparty_token=f"SYNTH-CP-{rng.randrange(1, 501):05d}",
                channel=("lab-api", "lab-batch", "lab-branch")[index % 3],
            )
        )

    cases = tuple(
        SupportCase(
            case_id=f"CASE-{index:06d}",
            customer_id=customers[index - 1].customer_id,
            assigned_principal_id=support_principals[
                (index - 1) % len(support_principals)
            ].principal_id,
            purpose="synthetic support review",
            status="active",
            valid_from_offset_seconds=0,
            valid_until_offset_seconds=7 * 24 * 60 * 60,
        )
        for index in range(1, size.support_cases + 1)
    )
    return SyntheticDataset(
        generator_version=GENERATOR_VERSION,
        seed=seed,
        profile=profile,
        principals=support_principals + compliance_principals,
        customers=customers,
        accounts=accounts,
        transactions=tuple(transactions_list),
        support_cases=cases,
    )
