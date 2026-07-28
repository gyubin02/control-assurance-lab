from dataclasses import replace

from assurance_lab.scenarios.financial_data import (
    GENERATOR_VERSION,
    PROFILE_SIZES,
    DatasetProfile,
    generate_dataset,
)


def test_generation_is_reproducible_and_manifested() -> None:
    first = generate_dataset(seed=2907, profile=DatasetProfile.SMOKE)
    second = generate_dataset(seed=2907, profile=DatasetProfile.SMOKE)

    assert first == second
    assert first.logical_digest() == second.logical_digest()
    assert first.manifest() == second.manifest()
    assert first.manifest()["generator_version"] == GENERATOR_VERSION


def test_seed_changes_content_and_digest_without_changing_declared_size() -> None:
    first = generate_dataset(seed=1, profile=DatasetProfile.SMOKE)
    second = generate_dataset(seed=2, profile=DatasetProfile.SMOKE)

    assert first.logical_digest() != second.logical_digest()
    assert first.manifest()["counts"] == second.manifest()["counts"]


def test_smoke_profile_referential_integrity_and_synthetic_markers() -> None:
    dataset = generate_dataset(seed=17, profile=DatasetProfile.SMOKE)
    size = PROFILE_SIZES[DatasetProfile.SMOKE]
    customer_ids = {customer.customer_id for customer in dataset.customers}
    account_ids = {account.account_id for account in dataset.accounts}
    principal_ids = {principal.principal_id for principal in dataset.principals}

    assert len(dataset.customers) == size.customers
    assert len(dataset.accounts) == size.accounts
    assert len(dataset.transactions) == size.transactions
    assert len(dataset.support_cases) == size.support_cases
    assert all(account.customer_id in customer_ids for account in dataset.accounts)
    assert all(transaction.account_id in account_ids for transaction in dataset.transactions)
    assert all(case.customer_id in customer_ids for case in dataset.support_cases)
    assert all(case.assigned_principal_id in principal_ids for case in dataset.support_cases)
    assert all(customer.synthetic for customer in dataset.customers)
    assert all(
        customer.display_name.startswith("SYNTH-CUSTOMER-")
        and customer.email.endswith("@example.invalid")
        for customer in dataset.customers
    )
    assert all(account.account_id.startswith("LAB-ACCOUNT-") for account in dataset.accounts)
    assert {account.currency for account in dataset.accounts} == {"LAB"}


def test_logical_digest_is_independent_of_in_memory_row_order() -> None:
    dataset = generate_dataset(seed=31, profile=DatasetProfile.SMOKE)
    reordered = replace(
        dataset,
        customers=tuple(reversed(dataset.customers)),
        transactions=tuple(reversed(dataset.transactions)),
    )

    assert reordered.logical_digest() == dataset.logical_digest()
