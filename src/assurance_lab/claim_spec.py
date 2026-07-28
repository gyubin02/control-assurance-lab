"""Structured scope for claims evaluated by assurance experiments."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    NonNegativeInt,
    PositiveInt,
    model_validator,
)


class SubjectKind(StrEnum):
    IDENTITY = "identity"
    SERVICE = "service"
    CONTROL = "control"
    DATA_FLOW = "data_flow"
    PATH = "path"
    ENVIRONMENT = "environment"


class ClaimSubject(BaseModel):
    kind: SubjectKind
    identifier: str = Field(min_length=1)
    component: str = Field(min_length=1)


class ClaimPredicate(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    statement: str = Field(min_length=1)


class InputDomain(BaseModel):
    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    fixture_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class EnvironmentScope(BaseModel):
    scenario_id: str = Field(min_length=1)
    scenario_version: str = Field(min_length=1)
    build_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class TemporalScope(BaseModel):
    as_of: AwareDatetime
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None

    @model_validator(mode="after")
    def coherent_window(self) -> TemporalScope:
        if (self.window_start is None) != (self.window_end is None):
            raise ValueError("claim time window requires both start and end")
        if (
            self.window_start is not None
            and self.window_end is not None
            and self.window_end < self.window_start
        ):
            raise ValueError("claim time window ends before it starts")
        if (
            self.window_start is not None
            and self.window_end is not None
            and not self.window_start <= self.as_of <= self.window_end
        ):
            raise ValueError("claim as_of must fall inside its declared window")
        return self


class QuantifierKind(StrEnum):
    ALL_TESTED = "all_tested"
    EXISTS_COUNTEREXAMPLE = "exists_counterexample"
    AT_LEAST_RATE = "at_least_rate"


class ClaimQuantifier(BaseModel):
    kind: QuantifierKind
    minimum_rate: float | None = None
    minimum_trials: PositiveInt

    @model_validator(mode="after")
    def rate_matches_kind(self) -> ClaimQuantifier:
        if self.minimum_rate is not None and not math.isfinite(self.minimum_rate):
            raise ValueError("minimum rate must be finite")
        if self.kind == QuantifierKind.AT_LEAST_RATE:
            if self.minimum_rate is None or not 0 <= self.minimum_rate <= 1:
                raise ValueError("rate quantifier requires minimum_rate in [0, 1]")
        elif self.minimum_rate is not None:
            raise ValueError("minimum_rate is only valid for at_least_rate")
        return self


class ExactTolerance(BaseModel):
    kind: Literal["exact"] = "exact"


class FailureBudgetTolerance(BaseModel):
    kind: Literal["failure_budget"] = "failure_budget"
    max_failures: NonNegativeInt


class NumericTolerance(BaseModel):
    kind: Literal["numeric"] = "numeric"
    absolute: float = Field(ge=0)
    unit: str = Field(min_length=1)

    @model_validator(mode="after")
    def finite_absolute_tolerance(self) -> NumericTolerance:
        if not math.isfinite(self.absolute):
            raise ValueError("numeric tolerance must be finite")
        return self


Tolerance = Annotated[
    ExactTolerance | FailureBudgetTolerance | NumericTolerance,
    Field(discriminator="kind"),
]


class EvidencePolicyRef(BaseModel):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)


class ClaimSpec(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9._-]*$")
    subject: ClaimSubject
    predicate: ClaimPredicate
    input_domain: InputDomain
    environment: EnvironmentScope
    temporal: TemporalScope
    quantifier: ClaimQuantifier
    tolerance: Tolerance
    evidence_policy: EvidencePolicyRef
