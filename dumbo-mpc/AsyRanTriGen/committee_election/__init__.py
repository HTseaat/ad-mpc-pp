"""Threshold-signature committee election primitives.

Stages 1--3 deliberately live outside the MPC execution path.  The package
contains deterministic data modelling, a thin wrapper around the existing
Boldyreva TBLS implementation, and an in-process asynchronous harness.
"""

from .model import (
    CandidateCommittee,
    CandidateRegistry,
    CommitteeMember,
    ElectionContext,
    ElectionModelError,
    SelectionResult,
    derive_coin_seed,
    deterministic_permutation,
    select_candidate,
)

__all__ = [
    "CandidateCommittee",
    "CandidateRegistry",
    "CommitteeMember",
    "ElectionContext",
    "ElectionModelError",
    "SelectionResult",
    "derive_coin_seed",
    "deterministic_permutation",
    "select_candidate",
]
