"""Algebraic, pairing, and base-link verification for stages 1--5."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Sequence

from .bootstrap import activate_upstream
from .base_link import DLEQProof, public_bases, verify_base_link_message
from .distributed_tau import LocalSetupResult


activate_upstream()

from pypairing import ZR, pair  # noqa: E402


@dataclass(frozen=True)
class VerificationReport:
    public_bases_ok: bool
    chain_length_ok: bool
    all_parties_same_chain: bool
    all_parties_same_h_chain: bool
    all_parties_same_g2: bool
    all_parties_same_h_commitments: bool
    all_parties_same_base_link_messages: bool
    reconstructed_chain_ok: bool
    reconstructed_h_powers_ok: bool
    reconstructed_h_chain_ok: bool
    reconstructed_alpha_g2_ok: bool
    pairing_recurrence_ok: bool
    h_pairing_recurrence_ok: bool
    base_link_dleq_ok: bool
    cleanup_ok: bool

    @property
    def ok(self) -> bool:
        return all(
            (
                self.public_bases_ok,
                self.chain_length_ok,
                self.all_parties_same_chain,
                self.all_parties_same_h_chain,
                self.all_parties_same_g2,
                self.all_parties_same_h_commitments,
                self.all_parties_same_base_link_messages,
                self.reconstructed_chain_ok,
                self.reconstructed_h_powers_ok,
                self.reconstructed_h_chain_ok,
                self.reconstructed_alpha_g2_ok,
                self.pairing_recurrence_ok,
                self.h_pairing_recurrence_ok,
                self.base_link_dleq_ok,
                self.cleanup_ok,
            )
        )


@dataclass(frozen=True)
class DistributedPartyVerificationReport:
    """Public checks one party can perform without reconstructing tau."""

    public_bases_ok: bool
    party_id_ok: bool
    chain_length_ok: bool
    chain_bases_ok: bool
    pairing_recurrence_ok: bool
    h_pairing_recurrence_ok: bool
    base_link_dleq_ok: bool
    h_commitment_view_ok: bool
    cleanup_ok: bool

    @property
    def ok(self) -> bool:
        return all(self.__dict__.values())


def reconstruct_alpha(result: LocalSetupResult):
    selected = result.parties[: result.params.t + 1]
    total = ZR(0)
    for party in selected:
        x_i = ZR(party.party_id + 1)
        coefficient = ZR(1)
        for other in selected:
            if other.party_id == party.party_id:
                continue
            x_j = ZR(other.party_id + 1)
            coefficient = coefficient * (-x_j) / (x_i - x_j)
        total = total + coefficient * party.alpha_share
    return total


def verify_pairing_recurrence(
    g_chain: Sequence[Any], g2: Any, alpha_g2: Any
) -> bool:
    if len(g_chain) < 2:
        return False
    return all(
        pair(g_chain[index], alpha_g2) == pair(g_chain[index + 1], g2)
        for index in range(len(g_chain) - 1)
    )


def verify_result(result: LocalSetupResult) -> VerificationReport:
    if not result.parties:
        return VerificationReport(*([False] * 15))

    first = result.parties[0]
    canonical_g, canonical_h, canonical_g2 = public_bases()
    public_bases_ok = (
        result.g == canonical_g
        and result.h == canonical_h
        and result.g2 == canonical_g2
    )
    count = result.params.log_q + 1
    chain_length_ok = all(
        len(party.g_chain) == result.params.effective_powers
        and len(party.h_chain) == result.params.effective_powers
        and len(party.powers_of_two_g1) == count
        and len(party.powers_of_two_h1) == count
        and len(party.powers_of_two_g2) == count
        and len(party.t_commits_g) == count
        and len(party.t_commits_h) == count
        and all(len(row) == result.params.n + 1 for row in party.t_commits_g)
        and all(len(row) == result.params.n + 1 for row in party.t_commits_h)
        and len(party.base_link_messages) == result.params.n
        for party in result.parties
    )
    all_parties_same_chain = all(
        party.g_chain == first.g_chain for party in result.parties
    )
    all_parties_same_h_chain = all(
        party.h_chain == first.h_chain for party in result.parties
    )
    all_parties_same_g2 = all(
        party.g2 == first.g2 and party.alpha_g2 == first.alpha_g2
        for party in result.parties
    )
    all_parties_same_h_commitments = all(
        party.t_commits_h == first.t_commits_h for party in result.parties
    )
    all_parties_same_base_link_messages = all(
        party.base_link_messages == first.base_link_messages
        for party in result.parties
    )

    alpha = reconstruct_alpha(result)
    reconstructed_chain_ok = first.g_chain[0] == result.g and all(
        point == result.g ** (alpha ** exponent)
        for exponent, point in enumerate(first.g_chain)
    )
    reconstructed_h_powers_ok = all(
        point == result.h ** (alpha ** (2**index))
        for index, point in enumerate(first.powers_of_two_h1)
    )
    reconstructed_h_chain_ok = first.h_chain[0] == result.h and all(
        point == result.h ** (alpha ** exponent)
        for exponent, point in enumerate(first.h_chain)
    )
    reconstructed_alpha_g2_ok = first.alpha_g2 == result.g2 ** alpha
    pairing_recurrence_ok = verify_pairing_recurrence(
        first.g_chain, result.g2, first.alpha_g2
    )
    h_pairing_recurrence_ok = verify_pairing_recurrence(
        first.h_chain, result.g2, first.alpha_g2
    )
    base_link_dleq_ok = chain_length_ok and all(
        verify_base_link_message(
            message,
            params=result.params,
            expected_party_id=party_id,
            g_commitments=tuple(
                first.t_commits_g[index][party_id + 1]
                for index in range(count)
            ),
            g=result.g,
            h=result.h,
        )
        for party_id, message in enumerate(first.base_link_messages)
    )
    cleanup_ok = result.pending_protocol_tasks == 0
    return VerificationReport(
        public_bases_ok=public_bases_ok,
        chain_length_ok=chain_length_ok,
        all_parties_same_chain=all_parties_same_chain,
        all_parties_same_h_chain=all_parties_same_h_chain,
        all_parties_same_g2=all_parties_same_g2,
        all_parties_same_h_commitments=all_parties_same_h_commitments,
        all_parties_same_base_link_messages=all_parties_same_base_link_messages,
        reconstructed_chain_ok=reconstructed_chain_ok,
        reconstructed_h_powers_ok=reconstructed_h_powers_ok,
        reconstructed_h_chain_ok=reconstructed_h_chain_ok,
        reconstructed_alpha_g2_ok=reconstructed_alpha_g2_ok,
        pairing_recurrence_ok=pairing_recurrence_ok,
        h_pairing_recurrence_ok=h_pairing_recurrence_ok,
        base_link_dleq_ok=base_link_dleq_ok,
        cleanup_ok=cleanup_ok,
    )


def verify_distributed_party_result(result: Any) -> DistributedPartyVerificationReport:
    """Verify a network party's public output without collecting secret shares.

    Cross-party agreement is intentionally left to the controller, which
    compares the canonical public SRS digest emitted independently by every
    node.  This avoids sending ``alpha_share`` to a central verifier.
    """

    if len(result.parties) != 1:
        return DistributedPartyVerificationReport(*([False] * 9))
    party = result.parties[0]
    canonical_g, canonical_h, canonical_g2 = public_bases()
    public_bases_ok = (
        result.g == canonical_g
        and result.h == canonical_h
        and result.g2 == canonical_g2
        and party.g2 == canonical_g2
    )
    count = result.params.log_q + 1
    party_id_ok = 0 <= party.party_id < result.params.n
    chain_length_ok = (
        len(party.g_chain) == result.params.effective_powers
        and len(party.h_chain) == result.params.effective_powers
        and len(party.powers_of_two_g1) == count
        and len(party.powers_of_two_h1) == count
        and len(party.powers_of_two_g2) == count
        and len(party.t_commits_g) == count
        and len(party.t_commits_h) == count
        and all(len(row) == result.params.n + 1 for row in party.t_commits_g)
        and all(len(row) == result.params.n + 1 for row in party.t_commits_h)
        and len(party.base_link_messages) == result.params.n
    )
    chain_bases_ok = (
        bool(party.g_chain)
        and bool(party.h_chain)
        and party.g_chain[0] == result.g
        and party.h_chain[0] == result.h
    )
    pairing_recurrence_ok = chain_length_ok and verify_pairing_recurrence(
        party.g_chain, result.g2, party.alpha_g2
    )
    h_pairing_recurrence_ok = chain_length_ok and verify_pairing_recurrence(
        party.h_chain, result.g2, party.alpha_g2
    )
    base_link_dleq_ok = chain_length_ok and all(
        verify_base_link_message(
            message,
            params=result.params,
            expected_party_id=sender,
            g_commitments=tuple(
                party.t_commits_g[index][sender + 1]
                for index in range(count)
            ),
            g=result.g,
            h=result.h,
        )
        for sender, message in enumerate(party.base_link_messages)
    )
    h_commitment_view_ok = chain_length_ok and all(
        party.t_commits_h[power_index][sender + 1]
        == party.base_link_messages[sender].h_commitments[power_index]
        for power_index in range(count)
        for sender in range(result.params.n)
    )
    return DistributedPartyVerificationReport(
        public_bases_ok=public_bases_ok,
        party_id_ok=party_id_ok,
        chain_length_ok=chain_length_ok,
        chain_bases_ok=chain_bases_ok,
        pairing_recurrence_ok=pairing_recurrence_ok,
        h_pairing_recurrence_ok=h_pairing_recurrence_ok,
        base_link_dleq_ok=base_link_dleq_ok,
        h_commitment_view_ok=h_commitment_view_ok,
        cleanup_ok=result.pending_protocol_tasks == 0,
    )


def tamper_is_rejected(result: LocalSetupResult) -> bool:
    first = result.parties[0]
    tampered = list(first.g_chain)
    tampered[1] = tampered[1] * result.g
    return not verify_pairing_recurrence(
        tampered, result.g2, first.alpha_g2
    )


def tampered_h_chain_is_rejected(result: LocalSetupResult) -> bool:
    first = result.parties[0]
    tampered = list(first.h_chain)
    tampered[1] = tampered[1] * result.h
    return not verify_pairing_recurrence(
        tampered, result.g2, first.alpha_g2
    )


def mismatched_alpha_h_chain_is_rejected(result: LocalSetupResult) -> bool:
    """Reject an h-chain generated independently with a different trapdoor."""

    alpha = reconstruct_alpha(result)
    other_alpha = alpha + ZR(1)
    mismatched = tuple(
        result.h ** (other_alpha ** exponent)
        for exponent in range(result.params.effective_powers)
    )
    return not verify_pairing_recurrence(
        mismatched, result.g2, result.parties[0].alpha_g2
    )


def _verify_replacement_message(
    result: LocalSetupResult, party_id: int, message: Any
) -> bool:
    first = result.parties[0]
    return verify_base_link_message(
        message,
        params=result.params,
        expected_party_id=party_id,
        g_commitments=tuple(
            first.t_commits_g[index][party_id + 1]
            for index in range(result.params.log_q + 1)
        ),
        g=result.g,
        h=result.h,
    )


def tampered_h_commitment_is_rejected(result: LocalSetupResult) -> bool:
    """Replace one H commitment while retaining its original proof."""

    message = result.parties[0].base_link_messages[0]
    commitments = list(message.h_commitments)
    commitments[0] = commitments[0] * result.h
    tampered = replace(message, h_commitments=tuple(commitments))
    return not _verify_replacement_message(result, 0, tampered)


def tampered_dleq_proof_is_rejected(result: LocalSetupResult) -> bool:
    """Replace one proof response while retaining its original statement."""

    message = result.parties[0].base_link_messages[0]
    proofs = list(message.proofs)
    proof = proofs[0]
    proofs[0] = DLEQProof(proof.challenge, proof.response + ZR(1))
    tampered = replace(message, proofs=tuple(proofs))
    return not _verify_replacement_message(result, 0, tampered)
