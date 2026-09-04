"""Stage-4 links between the same scalar shares in two public G1 bases.

Each party publishes ``H_{i,k} = h ** share_{i,k}`` and proves, with a
domain-separated Chaum--Pedersen proof, that its existing G- and new
H-commitments contain the same discrete logarithm.  The phase has its own
``BASE_LINK`` message tag and does not run a second all-powers protocol.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any, Sequence, Tuple

from ..config import SetupParams
from .bootstrap import activate_upstream


activate_upstream()

from adkg.utils.poly_misc import interpolate_g1_at_x  # noqa: E402
from pypairing import G1, G2, ZR  # noqa: E402


BASE_LINK_TAG = "BASE_LINK"
BASE_LINK_TRANSCRIPT = b"Continuum/TrustedSetup/BASE_LINK/v1"
H_HASH_DOMAIN = b"Continuum/KZG-Pedersen/h/v1"


@dataclass(frozen=True)
class DLEQProof:
    challenge: Any
    response: Any


@dataclass(frozen=True)
class BaseLinkMessage:
    party_id: int
    run_id: str
    h_commitments: Tuple[Any, ...]
    proofs: Tuple[DLEQProof, ...]


@dataclass(frozen=True)
class BaseLinkView:
    """The complete, verified stage-4 view held by one party."""

    messages: Tuple[BaseLinkMessage, ...]
    # Indexed first by powers-of-two index.  Each row is the commitment at
    # x=0 followed by evaluations for parties 0 through n-1.
    t_commits_h: Tuple[Tuple[Any, ...], ...]


def public_bases() -> tuple[Any, Any, Any]:
    """Return canonical public ``g``, domain-derived ``h``, and ``g2``."""

    return G1(), G1.hash(H_HASH_DOMAIN), G2()


def _field(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _point_bytes(point: Any) -> bytes:
    return bytes(point.__getstate__())


def _challenge(
    *,
    run_id: str,
    party_id: int,
    power_index: int,
    g: Any,
    h: Any,
    g_commitment: Any,
    h_commitment: Any,
    nonce_g: Any,
    nonce_h: Any,
):
    transcript = b"".join(
        (
            _field(BASE_LINK_TRANSCRIPT),
            _field(run_id.encode("utf-8")),
            party_id.to_bytes(8, "big"),
            power_index.to_bytes(8, "big"),
            _field(_point_bytes(g)),
            _field(_point_bytes(h)),
            _field(_point_bytes(g_commitment)),
            _field(_point_bytes(h_commitment)),
            _field(_point_bytes(nonce_g)),
            _field(_point_bytes(nonce_h)),
        )
    )
    return ZR.hash(hashlib.sha256(transcript).digest())


def prove_same_exponent(
    secret: Any,
    g_commitment: Any,
    h_commitment: Any,
    *,
    g: Any,
    h: Any,
    run_id: str,
    party_id: int,
    power_index: int,
) -> DLEQProof:
    """Create a non-interactive Chaum--Pedersen equality proof."""

    # Fail closed if the caller accidentally links commitments not formed from
    # the supplied local scalar share.
    if g ** secret != g_commitment or h ** secret != h_commitment:
        raise ValueError("commitments do not match the supplied scalar share")

    nonce = ZR.rand()
    nonce_g = g ** nonce
    nonce_h = h ** nonce
    challenge = _challenge(
        run_id=run_id,
        party_id=party_id,
        power_index=power_index,
        g=g,
        h=h,
        g_commitment=g_commitment,
        h_commitment=h_commitment,
        nonce_g=nonce_g,
        nonce_h=nonce_h,
    )
    return DLEQProof(challenge, nonce - challenge * secret)


def verify_same_exponent(
    g_commitment: Any,
    h_commitment: Any,
    proof: DLEQProof,
    *,
    g: Any,
    h: Any,
    run_id: str,
    party_id: int,
    power_index: int,
) -> bool:
    """Verify one domain-separated Chaum--Pedersen equality proof."""

    try:
        nonce_g = g_commitment ** proof.challenge * g ** proof.response
        nonce_h = h_commitment ** proof.challenge * h ** proof.response
        expected = _challenge(
            run_id=run_id,
            party_id=party_id,
            power_index=power_index,
            g=g,
            h=h,
            g_commitment=g_commitment,
            h_commitment=h_commitment,
            nonce_g=nonce_g,
            nonce_h=nonce_h,
        )
        return expected == proof.challenge
    except (AttributeError, TypeError, ValueError):
        return False


def build_base_link_message(
    *,
    params: SetupParams,
    party_id: int,
    power_shares: Sequence[Any],
    g_commitments: Sequence[Any],
    g: Any,
    h: Any,
) -> BaseLinkMessage:
    count = params.log_q + 1
    if len(power_shares) != count or len(g_commitments) != count:
        raise ValueError("unexpected powers-of-two vector length")

    h_commitments = tuple(h ** power_shares[index] for index in range(count))
    proofs = tuple(
        prove_same_exponent(
            power_shares[index],
            g_commitments[index],
            h_commitments[index],
            g=g,
            h=h,
            run_id=params.run_id,
            party_id=party_id,
            power_index=index,
        )
        for index in range(count)
    )
    return BaseLinkMessage(
        party_id=party_id,
        run_id=params.run_id,
        h_commitments=h_commitments,
        proofs=proofs,
    )


def verify_base_link_message(
    message: BaseLinkMessage,
    *,
    params: SetupParams,
    expected_party_id: int,
    g_commitments: Sequence[Any],
    g: Any,
    h: Any,
) -> bool:
    count = params.log_q + 1
    if (
        not isinstance(message, BaseLinkMessage)
        or message.party_id != expected_party_id
        or message.run_id != params.run_id
        or len(g_commitments) != count
        or len(message.h_commitments) != count
        or len(message.proofs) != count
    ):
        return False
    return all(
        verify_same_exponent(
            g_commitments[index],
            message.h_commitments[index],
            message.proofs[index],
            g=g,
            h=h,
            run_id=params.run_id,
            party_id=expected_party_id,
            power_index=index,
        )
        for index in range(count)
    )


def _complete_h_commitments(
    messages: Sequence[BaseLinkMessage], params: SetupParams
) -> Tuple[Tuple[Any, ...], ...]:
    rows = []
    for power_index in range(params.log_q + 1):
        evaluations = tuple(
            message.h_commitments[power_index] for message in messages
        )
        # Any t+1 verified evaluations determine the degree-t commitment at
        # x=0.  Retain every party evaluation for the next all-powers phase.
        coords = [
            [party_id + 1, evaluations[party_id]]
            for party_id in range(params.t + 1)
        ]
        constant = interpolate_g1_at_x(coords, 0, G1, ZR)
        rows.append((constant,) + evaluations)
    return tuple(rows)


async def run_base_link_party(
    *,
    instance: Any,
    raw_output: Sequence[Any],
    params: SetupParams,
    g: Any,
    h: Any,
) -> BaseLinkView:
    party_id = instance.my_id
    power_shares = tuple(raw_output[5][index] for index in range(params.log_q + 1))
    g_commitments = tuple(
        raw_output[6][index][party_id + 1]
        for index in range(params.log_q + 1)
    )
    own_message = build_base_link_message(
        params=params,
        party_id=party_id,
        power_shares=power_shares,
        g_commitments=g_commitments,
        g=g,
        h=h,
    )

    # Reuse ADKG's root dispatcher while isolating this phase under a distinct
    # top-level protocol message domain.
    send = instance.get_send(BASE_LINK_TAG)
    recv = instance.subscribe_recv(BASE_LINK_TAG)
    for destination in range(params.n):
        send(destination, own_message)

    received: dict[int, BaseLinkMessage] = {}
    while len(received) < params.n:
        sender, message = await recv()
        if sender in received:
            continue
        sender_g_commitments = tuple(
            raw_output[6][index][sender + 1]
            for index in range(params.log_q + 1)
        )
        if not verify_base_link_message(
            message,
            params=params,
            expected_party_id=sender,
            g_commitments=sender_g_commitments,
            g=g,
            h=h,
        ):
            raise ValueError(f"invalid BASE_LINK message from party {sender}")
        received[sender] = message

    messages = tuple(received[index] for index in range(params.n))
    return BaseLinkView(messages, _complete_h_commitments(messages, params))


async def run_base_link_phase(
    *,
    instances: Sequence[Any],
    raw_outputs: Sequence[Sequence[Any]],
    params: SetupParams,
    g: Any,
    h: Any,
) -> Tuple[BaseLinkView, ...]:
    """Run the all-to-all ``BASE_LINK`` phase for every local party."""

    if len(instances) != params.n or len(raw_outputs) != params.n:
        raise ValueError("BASE_LINK requires one instance and output per party")
    tasks = [
        asyncio.create_task(
            run_base_link_party(
                instance=instance,
                raw_output=raw_output,
                params=params,
                g=g,
                h=h,
            )
        )
        for instance, raw_output in zip(instances, raw_outputs)
    ]
    try:
        return tuple(await asyncio.gather(*tasks))
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
