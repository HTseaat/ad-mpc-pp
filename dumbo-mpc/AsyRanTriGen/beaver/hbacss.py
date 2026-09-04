import logging
import asyncio
import os
from pickle import dumps, loads
from beaver.symmetric_crypto import SymmetricCrypto
from beaver.broadcast.reliablebroadcast import reliablebroadcast, rbc_dyn
from beaver.broadcast.avid import AVID, AVID_DYNAMIC
from beaver.utils.misc import wrap_send, subscribe_recv
import time
from ctypes import *
import json
import random
import sys
from Crypto.Util.number import long_to_bytes
from beaver.pvtransfer import EncResult, PVTransferPayload
from beaver.gather import YosoGather
from beaver.aggregation_interfaces import (
    aggregate_ipakzg_witness,
    agg_kzg_mode,
    aggtrans_proof_size_metadata,
    build_batchmul_public_payload,
    build_aggtrans_noagg_public_payload,
    build_aggtrans_public_payload,
    build_ipakzg_context,
    combine_batchmul_payload,
    combine_aggtrans_noagg_payload,
    combine_aggtrans_payload,
    configure_aggregation_ffi,
    derive_ipakzg_challenge,
    parse_batchmul_public_payload,
    parse_aggtrans_noagg_public_payload,
    parse_aggtrans_public_payload,
    prepare_aggtrans_noagg,
    prove_aggtrans_legacy,
    prove_aggtrans_v2,
    verify_agg_ped_eval_batch,
    verify_aggtrans_noagg_relation,
    verify_aggtrans,
)
from beaver.protocol_metrics import (
    AGGTRANS_BACSS_GENERATE_COMPONENTS,
    AGGTRANS_BACSS_VERIFY_COMPONENTS,
    AGGTRANS_NOAGG_GENERATE_COMPONENTS,
    AGGTRANS_NOAGG_VERIFY_COMPONENTS,
    BATCHMUL_BACSS_VERIFY_COMPONENTS,
    BATCHMUL_GENERATE_COMPONENTS,
    BATCHMUL_VERIFY_COMPONENTS,
    BGW_GENERATE_COMPONENTS,
    BGW_VERIFY_COMPONENTS,
    aggtrans_generate_components,
    aggtrans_verify_components,
    finalize_operation,
    proof_metadata,
    timed_call,
)

lib_bulletproof = CDLL("./libbulletproofs_amcl.so")

lib_bulletproof.pyProveFactors.argtypes = [c_char_p]
# lib_bulletproof.pyProveFactors.restype = c_char_p
lib_bulletproof.pyProveFactors.restype = c_void_p

# lib_bulletproof.pyFreeString.argtypes = [c_char_p]
lib_bulletproof.pyFreeString.argtypes = [c_void_p]  # ✅ 必须匹配！
lib_bulletproof.pyFreeString.restype = None

lib_bulletproof.pyVerifyFactors.argtypes = [c_char_p]
# lib_bulletproof.pyVerifyFactors.restype = 
lib_bulletproof.pyVerifyFactors.restype = c_void_p  # ✅ 正确类型！

lib_bulletproof.pyElGamalEncrypt.argtypes = [c_char_p]
lib_bulletproof.pyElGamalEncrypt.restype = c_void_p

lib_bulletproof.pyElGamalDecrypt.argtypes = [c_char_p]
lib_bulletproof.pyElGamalDecrypt.restype = c_void_p

lib_bulletproof.pyProveFull.argtypes = [c_char_p]
lib_bulletproof.pyProveFull.restype = c_void_p

lib_bulletproof.pyVerifyFull.argtypes = [c_char_p]
lib_bulletproof.pyVerifyFull.restype = c_void_p

lib_bulletproof.pyComputeCommitmentGH.argtypes = [c_char_p]
lib_bulletproof.pyComputeCommitmentGH.restype = c_void_p

lib_bulletproof.pySymEncrypt.argtypes = [c_char_p]
lib_bulletproof.pySymEncrypt.restype = c_void_p

lib_bulletproof.pySymDecrypt.argtypes = [c_char_p]
lib_bulletproof.pySymDecrypt.restype = c_void_p




lib = CDLL("./kzg_ped_out.so")

lib.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
lib.pyCommit.restype = c_char_p
lib.pyCommitWithZeroFull.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyCommitWithZeroFull.restype  = c_char_p
if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None

lib.pyKeyEphemeralGen.argtypes = [c_char_p]
lib.pyKeyEphemeralGen.restype = c_char_p

lib.pySharedKeysGen_sender.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_sender.restype = c_char_p

lib.pySharedKeysGen_recv.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_recv.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

lib.pyBatchVerifyUnbatched.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerifyUnbatched.restype = c_bool

# Public verifier for KZG opening proofs (uses OpeningProofPub JSON format)
lib.pyBatchVerifyPub.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerifyPub.restype = c_bool

lib.pyParseRandom.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyParseRandom.restype = c_char_p

lib.pyParseRandomUnbatched.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyParseRandomUnbatched.restype = c_char_p

lib.pyBatchhiddenverify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchhiddenverify.restype = c_bool

lib.pyBatchhiddenverifyUnbatched.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchhiddenverifyUnbatched.restype = c_bool

lib.pyBatchhiddenzeroverify.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyBatchhiddenzeroverify.restype = c_bool

lib.pyBatchhiddenzeroverifyUnbatched.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyBatchhiddenzeroverifyUnbatched.restype = c_bool

lib.pyProdverify.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyProdverify.restype = c_bool

lib.pyProdverifyUnbatched.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyProdverifyUnbatched.restype = c_bool

lib.pyMultiplyClaimedValuesWithAux.argtypes = [c_char_p, c_char_p]
lib.pyMultiplyClaimedValuesWithAux.restype = c_char_p

lib.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyPedersenCommit.restype = c_char_p

lib.pyComputeShareGH.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyComputeShareGH.restype = c_char_p

lib.pyPedersenCombine.argtypes = [c_char_p, c_char_p]
lib.pyPedersenCombine.restype = c_char_p

lib.pyDeriveChallenge.argtypes = [c_char_p]
lib.pyDeriveChallenge.restype = c_char_p

lib.pyAggProveEvalZero.argtypes = [c_char_p, c_char_p]
lib.pyAggProveEvalZero.restype = c_char_p

lib.pyPubAggVerifyEval.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyPubAggVerifyEval.restype = c_bool

lib.pyPubAggVerifyEvalCombined.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyPubAggVerifyEvalCombined.restype = c_bool

configure_aggregation_ffi(lib)


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


def _call_with_bgw_metric(
        mpc_instance, proof_metric, metric_component, function, args,
        success=None):
    if proof_metric is None or metric_component is None:
        return function(*args)
    return timed_call(
        mpc_instance, proof_metric, metric_component, function, *args,
        success=success,
    )


def _timed_bgw_unbatched_call(
        function_name, function, args, context="", *, mpc_instance=None,
        proof_metric=None, metric_component=None, success=None):
    start = time.time()
    result = _call_with_bgw_metric(
        mpc_instance, proof_metric, metric_component, function, args, success,
    )
    elapsed = time.time() - start
    suffix = f", {context}" if context else ""
    logger.info(
        "bgw_unbatched_call_time: function=%s, elapsed=%s%s",
        function_name,
        elapsed,
        suffix,
    )
    return result


def _generate_ipakzg_aggregate_witnesses(
    *,
    mpc_instance,
    proof_metric,
    dealer_local_id,
    srs_pk,
    srs_vk,
    left_commitments,
    right_commitments,
    output_commitments,
    left_pedersen,
    right_pedersen,
    output_pedersen,
    left_openings,
    right_openings,
    output_openings,
):
    """Derive one full-context IPAKZG challenge and aggregate all witnesses."""
    context = build_ipakzg_context(
        dealer_local_id,
        left_commitments,
        right_commitments,
        output_commitments,
        left_pedersen,
        right_pedersen,
        output_pedersen,
    )
    challenge = timed_call(
        mpc_instance,
        proof_metric,
        "challenge_derivation",
        derive_ipakzg_challenge,
        lib,
        srs_pk,
        srs_vk,
        context,
    )

    def aggregate(relation, openings):
        return aggregate_ipakzg_witness(
            library=lib,
            context=context,
            relation=relation,
            openings=openings,
            gamma=challenge,
        )

    output_witness = timed_call(
        mpc_instance,
        proof_metric,
        "output_zero_aggregation",
        aggregate,
        "output",
        output_openings,
    )
    left_witness = timed_call(
        mpc_instance,
        proof_metric,
        "left_anchor_aggregation",
        aggregate,
        "left",
        left_openings,
    )
    right_witness = timed_call(
        mpc_instance,
        proof_metric,
        "right_anchor_aggregation",
        aggregate,
        "right",
        right_openings,
    )
    return left_witness, right_witness, output_witness


def _verify_ipakzg_aggregate_relations(
    *,
    mpc_instance,
    proof_metric,
    dealer_local_id,
    srs_pk,
    srs_vk,
    left_commitments,
    right_commitments,
    output_commitments,
    left_pedersen,
    right_pedersen,
    output_pedersen,
    left_witness,
    right_witness,
    output_witness,
):
    """Run the revised Fig. 5 AggPedVerEval for all BatchMul relations."""
    context = build_ipakzg_context(
        dealer_local_id,
        left_commitments,
        right_commitments,
        output_commitments,
        left_pedersen,
        right_pedersen,
        output_pedersen,
    )

    verification = timed_call(
        mpc_instance,
        proof_metric,
        "aggped_batch_verify",
        lambda: verify_agg_ped_eval_batch(
            library=lib,
            srs_pk=srs_pk,
            srs_vk=srs_vk,
            context=context,
            left_witness=left_witness,
            right_witness=right_witness,
            output_witness=output_witness,
        ),
        success=lambda result: result.accepted,
    )
    return (
        verification.left_valid,
        verification.right_valid,
        verification.output_valid,
    )


def _verify_aggtrans_noagg_relations(
    *,
    mpc_instance,
    proof_metric,
    dealer_local_id,
    srs_vk,
    old_commitments,
    fresh_commitments,
    old_witnesses,
    fresh_witnesses,
    pedersen,
):
    """Run both NoAgg relations independently, with no boolean short-circuit."""
    old_anchor_valid = timed_call(
        mpc_instance,
        proof_metric,
        "old_anchor_batch_verify",
        lambda: verify_aggtrans_noagg_relation(
            library=lib,
            srs_vk=srs_vk,
            commitments=old_commitments,
            witnesses=old_witnesses,
            pedersen=pedersen,
            evaluation_index=dealer_local_id,
        ),
        success=bool,
    )
    fresh_zero_valid = timed_call(
        mpc_instance,
        proof_metric,
        "fresh_zero_batch_verify",
        lambda: verify_aggtrans_noagg_relation(
            library=lib,
            srs_vk=srs_vk,
            commitments=fresh_commitments,
            witnesses=fresh_witnesses,
            pedersen=pedersen,
            evaluation_index=-1,
        ),
        success=bool,
    )
    return bool(old_anchor_valid), bool(fresh_zero_valid)


def _bgw_use_batch_verify(component):
    return (
        os.getenv("BGW_UNBATCHED_BATCH_ALL_VERIFY") == "1"
        or os.getenv(f"BGW_UNBATCHED_BATCH_{component.upper()}_VERIFY") == "1"
    )


def _timed_bgw_mixed_batch_call(
        component, function_name, function, args, context="", *,
        mpc_instance=None, proof_metric=None, metric_component=None,
        success=None):
    start = time.time()
    result = _call_with_bgw_metric(
        mpc_instance, proof_metric, metric_component, function, args, success,
    )
    elapsed = time.time() - start
    suffix = f", {context}" if context else ""
    logger.info(
        "bgw_mixed_batch_%s_verify_time: function=%s, elapsed=%s%s",
        component,
        function_name,
        elapsed,
        suffix,
    )
    return result


def _timed_bgw_batch_unbatched_call(
        component, function_name, function, args, context="", *,
        mpc_instance=None, proof_metric=None, metric_component=None,
        success=None):
    start = time.time()
    result = _call_with_bgw_metric(
        mpc_instance, proof_metric, metric_component, function, args, success,
    )
    elapsed = time.time() - start
    suffix = f", {context}" if context else ""
    logger.info(
        "bgw_batch_unbatched_%s_verify_time: function=%s, elapsed=%s%s",
        component,
        function_name,
        elapsed,
        suffix,
    )
    return result


def _timed_bgw_product_generation_call(
        mode, function_name, function, args, context="", *, mpc_instance=None,
        proof_metric=None, metric_component=None, success=None):
    start = time.time()
    result = _call_with_bgw_metric(
        mpc_instance, proof_metric, metric_component, function, args, success,
    )
    elapsed = time.time() - start
    suffix = f", {context}" if context else ""
    logger.info(
        "bgw_product_proof_generation_time: mode=%s, function=%s, elapsed=%s%s",
        mode,
        function_name,
        elapsed,
        suffix,
    )
    if mode == "unbatched":
        logger.info(
            "bgw_unbatched_call_time: function=%s, elapsed=%s%s",
            function_name,
            elapsed,
            suffix,
        )
    return result


def _binary_payload_size(value):
    """Return the binary size of a proof carried as bytes or a hex string."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    if isinstance(value, str):
        try:
            return len(bytes.fromhex(value))
        except ValueError:
            return len(value.encode("utf-8"))
    return len(dumps(value))


def _record_hbacss_payload_calibration(
        instance, broadcast_msg, dispersal_msg_list, local_values):
    """Record enough payload data to rebuild paper-size HBACSS bodies.

    The implementation serializes curve objects as decimal JSON.  The audit
    keeps the measured RBC/AVID control schedule, but needs the logical batch
    size (and the Bulletproof byte length) to replace those objects with their
    canonical binary sizes.  AggTrans public proof vectors are carried once
    in the RBC envelope; receiver-specific openings remain in AVID.
    """
    metrics_recorder = getattr(
        getattr(instance, "mpc_instance", None), "metrics_recorder", None
    )
    protocol_by_mode = {
        "avss_with_transfer": "aggtrans-noagg",
        "avss_with_aggtransfer": "aggtrans",
        "avss_with_aggbatch_multiplication": "batchmul",
        "avss_with_proof": "bgw",
    }
    protocol = protocol_by_mode.get(instance.mode)
    if metrics_recorder is None or protocol is None:
        return

    entry = {
        "protocol": protocol,
        "dealer_local_id": instance.my_id,
        "public_payload_bytes": len(broadcast_msg),
        "private_ciphertext_bytes": [
            len(ciphertext) for ciphertext in dispersal_msg_list
        ],
    }
    if instance.mode == "avss_with_proof":
        parsed = local_values["deser_comsandproofs"]
        entry["batch_size"] = len(parsed["commitments_c"])
        entry["product_proof_count"] = len(parsed["prodProofs"])
    elif instance.mode == "avss_with_aggbatch_multiplication":
        parsed = local_values["deser_comandproofwithzero"]
        entry["batch_size"] = len(parsed["commitmentList"])
        entry["factor_proof_bytes"] = _binary_payload_size(
            local_values["proof"]
        )
    metrics_recorder.record_payload_calibration(**entry)


def _build_hbacss_broadcast_payload(
    instance,
    serialized_commitment,
    serialized_ephemeral_public_key,
    local_values,
):
    """Put the common transfer transcript in RBC, never in private AVID."""
    if instance.mode == "avss_with_transfer":
        public_payload = build_aggtrans_noagg_public_payload(
            local_values["serialized_original_commitment"],
            local_values["noagg_artifacts"],
        )
        return dumps((
            serialized_commitment,
            serialized_ephemeral_public_key,
            public_payload,
        ))
    if instance.mode == "avss_with_aggtransfer":
        public_payload = build_aggtrans_public_payload(
            instance.agg_kzg_mode,
            local_values["serialized_original_commitment"],
            v2=local_values.get("aggtrans_v2"),
            legacy=local_values.get("aggtrans_legacy"),
        )
        return dumps((
            serialized_commitment,
            serialized_ephemeral_public_key,
            public_payload,
        ))
    if instance.mode == "avss_with_aggbatch_multiplication":
        public_payload = build_batchmul_public_payload(
            left_commitments=local_values["serialized_left_commitment"],
            right_commitments=local_values["serialized_right_commitment"],
            left_witness=local_values["ser_aggleftproof"],
            right_witness=local_values["ser_aggrightproof"],
            output_witness=local_values["ser_aggproofAtZero"],
            left_pedersen=local_values["ser_pedersen_left"],
            right_pedersen=local_values["ser_pedersen_right"],
            output_pedersen=local_values["ser_pedersen_output"],
            factor_proof=local_values["proof"],
        )
        return dumps((
            serialized_commitment,
            serialized_ephemeral_public_key,
            public_payload,
        ))
    return dumps((serialized_commitment, serialized_ephemeral_public_key))


def _parse_hbacss_broadcast_payload(instance, rbc_msg):
    """Parse the RBC envelope and type-check any common transfer bundle."""
    envelope = loads(rbc_msg)
    transfer_modes = {
        "avss_with_transfer", "avss_with_aggtransfer",
        "avss_with_aggbatch_multiplication",
    }
    expected_length = 3 if instance.mode in transfer_modes else 2
    if not isinstance(envelope, tuple) or len(envelope) != expected_length:
        raise ValueError(
            f"invalid {instance.mode} RBC envelope: expected "
            f"{expected_length} fields"
        )
    serialized_commitment = envelope[0]
    serialized_ephemeral_public_key = envelope[1]
    public_payload = None
    if instance.mode == "avss_with_transfer":
        public_payload = parse_aggtrans_noagg_public_payload(envelope[2])
    elif instance.mode == "avss_with_aggtransfer":
        public_payload = parse_aggtrans_public_payload(
            instance.agg_kzg_mode, envelope[2]
        )
    elif instance.mode == "avss_with_aggbatch_multiplication":
        public_payload = parse_batchmul_public_payload(envelope[2])
    return (
        serialized_commitment,
        serialized_ephemeral_public_key,
        public_payload,
    )


class HbAVSSMessageType:
    OK = "OK"
    IMPLICATE = "IMPLICATE"
    READY = "READY"
    RECOVERY = "RECOVERY"
    RECOVERY1 = "RECOVERY1"
    RECOVERY2 = "RECOVERY2"
    KDIBROADCAST = "KDIBROADCAST"

class Hbacss0:
    #@profile
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, msgmode):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)
        #todo: g should be baked into the pki or something
        self.srs_kzg = crs
        # deserialized_srs_kzg = json.loads(crs.decode('utf-8'))
        # self.srs_pk = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
        
        self.mode = msgmode
        self.agg_kzg_mode = agg_kzg_mode()
        if os.getenv("DISABLE_AGG_PROTO") == "1":
            if self.mode == "avss_with_aggtransfer":
                self.mode = "avss_with_transfer"
            elif self.mode == "avss_with_aggbatch_multiplication":
                self.mode = "avss_with_batch_multiplication"

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        self.avid_msg_queue = asyncio.Queue()
        self.tasks = []
        self.shares_future = asyncio.Future()
        self.output_queue = asyncio.Queue(maxsize=self.n)
        self.tagvars = {}

    async def _recv_loop(self, q):           
        avid, tag, dispersal_msg_list = await q.get()
        await avid.disperse(tag, self.my_id, dispersal_msg_list)
        
    def __enter__(self):
        # self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
                
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # TODO: Add the handle implication
        pass
        # commitments =  self.tagvars[tag]['commitments']
        # # discard if PKj ! = g^SKj
        # if self.public_keys[j] != pow(self.g, j_sk):
        #     return False
        # # decrypt and verify
        # implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        # j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # # Same as the batch size
        # secret_count = len(commitments)

        # try:
        #     j_shares, j_auxes, j_witnesses = SymmetricCrypto.decrypt(
        #         str(j_shared_key).encode(), implicate_msg
        #     )
        # except Exception as e:  # TODO specific exception
        #     logger.warn("Implicate confirmed, bad encryption:", e)
        #     return True
        # return not self.poly_commit.batch_verify_eval(
        #     commitments, j + 1, j_shares, j_auxes, j_witnesses
        # )



    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
        #     logger.debug("[%d] sent_kdi_broadcast", self.my_id)
        #     kdi = self.tagvars[tag]['shared_key']
        #     multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
        #     self.kdi_broadcast_sent = True
        # if self.tagvars[tag]['all_shares_valid']:
        #     return

        # if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
        #     logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
        #     avid = self.tagvars[tag]['avid']
        #     retrieved_msg = await avid.retrieve(tag, sender)
        #     try:
        #         j_shares, j_witnesses = SymmetricCrypto.decrypt(
        #             str(avss_msg[1]).encode(), retrieved_msg
        #         )
        #     except Exception as e:  # TODO: Add specific exception
        #         logger.debug("Implicate confirmed, bad encryption:", e)
        #     commitments = self.tagvars[tag]['commitments']
        #     if (self.poly_commit.batch_verify_eval(commitments,
        #                                            sender + 1, j_shares, j_witnesses)):
        #         if not self.saved_shares[sender]:
        #             self.saved_shared_actual_length += 1
        #             self.saved_shares[sender] = j_shares

        # # if t+1 in the saved_set, interpolate and sell all OK
        # if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
        #     logger.debug("[%d] interpolating", self.my_id)
        #     # Batch size
        #     shares = []
        #     secret_count = len(self.tagvars[tag]['commitments'])
        #     for i in range(secret_count):
        #         phi_coords = [
        #             (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
        #         ]
        #         shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
        #     self.tagvars[tag]['all_shares_valid'] = True
        #     self.tagvars[tag]['shares'] = shares
        #     self.tagvars[tag]['in_share_recovery'] = False
        #     self.interpolated = True
        #     multicast((HbAVSSMessageType.OK, ""))
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        logging.info("enter _process_avss_msg")
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        # self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        # self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable broadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(dealer_id, tag, dispersal_msg, rbc_msg)

        logging.info("after self._handle_dealer_msgs")
        
        if self.tagvars[tag]['all_shares_valid']:
            if self.mode == "avss_without_proof":
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_proof":
                logging.debug(f"dealer_id: {dealer_id}")
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_transfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggtransfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggbatch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            if self.mode == "avss_with_batch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            output = True
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

        # obtain
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()
            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    # ------------------------------------------------------------------
    #  Helper: run local ΠGather + ΠSelectBlock
    # ------------------------------------------------------------------
    async def _run_local_gather(self, node_communicator):
        """
        把 self.pvtransfer_bytes 当作 B_i，启动 YosoGather，
        等它跑完 Strongly-Stable 选块协议。
        """
        from beaver.gather import YosoGather   # 延迟 import 避免循环

        g = YosoGather(
            self.public_keys, self.private_key,
            self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            self.pvtransfer_bytes          # ★ B_i
        )
        task = asyncio.create_task(g.run_gather(node_communicator))
        await task         # ← 在协程内合法使用 await
        g.kill()

        logging.info(
            "[%d] ΠGather done – |U₃|=%d, g=%s, |C|=%d",
            self.my_id,
            len(getattr(g, "U", {})),
            getattr(g, "g", "NA"),
            len(getattr(g, "final_block", b"")),
        )

    #@profile
    def _get_dealer_msg(self, acsstag, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        proofandshares = []
        
        if self.mode == "avss_without_proof":
            commitmentlistandprooflist = lib.pyCommit(self.srs_kzg['Pk'], values, self.t)
            logging.info("after pyCommit commitmentlistandprooflist")
            
            deserialized_commitmentlistandprooflist = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deserialized_commitmentlistandprooflist['commitmentList']).encode('utf-8')            
            for i in range(self.n):
                proofandshares.append(json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8'))
            # logging.info("avss_without_proof proofandshares: %s", proofandshares)
        if self.mode == "avss_with_proof":
            deserialized_commandprooflist = json.loads(values.decode('utf-8'))
            bgw_batch_size = len(deserialized_commandprooflist['commitment']) // 2
            mpc_instance = getattr(self, "mpc_instance", None)
            bgw_layer = int(getattr(mpc_instance, "layer_ID", -1))
            bgw_generation_metric = proof_metadata(
                mpc_instance,
                protocol="bgw",
                operation="bgw_generate",
                dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=bgw_batch_size,
                normalization_count=bgw_batch_size,
                unit="gate",
                source_layer=bgw_layer,
                target_layer=bgw_layer,
            )
            serialized_commitmentlist = json.dumps(deserialized_commandprooflist['commitment']).encode('utf-8')
            serialized_prooflist = json.dumps(deserialized_commandprooflist['proof']).encode('utf-8')
            product_generation_context = (
                f"my_id={self.my_id}, t={self.t}, "
                f"commitments={len(deserialized_commandprooflist['commitment'])}, "
                f"proofs={len(deserialized_commandprooflist['proof'])}, "
                f"expected_product_proofs={len(deserialized_commandprooflist['commitment']) // 2}"
            )
            if os.getenv("BGW_UNBATCHED_VERIFY") == "1":
                commitmentlistandprooflist = _timed_bgw_product_generation_call(
                    "unbatched",
                    "pyParseRandomUnbatched",
                    lib.pyParseRandomUnbatched,
                    (
                        self.srs_kzg['Pk'],
                        serialized_commitmentlist,
                        serialized_prooflist,
                        self.t,
                        self.my_id,
                    ),
                    product_generation_context,
                    mpc_instance=mpc_instance,
                    proof_metric=bgw_generation_metric,
                    metric_component="degree_reduction_proof_generation",
                )
            else:
                commitmentlistandprooflist = _timed_bgw_product_generation_call(
                    "batched",
                    "pyParseRandom",
                    lib.pyParseRandom,
                    (
                        self.srs_kzg['Pk'],
                        serialized_commitmentlist,
                        serialized_prooflist,
                        self.t,
                        self.my_id,
                    ),
                    product_generation_context,
                    mpc_instance=mpc_instance,
                    proof_metric=bgw_generation_metric,
                    metric_component="degree_reduction_proof_generation",
                )

            deser_comsandproofs = json.loads(commitmentlistandprooflist.decode('utf-8'))
            # logging.info("deser_comsandproofs: %s", deser_comsandproofs)
            serialized_commitment = json.dumps(deser_comsandproofs['commitments_c']).encode('utf-8') 
            serialized_zkProof_ab = json.dumps(deser_comsandproofs['zkProof_ab']).encode('utf-8') 
            serialized_zkProof_c_zero = json.dumps(deser_comsandproofs['zkProof_c_zero']).encode('utf-8') 
            serialized_prodProofs = json.dumps(deser_comsandproofs['prodProofs']).encode('utf-8') 
            finalize_operation(
                mpc_instance,
                bgw_generation_metric,
                BGW_GENERATE_COMPONENTS,
                success=True,
            )
            logger.info(f"prodProofs size: {len(serialized_prodProofs)} bytes")
            logger.info(f"prodProofs count: {len(deser_comsandproofs['prodProofs'])}")
            
            for i in range(self.n):
                proofandshares.append(json.dumps(deser_comsandproofs['proofs_c'][i]).encode('utf-8'))   
            # logging.info("proofandshares: %s", proofandshares)

        if self.mode == "avss_with_transfer": 
            # `values` carries the serialized `com_and_proof_obj` produced in
            # setup_transfer.log.  Extract ClaimedValue / ClaimedValueAux,
            # build the two secret vectors, and obtain commitments & proofs
            # that also include f(0) related data via pyCommitWithZeroFull.
            # -------------------------------------------------------------
            # robust JSON decode (handle both normal JSON and python‐repr)
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("secrets: %s", secrets)
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            mpc_instance = getattr(self, "mpc_instance", None)
            noagg_generation_metric = proof_metadata(
                mpc_instance, protocol="aggtrans-noagg",
                operation="noagg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None, batch_size=len(proofs_lst),
            )
            comandproofwithzero = timed_call(
                mpc_instance, noagg_generation_metric,
                "commitment_opening_generation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)
            # logging.info("serialized_commitment: %s", serialized_commitment)


            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            # logging.info("proof_at_zero_Honly: %s", proof_at_zero_Honly)

            noagg_artifacts = prepare_aggtrans_noagg(
                library=lib,
                old_commitments=original_commitment,
                fresh_commitments=deser_comandproofwithzero["commitmentList"],
                old_witnesses=original_proof_no_val,
                fresh_witnesses=proof_at_zero_Honly,
                share_g=deser_comandproofwithzero.get("shareG", []),
                share_h=deser_comandproofwithzero.get("shareH", []),
                pedersen_combine=lambda share_g, share_h: timed_call(
                    mpc_instance, noagg_generation_metric,
                    "pedersen_commitment_preparation",
                    lib.pyPedersenCombine, share_g, share_h,
                ),
            )
            finalize_operation(
                mpc_instance, noagg_generation_metric,
                AGGTRANS_NOAGG_GENERATE_COMPONENTS, success=True,
            )

        if self.mode == "avss_with_aggtransfer": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            fresh_openings = deser_comandproofwithzero.get("proofAtZero", [])
            aggtrans_v2 = None
            aggtrans_legacy = None
            if self.agg_kzg_mode in {"v2", "shadow"}:
                aggtrans_v2 = prove_aggtrans_v2(
                    library=lib, srs_pk=self.srs_kzg['Pk'],
                    srs_vk=self.srs_kzg['Vk'], dealer_local_id=self.my_id,
                    old_commitments=original_commitment,
                    fresh_commitments=deser_comandproofwithzero["commitmentList"],
                    old_openings=proofs_lst, fresh_openings=fresh_openings,
                )
            if self.agg_kzg_mode in {"legacy", "shadow"}:
                aggtrans_legacy = prove_aggtrans_legacy(
                    library=lib,
                    fresh_commitments=deser_comandproofwithzero["commitmentList"],
                    old_openings=proofs_lst, fresh_openings=fresh_openings,
                    share_g=deser_comandproofwithzero.get("shareG", []),
                    share_h=deser_comandproofwithzero.get("shareH", []),
                )

            logging.info("self.public_keys: %s", self.public_keys)
            logging.info("self.private_key: %s", self.private_key)          


            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggproofAtZero).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     0                 # C.int
            # )
            # logging.info("x=0 pyPubAggVerifyEval result: %s", ok)

            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_original_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggoriginalproof).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     self.my_id + 1                 # C.int
            # )
            # logging.info("x=my.id pyPubAggVerifyEval result: %s", ok)

            # --------------------- 从这行开始，后续的代码都是用来测试 Poseidon + Bulletproof 的 --------------------

            pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            g0 = pk_dict["G1_g"][0]
            h0 = pk_dict["G1_h"][0]

            # read G1_g[0] X/Y 
            gx_dec = int(g0["X"])
            gy_dec = int(g0["Y"])

            # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            gx_bytes = long_to_bytes(gx_dec, 48)
            gy_bytes = long_to_bytes(gy_dec, 48)

            uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_g_hex = uncompressed_g.hex()
            logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

            # add h0
            hx_dec = int(h0["X"])
            hy_dec = int(h0["Y"])

            # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            hx_bytes = long_to_bytes(hx_dec, 48)
            hy_bytes = long_to_bytes(hy_dec, 48)

            uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            uncompressed_h_hex = uncompressed_h.hex()
            logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
            
            sk = "43066057178372115162090031665738480497785504495963485110743715314730498099898"
            sk_hex = hex(int(sk))[2:]  # 去掉 0x 前缀
            pk_x = "2540810243697281646753816249646546839680056672316758359369207562792691238809422685043919463202492103317975796630457"
            pk_y = "50066053523316668810016801456660224022045904723296188340443488016713934584332814528641622484569632142481660547518"
            pkx_bytes = long_to_bytes(int(pk_x), 48)
            pky_bytes = long_to_bytes(int(pk_y), 48)

            uncompressed_pk = b'\x04' + pkx_bytes + pky_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_pk_hex = uncompressed_pk.hex()
            logging.info("uncompressed_pk.hex(): %s", uncompressed_pk.hex())

            k = "6706283196960114501037797896778429581316608798606687574701835551207274422636"
            k_hex = hex(int(k))[2:]  # 去掉 0x 前缀
            k_x = "1414576985840271823358185120885954780171082639683846674231723237543180390154178096938117414806051004278910490643080"
            k_y = "2646059067981507357143657154501587172603295817551133156830318975462005332733650918056918384628991898173670748015537"

            r = "1757101419104903848312328479324811944822009314342771061452727681968477199489"
            r_hex = hex(int(r))[2:]  # 去掉 0x 前缀
            logging.info("r_hex: %s", r_hex)


            payload = {
                "g": uncompressed_g_hex,
                "pk": uncompressed_pk_hex,
                "r": r_hex,
                "k": k_hex
            }

            json_input = json.dumps(payload).encode("utf-8")
            ptr = lib_bulletproof.pyElGamalEncrypt(json_input)
            logging.info("Elgamal done!")
            result = json.loads(string_at(ptr).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr)

            logging.info("Elgamal result: %s", result)

            # 提取已是 hex 的 C1、C2 中的 X, Y
            c1_x_str, c1_y_str = result["C1"].strip("()").split(",")
            c2_x_str, c2_y_str = result["C2"].strip("()").split(",")

            # 正确：用 int(x, 16) 明确指出是 hex 编码
            c1_x_bytes = long_to_bytes(int(c1_x_str, 16), 48)
            c1_y_bytes = long_to_bytes(int(c1_y_str, 16), 48)
            c2_x_bytes = long_to_bytes(int(c2_x_str, 16), 48)
            c2_y_bytes = long_to_bytes(int(c2_y_str, 16), 48)

            c1_hex = (b'\x04' + c1_x_bytes + c1_y_bytes).hex()
            c2_hex = (b'\x04' + c2_x_bytes + c2_y_bytes).hex()

            logging.info("C1 uncompressed hex: %s", c1_hex)
            logging.info("C2 uncompressed hex: %s", c2_hex)

            # --- ElGamal 解密测试 ---
            payload_dec = {
                "C1": c1_hex,
                "C2": c2_hex,
                "sk": sk_hex
            }
            json_input_dec = json.dumps(payload_dec).encode("utf-8")
            ptr_dec = lib_bulletproof.pyElGamalDecrypt(json_input_dec)
            result_dec = json.loads(string_at(ptr_dec).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_dec)
            logging.info("Elgamal decrypted message: %s", result_dec)

            msg_x_str, msg_y_str = result_dec["message"].strip("()").split(",")
            # 转换为 int
            msg_x = int(msg_x_str, 16)
            msg_y = int(msg_y_str, 16)
            gk_x = int(k_x)
            gk_y = int(k_y)
            logging.info("msg_x: %s", msg_x)
            logging.info("msg_y: %s", msg_y)
            logging.info("gk_x: %s", gk_x)
            logging.info("gk_y: %s", gk_y)

            # 假设 proof_data 是你给出的 Claim 列表
            proof_data = [
                {
                    'H': {
                        'X': '3745266854975719612369328163075316356437546587976323074075243596723375997055156776375695072565039068643712263780519',
                        'Y': '2862635875034375207149747167738672980692528846424104937693511546815553940041994990281449645502568319374862734155723'
                    },
                    'ClaimedValue': '39717085216362713791605272371576796942938295723193556508027758597100637174017',
                    'ClaimedValueAux': '21460181816851650248690820325580627225506435345474091454335450635704000694306'
                },
                {
                    'H': {
                        'X': '2042881334636470377695355532189955737722483351743485125603949488056168426976312777142141575962003900781715177250737',
                        'Y': '2348247241808867285484989864378509317938286312402821458644613657106626740505693927128830108660399073036184801810482'
                    },
                    'ClaimedValue': '26859544678991499888612992246007769180277053423222697103657771338620412850897',
                    'ClaimedValueAux': '29570473307959804945650000145185714158272994972862092909000046856425182372653'
                }
            ]

            # 构造 W（H 点）、m、m' 序列
            W_list = []
            m_list = []
            m_prime_list = []

            for item in proof_data:
                m_list.append(hex(int(item["ClaimedValue"]))[2:])
                m_prime_list.append(hex(int(item["ClaimedValueAux"]))[2:])
            logging.info("m_list (hex): %s", m_list)
            logging.info("m_prime_list (hex): %s", m_prime_list)

            payload_W = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "m": m_list,
                "m_prime": m_prime_list
            }

            json_input_W = json.dumps(payload_W).encode("utf-8")
            ptr_W = lib_bulletproof.pyComputeCommitmentGH(json_input_W)
            result_W = json.loads(string_at(ptr_W).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_W)
            logging.info("result_W: %s", result_W)

            W_list = []
            for point in result_W:
                x_hex, y_hex = point.strip("()").split(",")
                x_bytes = long_to_bytes(int(x_hex, 16), 48)
                y_bytes = long_to_bytes(int(y_hex, 16), 48)
                W_uncompressed = b'\x04' + x_bytes + y_bytes
                W_list.append(W_uncompressed.hex())
            logging.info("W_list (uncompressed hex): %s", W_list)

            # 构造 pyProveFull 输入 payload
            payload_proof = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "pk": uncompressed_pk_hex,
                "C1": c1_hex,
                "C2": c2_hex,
                "r": r_hex,
                "r_prime": k_hex,
                "m": m_list,
                "m_prime": m_prime_list,
                "W": W_list
            }

            # 执行证明
            json_input_proof = json.dumps(payload_proof).encode("utf-8")
            ptr_proof = lib_bulletproof.pyProveFull(json_input_proof)
            result_proof = json.loads(string_at(ptr_proof).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_proof)
            logging.info("Bulletproof result is OK")
            # logging.info("Bulletproof result: %s", result_proof)

            # logging.info("Proof is hex? %s", all(c in "0123456789abcdefABCDEF" for c in result_proof))
            proof = result_proof["proof"]

            # === Bulletproof pyVerifyFull 测试 ===
            payload_verify = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "pk": uncompressed_pk_hex,
                "C1": c1_hex,
                "C2": c2_hex,
                "W": W_list,              # W_list 是 G1 uncompressed 编码 hex 字符串数组
                "proof": proof     # result_proof 是 pyProveFull 返回的 base64 编码字符串
            }

            json_input_verify = json.dumps(payload_verify).encode("utf-8")
            ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
            result_verify = json.loads(string_at(ptr_verify).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_verify)


            logging.info("Bulletproof verify result: %s", result_verify)

            # ------------------------------------------------------------------
            # Poseidon‑derived symmetric encryption / decryption round‑trip test
            # ------------------------------------------------------------------
            #
            #   • Encrypt (m_i , m'_i)  →  (c_i , c'_i)
            #   • Decrypt using  (g^k , sk)  →  (m_i , m'_i)  ––– should match
            #
            #   Inputs already in scope:
            #       uncompressed_pk_hex   – receiver public key  pk   (hex)
            #       k_hex                 – ephemeral scalar     k
            #       m_list , m_prime_list – hex scalars of secrets
            #       sk_hex                – receiver secret key  sk
            #       k_x , k_y             – coordinates of g^k  (from earlier)
            # ------------------------------------------------------------------

            # ----------------- 测试 Poseidon + Bulletproof 的对称加密解密 -----------------
            # Build uncompressed hex for g^k (needed by decrypt)
            gk_x_bytes = long_to_bytes(int(k_x), 48)
            gk_y_bytes = long_to_bytes(int(k_y), 48)
            uncompressed_gk_hex = (b"\x04" + gk_x_bytes + gk_y_bytes).hex()

            cipher_pairs = []
            for mi_hex, mpi_hex in zip(m_list, m_prime_list):
                enc_payload = {
                    "pk": uncompressed_pk_hex,
                    "k":  k_hex,
                    "m":  mi_hex,
                    "m_prime": mpi_hex
                }
                ptr_enc = lib_bulletproof.pySymEncrypt(json.dumps(enc_payload).encode("utf-8"))
                cipher = json.loads(string_at(ptr_enc).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_enc)
                cipher_pairs.append((mi_hex, mpi_hex, cipher["c"], cipher["c_prime"]))
                logging.info("SymEncrypt → (c, c') = (%s, %s)", cipher["c"], cipher["c_prime"])

            # Decrypt and check we recover the original plaintexts
            for plaintext_m, plaintext_mp, c_hex, cp_hex in cipher_pairs:
                dec_payload = {
                    "gk": uncompressed_gk_hex,
                    "sk": sk_hex,
                    "c":  c_hex,
                    "c_prime": cp_hex
                }
                ptr_dec = lib_bulletproof.pySymDecrypt(json.dumps(dec_payload).encode("utf-8"))
                dec_result = json.loads(string_at(ptr_dec).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_dec)

                # Equality check should ignore leading‑zero padding differences.
                ok_m  = (int(dec_result["m"], 16)       == int(plaintext_m, 16))
                ok_mp = (int(dec_result["m_prime"], 16) == int(plaintext_mp, 16))
                logging.info(
                    "SymDecrypt check – m ok? %s, m' ok? %s (m=%s, m'=%s)",
                    ok_m, ok_mp, dec_result["m"], dec_result["m_prime"]
                )

        if self.mode == "avss_with_pvtransfer": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )
           
            # ------------ PVTrans Lines 104-105 ------------
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")

            challenge = lib.pyDeriveChallenge(serialized_commitment)
            # logging.info("challenge: %s", challenge)

            aggproofAtZero = lib.pyAggProveEvalZero(
                    serialized_proofAtZero,
                    challenge         # γ 的十进制字符串
                )
            logging.info("aggproofAtZero: %s", aggproofAtZero)
            dser_aggproofAtZero = json.loads(aggproofAtZero.decode('utf-8'))["aggH"]
            # logging.info("dser_aggproofAtZero: %s", dser_aggproofAtZero)
            ser_aggproofAtZero = json.dumps(dser_aggproofAtZero).encode('utf-8')

            # --- aggregate each node’s proofList (H‑only) and fold with γ ---
            aggregated_proofList = []
            for i in range(self.n):
                # 取出第 i 个节点的 proof 列表并只保留 H 字段
                node_proofs = deser_comandproofwithzero["proofList"][i]
                node_H_only = [{"H": p["H"]} for p in node_proofs]

                serialized_node_H = json.dumps(node_H_only).encode("utf-8")
                agg_node = lib.pyAggProveEvalZero(
                    serialized_node_H,
                    challenge          # γ 的十进制字符串
                )
                dser_agg_node = json.loads(agg_node.decode("utf-8"))["aggH"]
                aggregated_proofList.append(
                    json.dumps(dser_agg_node).encode("utf-8")
                )

            # --------- PVTrans Lines 107-109 ------------
            # ------------------------------------------------------------------
            # Encrypt per‑node data:
            #   • fresh (r, k) scalars for this node
            #   • ElGamal encrypt g^k  →  (C1, C2)
            #   • Poseidon‑derived symmetric encrypt each (m, m′) share
            # ------------------------------------------------------------------
            # Decode the public key list (bytes → JSON list)
            public_keys_list = json.loads(self.public_keys.decode("utf-8"))
            pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            g0 = pk_dict["G1_g"][0]
            h0 = pk_dict["G1_h"][0]

            # read G1_g[0] X/Y 
            gx_dec = int(g0["X"])
            gy_dec = int(g0["Y"])

            # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            gx_bytes = long_to_bytes(gx_dec, 48)
            gy_bytes = long_to_bytes(gy_dec, 48)

            uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_g_hex = uncompressed_g.hex()

            # add h0
            hx_dec = int(h0["X"])
            hy_dec = int(h0["Y"])

            # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            hx_bytes = long_to_bytes(hx_dec, 48)
            hy_bytes = long_to_bytes(hy_dec, 48)

            uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            uncompressed_h_hex = uncompressed_h.hex()

            enc_results = []   # accumulate per‑node encryption artefacts for later use
            for node_idx, pk_entry in enumerate(public_keys_list):
                # pk_entry might already be a hex string or a dict with X/Y coords
                if isinstance(pk_entry, dict):
                    pkx = long_to_bytes(int(pk_entry["X"]), 48)
                    pky = long_to_bytes(int(pk_entry["Y"]), 48)
                    pk_hex = (b"\x04" + pkx + pky).hex()
                else:
                    pk_hex = pk_entry  # assume uncompressed hex

                # --- fresh randomness per node ---------------------------------
                r_hex = hex(random.getrandbits(256))[2:]
                k_hex = hex(random.getrandbits(256))[2:]

                # --- ElGamal: encrypt g^k under pk ------------------------------
                elg_payload = {
                    "g":  uncompressed_g_hex,  # base point prepared earlier
                    "pk": pk_hex,
                    "r":  r_hex,
                    "k":  k_hex
                }
                ptr_elg = lib_bulletproof.pyElGamalEncrypt(
                    json.dumps(elg_payload).encode("utf-8")
                )
                elg_out = json.loads(string_at(ptr_elg).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_elg)  # free C string

                C1_hex, C2_hex = elg_out["C1"], elg_out["C2"]

                # --- Poseidon symmetric encryption for each share --------------
                # Extract (m, m′) for this node from deser_comandproofwithzero["proofList"]
                node_proofs_full = deser_comandproofwithzero["proofList"][node_idx]
                m_list_node       = [hex(int(p["ClaimedValue"]))[2:]     for p in node_proofs_full]
                m_prime_list_node = [hex(int(p["ClaimedValueAux"]))[2:]  for p in node_proofs_full]

                # --- Compute W = g^m * h^{m'} for this node ---------------------
                payload_W = {
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex,
                    "m": m_list_node,
                    "m_prime": m_prime_list_node
                }
                ptr_W = lib_bulletproof.pyComputeCommitmentGH(json.dumps(payload_W).encode("utf-8"))
                result_W = json.loads(string_at(ptr_W).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_W)
                logging.info("[node %d] result_W: %s", node_idx, result_W)

                W_list_node = []
                for point in result_W:
                    x_hex, y_hex = point.strip("()").split(",")
                    x_bytes = long_to_bytes(int(x_hex, 16), 48)
                    y_bytes = long_to_bytes(int(y_hex, 16), 48)
                    W_uncompressed = b'\x04' + x_bytes + y_bytes
                    W_list_node.append(W_uncompressed.hex())

                cipher_shares = []
                for m_hex, mp_hex in zip(m_list_node, m_prime_list_node):
                    sym_payload = {
                        "pk": pk_hex,
                        "k":  k_hex,
                        "m":  m_hex,
                        "m_prime": mp_hex
                    }
                    ptr_sym = lib_bulletproof.pySymEncrypt(
                        json.dumps(sym_payload).encode("utf-8")
                    )
                    sym_out = json.loads(string_at(ptr_sym).decode("utf-8"))
                    lib_bulletproof.pyFreeString(ptr_sym)
                    cipher_shares.append((sym_out["c"], sym_out["c_prime"]))

                # --- Bulletproof full proof ------------------------------------
                payload_proof = {
                    "g":  uncompressed_g_hex,
                    "h":  uncompressed_h_hex,
                    "pk": pk_hex,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "r":  r_hex,
                    "r_prime": k_hex,
                    "m":  m_list_node,
                    "m_prime": m_prime_list_node,
                    "W":  W_list_node
                }
                ptr_proof = lib_bulletproof.pyProveFull(json.dumps(payload_proof).encode("utf-8"))
                proof_out = json.loads(string_at(ptr_proof).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_proof)
                proof_hex = proof_out["proof"]
                logging.info("[node %d] Bulletproof proof generated (len=%d hex)", node_idx, len(proof_hex))

                # Record everything for this node
                enc_results.append({
                    "node_id": node_idx,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "cipher_shares": cipher_shares,  # list of (c, c')
                    "W": W_list_node,                # list of uncompressed-hex points
                    "proof": proof_hex               # hex string
                })

            

            # enc_results is now a list you can attach to dispersal_msg_list or log

            logging.info("Per‑node encryption results prepared (len=%d)", len(enc_results))
            # ---- Bundle PV‑Transfer artefacts ---------------------------------
            #
            # We need to ship:
            #   • enc_results           – per‑node ciphertexts, W, proofs
            #   • serialized_commitment – polynomial commitment of all shares
            #   • ser_aggproofAtZero    – aggregated evaluation‑proof at 0
            #   • aggregated_proofList  – γ‑folded proofs per node
            #
            pvtransfer_payload = {
                "enc_results": enc_results,
                "commitment": (
                    serialized_commitment.decode("utf-8")
                    if isinstance(serialized_commitment, (bytes, bytearray))
                    else serialized_commitment
                ),
                "aggProofAtZero": (
                    ser_aggproofAtZero.decode("utf-8")
                    if isinstance(ser_aggproofAtZero, (bytes, bytearray))
                    else ser_aggproofAtZero
                ),
                "aggregated_proofList": [
                    p.decode("utf-8") if isinstance(p, (bytes, bytearray)) else p
                    for p in aggregated_proofList
                ],
            }
            # Store for later use when building dispersal messages
            self.pvtransfer_payload = pvtransfer_payload
            logging.info("PV‑Transfer payload assembled")
            
            # --- Convert dict → dataclass, serialize for RBC / TOB ---
            pv_obj = PVTransferPayload(
                enc_results=[EncResult(**er) for er in enc_results],
                commitment=pvtransfer_payload["commitment"],
                agg_proof_at_zero=pvtransfer_payload["aggProofAtZero"],
                aggregated_proof_list=pvtransfer_payload["aggregated_proofList"],
            )
            # 保存二进制版本，供后续 ΠGather / ΠSelectBlock / TOB 使用
            self.pvtransfer_bytes = pv_obj.to_bytes()
            logging.info(
                "PV-Transfer payload serialised (len=%d bytes)",
                len(self.pvtransfer_bytes),
            )

            # await self._run_local_gather(node_communicator)
            
        if self.mode == "avss_with_batch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            # logger.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed comandproof_right_inputs: {comandproof_right_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed deser_result: {deser_result}")
            # logger.info(f"[dealer {self.my_id}] parsed proof: {proof}")

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'], serialized_secrets,
                serialized_secrets_aux, self.t
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")
            
            # logging.info("serialized_proofAtZero: %s", serialized_proofAtZero)
            # logging.info("serialized_output_shareG: %s", serialized_output_shareG)
            # logging.info("serialized_output_shareH: %s", serialized_output_shareH)

            ab_shareGH = lib.pyComputeShareGH(
                self.srs_kzg['Pk'],
                serialized_left_proof,
                serialized_right_proof
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # logger.info("deser_ab_shareGH: %s", deser_ab_shareGH)
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            # logger.info("serialized_left_shareG: %s", serialized_left_shareG)
            # logger.info("serialized_left_shareH: %s", serialized_left_shareH)
            # logger.info("serialized_right_shareG: %s", serialized_right_shareG)
            # logger.info("serialized_right_shareH: %s", serialized_right_shareH)

        if self.mode == "avss_with_aggbatch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])
            proof_metric = proof_metadata(
                getattr(self, "mpc_instance", None), protocol="batchmul",
                operation="ipakzg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=len(comandproof_left_inputs.get("proof", [])),
            )

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            # logging.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")

            comandproofwithzero = timed_call(
                getattr(self, "mpc_instance", None), proof_metric,
                "output_commitment_preparation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")

            ab_shareGH = timed_call(
                getattr(self, "mpc_instance", None), proof_metric,
                "anchor_share_preparation", lib.pyComputeShareGH,
                self.srs_kzg['Pk'], serialized_left_proof,
                serialized_right_proof,
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            def _prepare_pedersen_commitments():
                return (
                    lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH),
                    lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH),
                    lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH),
                )

            ser_pedersen_left, ser_pedersen_right, ser_pedersen_output = timed_call(
                getattr(self, "mpc_instance", None), proof_metric,
                "pedersen_commitment_preparation", _prepare_pedersen_commitments,
            )
            (
                ser_aggleftproof,
                ser_aggrightproof,
                ser_aggproofAtZero,
            ) = _generate_ipakzg_aggregate_witnesses(
                mpc_instance=getattr(self, "mpc_instance", None),
                proof_metric=proof_metric,
                dealer_local_id=self.my_id,
                srs_pk=self.srs_kzg["Pk"],
                srs_vk=self.srs_kzg["Vk"],
                left_commitments=serialized_left_commitment,
                right_commitments=serialized_right_commitment,
                output_commitments=serialized_commitment,
                left_pedersen=ser_pedersen_left,
                right_pedersen=ser_pedersen_right,
                output_pedersen=ser_pedersen_output,
                left_openings=comandproof_left_inputs["proof"],
                right_openings=comandproof_right_inputs["proof"],
                output_openings=deser_comandproofwithzero["proofAtZero"],
            )
            finalize_operation(
                getattr(self, "mpc_instance", None), proof_metric,
                BATCHMUL_GENERATE_COMPONENTS, success=True,
            )

        
        serialized_ephemeralpublicsecretkey = lib.pyKeyEphemeralGen(self.srs_kzg['Pk'], self.public_keys)
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')

        dispersal_msg_list = [None] * n
        shared_keys = [None] * n
        serialized_publickeys = json.loads(self.public_keys.decode('utf-8'))
        for i in range(n):
            shared_keys[i] = lib.pySharedKeysGen_sender(json.dumps(serialized_publickeys[i]).encode('utf-8'), serialized_ephemeralsecretkey)
            if self.mode == "avss_without_proof":
                z = proofandshares[i]
            if self.mode == "avss_with_proof":
                z = (proofandshares[i], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs)
            if self.mode == "avss_with_transfer":
                z = proofandshares[i]
            if self.mode == "avss_with_aggtransfer":
                z = proofandshares[i]
            if self.mode == "avss_with_batch_multiplication":
                z = (
                    proofandshares[i],
                    serialized_left_commitment,
                    serialized_left_proof, 
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof, 
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof                   
                )
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                z = proofandshares[i]
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), z)


        logging.info("before return dumps")
        broadcast_msg = _build_hbacss_broadcast_payload(
            self, serialized_commitment, serialized_ephemeralpublickey,
            locals(),
        )
        _record_hbacss_payload_calibration(
            self, broadcast_msg, dispersal_msg_list, locals()
        )
        return broadcast_msg, dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, dealer_id, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        
        (
            serialized_commitment,
            serialized_ephemeral_public_key,
            transfer_public_payload,
        ) = _parse_hbacss_broadcast_payload(self, rbc_msg)
        
        serialized_private_key = json.loads(json.loads(self.private_key.decode('utf-8')))

        serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeral_public_key, json.dumps(serialized_private_key[f'{dealer_id}']).encode('utf-8'))
        # self.tagvars[tag]['shared_key'] = serialized_sharedkey
        # self.tagvars[tag]['ephemeral_public_key'] = serialized_ephemeral_public_key
        try:
            if self.mode == "avss_without_proof":
                serialized_proofandshares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_proof":
                serialized_proofandshares, serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_transfer":
                noagg_payload = combine_aggtrans_noagg_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = noagg_payload.proof_and_shares
                serialized_original_commitment = noagg_payload.old_commitments
            if self.mode == "avss_with_aggtransfer":
                aggtrans_payload = combine_aggtrans_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = aggtrans_payload.proof_and_shares
                serialized_original_commitment = aggtrans_payload.old_commitments
            if self.mode == "avss_with_batch_multiplication":
                (
                    serialized_proofandshares,
                    serialized_left_commitment,
                    serialized_left_proof,
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof,
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof
                ) = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                batchmul_payload = combine_batchmul_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = batchmul_payload.proof_and_shares
                serialized_left_commitment = batchmul_payload.left_commitments
                serialized_right_commitment = batchmul_payload.right_commitments
                ser_aggleftproof = batchmul_payload.left_witness
                ser_aggrightproof = batchmul_payload.right_witness
                ser_aggproofAtZero = batchmul_payload.output_witness
                ser_pedersen_left = batchmul_payload.left_pedersen
                ser_pedersen_right = batchmul_payload.right_pedersen
                ser_pedersen_output = batchmul_payload.output_pedersen
                proof = batchmul_payload.factor_proof

                # # --- reconstruct two public proof‑and‑share lists ---
                # # 1) evaluation at x = i      (original proof)
                # # 2) evaluation at x = 0      (proofAtZero)
                # #
                # # Each element becomes {"H": ..., "G": shareG[i], "HClaim": shareH[i]}
                # #
                # deser_orig_proof = json.loads(serialized_original_proof.decode("utf-8"))
                # deser_P0         = json.loads(serialized_proofAtZero.decode("utf-8"))
                # deser_G          = json.loads(serialized_shareG.decode("utf-8"))
                # deser_H          = json.loads(serialized_shareH.decode("utf-8"))

                # # helper to fuse H, G, Ĥ
                # def _fuse(H_arr, G_arr, Hhat_arr):
                #     fused = []
                #     for idx in range(len(H_arr)):
                #         fused.append({
                #             "H": H_arr[idx]["H"],
                #             "GClaim": G_arr[idx],
                #             "HClaim": Hhat_arr[idx]
                #         })
                #     return fused

                # fused_proof_and_shares      = _fuse(deser_orig_proof, deser_G, deser_H)
                # fused_proofanzero_andshares = _fuse(deser_P0, deser_G, deser_H)

                # logging.info("fused_proof_and_shares: %s", fused_proof_and_shares)
                # logging.info("fused_proofanzero_andshares: %s", fused_proofanzero_andshares)

                # serialized_proofandshares_pub      = json.dumps(fused_proof_and_shares).encode("utf-8")
                # serialized_proofandshares_zero_pub = json.dumps(fused_proofanzero_andshares).encode("utf-8")
                
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
         
         
        if all_shares_valid:
            if self.mode == "avss_without_proof":
                if lib.pyBatchVerify(self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    all_shares_valid = False
            if self.mode == "avss_with_proof":
                mpc_instance = getattr(self, "mpc_instance", None)
                bgw_layer = int(getattr(mpc_instance, "layer_ID", -1))
                bgw_batch_size = len(json.loads(serialized_commitment.decode("utf-8")))
                bgw_verification_metric = proof_metadata(
                    mpc_instance,
                    protocol="bgw",
                    operation="bgw_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=bgw_batch_size,
                    normalization_count=bgw_batch_size,
                    unit="gate",
                    source_layer=bgw_layer,
                    target_layer=bgw_layer,
                )
                verification_success = lambda result: result == int(1)
                if os.getenv("BGW_UNBATCHED_VERIFY") == "1":
                    verify_total_start = time.time()
                    verify_context = f"my_id={self.my_id}, dealer_id={dealer_id}"
                    batch_share_verify = _bgw_use_batch_verify("share")
                    batch_hidden_verify = _bgw_use_batch_verify("hidden")
                    batch_zero_verify = _bgw_use_batch_verify("zero")
                    batch_prod_verify = _bgw_use_batch_verify("prod")
                    if batch_share_verify:
                        shares_ok = _timed_bgw_mixed_batch_call(
                            "share",
                            "pyBatchVerify",
                            lib.pyBatchVerify,
                            (
                                self.srs_kzg['Vk'],
                                serialized_commitment,
                                serialized_proofandshares,
                                self.my_id,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="share_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    else:
                        shares_ok = _timed_bgw_unbatched_call(
                            "pyBatchVerifyUnbatched",
                            lib.pyBatchVerifyUnbatched,
                            (
                                self.srs_kzg['Vk'],
                                serialized_commitment,
                                serialized_proofandshares,
                                self.my_id,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="share_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    if batch_hidden_verify:
                        hidden_ok = _timed_bgw_mixed_batch_call(
                            "hidden",
                            "pyBatchhiddenverify",
                            lib.pyBatchhiddenverify,
                            (
                                self.srs_kzg['Vk'],
                                self.tagvars[tag]['committment_ab'],
                                serialized_zkProof_ab,
                                dealer_id,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="hidden_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    else:
                        hidden_ok = _timed_bgw_unbatched_call(
                            "pyBatchhiddenverifyUnbatched",
                            lib.pyBatchhiddenverifyUnbatched,
                            (
                                self.srs_kzg['Vk'],
                                self.tagvars[tag]['committment_ab'],
                                serialized_zkProof_ab,
                                dealer_id,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="hidden_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    if batch_zero_verify:
                        zero_ok = _timed_bgw_mixed_batch_call(
                            "zero",
                            "pyBatchhiddenzeroverify",
                            lib.pyBatchhiddenzeroverify,
                            (
                                self.srs_kzg['Vk'],
                                serialized_commitment,
                                serialized_zkProof_c_zero,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="zero_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    else:
                        zero_ok = _timed_bgw_unbatched_call(
                            "pyBatchhiddenzeroverifyUnbatched",
                            lib.pyBatchhiddenzeroverifyUnbatched,
                            (
                                self.srs_kzg['Vk'],
                                serialized_commitment,
                                serialized_zkProof_c_zero,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="zero_evaluation_verify",
                            success=verification_success,
                        ) == int(1)
                    if batch_prod_verify:
                        prod_ok = _timed_bgw_mixed_batch_call(
                            "prod",
                            "pyProdverify",
                            lib.pyProdverify,
                            (
                                self.srs_kzg['Vk'],
                                serialized_zkProof_ab,
                                serialized_zkProof_c_zero,
                                serialized_prodProofs,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="product_relation_verify",
                            success=verification_success,
                        ) == int(1)
                    else:
                        prod_ok = _timed_bgw_unbatched_call(
                            "pyProdverifyUnbatched",
                            lib.pyProdverifyUnbatched,
                            (
                                self.srs_kzg['Vk'],
                                serialized_zkProof_ab,
                                serialized_zkProof_c_zero,
                                serialized_prodProofs,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="product_relation_verify",
                            success=verification_success,
                        ) == int(1)
                    logger.info(
                        "bgw_unbatched_verify_total_time: elapsed=%s, my_id=%s, dealer_id=%s, batch_share_verify=%s, batch_hidden_verify=%s, batch_zero_verify=%s, batch_prod_verify=%s, shares_ok=%s, hidden_ok=%s, zero_ok=%s, prod_ok=%s",
                        time.time() - verify_total_start,
                        self.my_id,
                        dealer_id,
                        batch_share_verify,
                        batch_hidden_verify,
                        batch_zero_verify,
                        batch_prod_verify,
                        shares_ok,
                        hidden_ok,
                        zero_ok,
                        prod_ok,
                    )
                else:
                    verify_total_start = time.time()
                    verify_context = f"my_id={self.my_id}, dealer_id={dealer_id}"
                    shares_ok = timed_call(
                        mpc_instance,
                        bgw_verification_metric,
                        "share_evaluation_verify",
                        lib.pyBatchVerify,
                        self.srs_kzg['Vk'],
                        serialized_commitment,
                        serialized_proofandshares,
                        self.my_id,
                        success=verification_success,
                    ) == int(1)
                    hidden_ok = timed_call(
                        mpc_instance,
                        bgw_verification_metric,
                        "hidden_evaluation_verify",
                        lib.pyBatchhiddenverify,
                        self.srs_kzg['Vk'],
                        self.tagvars[tag]['committment_ab'],
                        serialized_zkProof_ab,
                        dealer_id,
                        success=verification_success,
                    ) == int(1)
                    zero_ok = timed_call(
                        mpc_instance,
                        bgw_verification_metric,
                        "zero_evaluation_verify",
                        lib.pyBatchhiddenzeroverify,
                        self.srs_kzg['Vk'],
                        serialized_commitment,
                        serialized_zkProof_c_zero,
                        success=verification_success,
                    ) == int(1)
                    if os.getenv("BGW_BATCH_UNBATCHED_PROD_VERIFY") == "1":
                        prod_ok = _timed_bgw_batch_unbatched_call(
                            "prod",
                            "pyProdverifyUnbatched",
                            lib.pyProdverifyUnbatched,
                            (
                                self.srs_kzg['Vk'],
                                serialized_zkProof_ab,
                                serialized_zkProof_c_zero,
                                serialized_prodProofs,
                            ),
                            verify_context,
                            mpc_instance=mpc_instance,
                            proof_metric=bgw_verification_metric,
                            metric_component="product_relation_verify",
                            success=verification_success,
                        ) == int(1)
                    else:
                        prod_ok = timed_call(
                            mpc_instance,
                            bgw_verification_metric,
                            "product_relation_verify",
                            lib.pyProdverify,
                            self.srs_kzg['Vk'],
                            serialized_zkProof_ab,
                            serialized_zkProof_c_zero,
                            serialized_prodProofs,
                            success=verification_success,
                        ) == int(1)
                    logger.info(
                        "bgw_batch_verify_total_time: elapsed=%s, my_id=%s, dealer_id=%s, unbatched_prod_verify=%s, shares_ok=%s, hidden_ok=%s, zero_ok=%s, prod_ok=%s",
                        time.time() - verify_total_start,
                        self.my_id,
                        dealer_id,
                        os.getenv("BGW_BATCH_UNBATCHED_PROD_VERIFY") == "1",
                        shares_ok,
                        hidden_ok,
                        zero_ok,
                        prod_ok,
                    )
                bgw_verification_ok = (
                    shares_ok and hidden_ok and zero_ok and prod_ok
                )
                finalize_operation(
                    mpc_instance,
                    bgw_verification_metric,
                    BGW_VERIFY_COMPONENTS,
                    success=bgw_verification_ok,
                )
                if bgw_verification_ok:
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    return False
            if self.mode == "avss_with_transfer":
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans-noagg",
                    operation="batch_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_original_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, proof_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                old_anchor_valid, fresh_zero_valid = (
                    _verify_aggtrans_noagg_relations(
                        mpc_instance=mpc_instance,
                        proof_metric=proof_metric,
                        dealer_local_id=dealer_id,
                        srs_vk=self.srs_kzg['Vk'],
                        old_commitments=serialized_original_commitment,
                        fresh_commitments=serialized_commitment,
                        old_witnesses=noagg_payload.old_witnesses,
                        fresh_witnesses=noagg_payload.fresh_witnesses,
                        pedersen=noagg_payload.pedersen,
                    )
                )
                finalize_operation(
                    mpc_instance, proof_metric,
                    AGGTRANS_NOAGG_VERIFY_COMPONENTS,
                    success=(
                        bacss_share_valid
                        and old_anchor_valid
                        and fresh_zero_valid
                    ),
                )
                if bacss_share_valid and old_anchor_valid and fresh_zero_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_aggtransfer":
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans",
                    operation="aggtrans_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    AGGTRANS_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                aggtrans_verification = verify_aggtrans(
                    self.agg_kzg_mode, library=lib,
                    srs_pk=self.srs_kzg['Pk'], srs_vk=self.srs_kzg['Vk'],
                    dealer_local_id=dealer_id, receiver_local_id=self.my_id,
                    fresh_commitments=serialized_commitment,
                    payload=aggtrans_payload,
                )
                fresh_zero_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.fresh_zero_valid
                )
                old_anchor_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.old_anchor_valid
                )

                mpc_instance = getattr(self, "mpc_instance", None)
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_aggtrans_verification(
                        dealer_local_id=dealer_id,
                        bacss_share_valid=bacss_share_valid,
                        fresh_zero_valid=fresh_zero_valid,
                        old_anchor_valid=old_anchor_valid,
                    )

                if bacss_share_valid and fresh_zero_valid and old_anchor_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left_list = json.loads(ser_pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(ser_pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(ser_pedersen_output.decode("utf-8"))
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="ipakzg_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                def _verify_factor_proof():
                    result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                    try:
                        result_json = string_at(result_ptr).decode("utf-8")
                        logger.info("verifier_result_json: %s", result_json)
                        return bool(json.loads(result_json).get("verified", False))
                    finally:
                        lib_bulletproof.pyFreeString(result_ptr)

                product_proof_valid = timed_call(
                    mpc_instance, proof_metric, "factor_verify",
                    _verify_factor_proof, success=bool,
                )
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="batchmul_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    BATCHMUL_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                (
                    left_anchor_valid,
                    right_anchor_valid,
                    output_zero_valid,
                ) = _verify_ipakzg_aggregate_relations(
                    mpc_instance=mpc_instance,
                    proof_metric=proof_metric,
                    dealer_local_id=dealer_id,
                    srs_pk=self.srs_kzg["Pk"],
                    srs_vk=self.srs_kzg["Vk"],
                    left_commitments=serialized_left_commitment,
                    right_commitments=serialized_right_commitment,
                    output_commitments=serialized_commitment,
                    left_pedersen=ser_pedersen_left,
                    right_pedersen=ser_pedersen_right,
                    output_pedersen=ser_pedersen_output,
                    left_witness=ser_aggleftproof,
                    right_witness=ser_aggrightproof,
                    output_witness=ser_aggproofAtZero,
                )
                proof_valid = (
                    product_proof_valid and left_anchor_valid
                    and right_anchor_valid and output_zero_valid
                )
                finalize_operation(
                    mpc_instance, proof_metric, BATCHMUL_VERIFY_COMPONENTS,
                    success=proof_valid,
                )
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_batchmul_verification(
                        dealer_local_id=dealer_id,
                        product_proof_valid=product_proof_valid,
                        bacss_share_valid=bacss_share_valid,
                        left_anchor_valid=left_anchor_valid,
                        right_anchor_valid=right_anchor_valid,
                        output_zero_valid=output_zero_valid,
                    )
                if proof_valid and bacss_share_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                    self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_batch_multiplication":
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left = lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH)
                pedersen_right = lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH)
                pedersen_out = lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH)

                # logger.info("pedersen_left: %s", pedersen_left)
                # logger.info("pedersen_right: %s", pedersen_right)
                # logger.info("pedersen_out: %s", pedersen_out)

                pedersen_left_list = json.loads(pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(pedersen_out.decode("utf-8"))

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                verifier_result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                verifier_result_json = string_at(verifier_result_ptr).decode("utf-8")

                logger.info("verifier_result_json: %s", verifier_result_json)
                lib_bulletproof.pyFreeString(verifier_result_ptr)

                # Add check for verification result
                if json.loads(verifier_result_json).get("verified", False):
                    logging.info("inner product verified successfully")
                    if lib.pyBatchVerify(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                        ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_left_commitment, serialized_left_proof, serialized_left_shareG, serialized_left_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_right_commitment, serialized_right_proof, serialized_right_shareG, serialized_right_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofAtZero, serialized_output_shareG, serialized_output_shareH, -1
                    ) == int(1):
                        logging.info("shares verified successfully")
                        mpc_instance = getattr(self, "mpc_instance", None)
                        fault_controller = getattr(
                            mpc_instance, "fault_controller", None
                        )
                        if fault_controller is not None:
                            fault_controller.record_batchmul_verification(
                                dealer_local_id=dealer_id,
                                product_proof_valid=True,
                                bacss_share_valid=True,
                                left_anchor_valid=True,
                                right_anchor_valid=True,
                                output_zero_valid=True,
                            )
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                        self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                        self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                    else:
                        logging.info("shares verification FAILED")
                        return False
                else:
                    logging.info("inner product verification FAILED")
                    return False
    
        return all_shares_valid

    #@profile
    async def avss(self, avss_id, coms=None, values=None, dealer_id=None, client_mode=False):
        
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )
        
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"
        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []
        if self.mode == "avss_with_proof":
            self.tagvars[acsstag]['committment_ab'] = coms
            

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(acsstag, values, n)

            
        
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        logging.info("before reliablebroadcast")
        rbc_msg = await reliablebroadcast(
            rbctag,
            self.my_id,
            n,
            self.t,
            dealer_id,
            broadcast_msg,
            recv,
            send,
            client_mode=client_mode,
        )  # (# noqa: E501)
        logging.info("after reliablebroadcast")
        avidtag = f"{dealer_id}-{avss_id}-B-AVID"
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        
        send, recv = self.get_send(avidtag), self.subscribe_recv(avidtag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(n, self.t, dealer_id, recv, send, n)
        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid, avidtag, dispersal_msg_list))
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)   

class ACSS_Pre(Hbacss0):
    #@profile
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, msgmode, mpc_instance):  
        
        self.mpc_instance = mpc_instance
        logging.info("public_keys: %s", public_keys)
        serialized_pk_bytes = json.dumps(public_keys).encode('utf-8')
        
        super().__init__(serialized_pk_bytes, private_key, crs, n, t, my_id, send, recv, msgmode)

    async def _recv_loop(self, q):           
        avid_dyn, tag, dispersal_msg_list = await q.get()
        logging.info("[%d] Starting AVID disperse", self.my_id)
        asyncio.create_task(avid_dyn.disperse(tag, self.my_id, dispersal_msg_list))
        # await avid_dyn.disperse(tag, self.my_id, dispersal_msg_list)
        
    def __enter__(self):
        # self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
                
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # TODO: Add the handle implication
        pass
        # commitments =  self.tagvars[tag]['commitments']
        # # discard if PKj ! = g^SKj
        # if self.public_keys[j] != pow(self.g, j_sk):
        #     return False
        # # decrypt and verify
        # implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        # j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # # Same as the batch size
        # secret_count = len(commitments)

        # try:
        #     j_shares, j_auxes, j_witnesses = SymmetricCrypto.decrypt(
        #         str(j_shared_key).encode(), implicate_msg
        #     )
        # except Exception as e:  # TODO specific exception
        #     logger.warn("Implicate confirmed, bad encryption:", e)
        #     return True
        # return not self.poly_commit.batch_verify_eval(
        #     commitments, j + 1, j_shares, j_auxes, j_witnesses
        # )



    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
        #     logger.debug("[%d] sent_kdi_broadcast", self.my_id)
        #     kdi = self.tagvars[tag]['shared_key']
        #     multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
        #     self.kdi_broadcast_sent = True
        # if self.tagvars[tag]['all_shares_valid']:
        #     return

        # if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
        #     logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
        #     avid = self.tagvars[tag]['avid']
        #     retrieved_msg = await avid.retrieve(tag, sender)
        #     try:
        #         j_shares, j_witnesses = SymmetricCrypto.decrypt(
        #             str(avss_msg[1]).encode(), retrieved_msg
        #         )
        #     except Exception as e:  # TODO: Add specific exception
        #         logger.debug("Implicate confirmed, bad encryption:", e)
        #     commitments = self.tagvars[tag]['commitments']
        #     if (self.poly_commit.batch_verify_eval(commitments,
        #                                            sender + 1, j_shares, j_witnesses)):
        #         if not self.saved_shares[sender]:
        #             self.saved_shared_actual_length += 1
        #             self.saved_shares[sender] = j_shares

        # # if t+1 in the saved_set, interpolate and sell all OK
        # if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
        #     logger.debug("[%d] interpolating", self.my_id)
        #     # Batch size
        #     shares = []
        #     secret_count = len(self.tagvars[tag]['commitments'])
        #     for i in range(secret_count):
        #         phi_coords = [
        #             (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
        #         ]
        #         shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
        #     self.tagvars[tag]['all_shares_valid'] = True
        #     self.tagvars[tag]['shares'] = shares
        #     self.tagvars[tag]['in_share_recovery'] = False
        #     self.interpolated = True
        #     multicast((HbAVSSMessageType.OK, ""))
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        # self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        # self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable broadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(dealer_id, tag, dispersal_msg, rbc_msg)
        
        if self.tagvars[tag]['all_shares_valid']:
            if self.mode == "avss_without_proof":
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_proof":
                logging.debug(f"dealer_id: {dealer_id}")
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_transfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggtransfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggbatch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            if self.mode == "avss_with_batch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            output = True
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

        # obtain
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()
            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    # ------------------------------------------------------------------
    #  Helper: run local ΠGather + ΠSelectBlock
    # ------------------------------------------------------------------
    async def _run_local_gather(self, node_communicator):
        """
        把 self.pvtransfer_bytes 当作 B_i，启动 YosoGather，
        等它跑完 Strongly-Stable 选块协议。
        """
        from beaver.gather import YosoGather   # 延迟 import 避免循环

        g = YosoGather(
            self.public_keys, self.private_key,
            self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            self.pvtransfer_bytes          # ★ B_i
        )
        task = asyncio.create_task(g.run_gather(node_communicator))
        await task         # ← 在协程内合法使用 await
        g.kill()

        logging.info(
            "[%d] ΠGather done – |U₃|=%d, g=%s, |C|=%d",
            self.my_id,
            len(getattr(g, "U", {})),
            getattr(g, "g", "NA"),
            len(getattr(g, "final_block", b"")),
        )

    #@profile
    def _get_dealer_msg(self, acsstag, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        proofandshares = []
        # logging.info("values: %s", values)
        # serialized_values = json.dumps(values).encode('utf-8')
        # logging.info("serialized_values: %s", serialized_values)
        if self.mode == "avss_without_proof":
            commitmentlistandprooflist = lib.pyCommit(self.srs_kzg['Pk'], values, self.t)

            deserialized_commitmentlistandprooflist = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deserialized_commitmentlistandprooflist['commitmentList']).encode('utf-8')       
            for i in range(self.n):
                proofandshares.append(json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8'))

            # logging.info("avss_without_proof proofandshares: %s", proofandshares)
        if self.mode == "avss_with_proof":
            deserialized_commandprooflist = json.loads(values.decode('utf-8'))            
            serialized_commitmentlist = json.dumps(deserialized_commandprooflist['commitment']).encode('utf-8')
            serialized_prooflist = json.dumps(deserialized_commandprooflist['proof']).encode('utf-8')
            commitmentlistandprooflist = lib.pyParseRandom(self.srs_kzg['Pk'], serialized_commitmentlist, serialized_prooflist, self.t, self.my_id)

            deser_comsandproofs = json.loads(commitmentlistandprooflist.decode('utf-8'))
            # logging.info("deser_comsandproofs: %s", deser_comsandproofs)
            serialized_commitment = json.dumps(deser_comsandproofs['commitments_c']).encode('utf-8') 
            serialized_zkProof_ab = json.dumps(deser_comsandproofs['zkProof_ab']).encode('utf-8') 
            serialized_zkProof_c_zero = json.dumps(deser_comsandproofs['zkProof_c_zero']).encode('utf-8') 
            serialized_prodProofs = json.dumps(deser_comsandproofs['prodProofs']).encode('utf-8') 
            logger.info(f"prodProofs size: {len(serialized_prodProofs)} bytes")
            logger.info(f"prodProofs count: {len(deser_comsandproofs['prodProofs'])}")
            
            for i in range(self.n):
                proofandshares.append(json.dumps(deser_comsandproofs['proofs_c'][i]).encode('utf-8'))   
            # logging.info("proofandshares: %s", proofandshares)

        if self.mode == "avss_with_transfer": 
            # `values` carries the serialized `com_and_proof_obj` produced in
            # setup_transfer.log.  Extract ClaimedValue / ClaimedValueAux,
            # build the two secret vectors, and obtain commitments & proofs
            # that also include f(0) related data via pyCommitWithZeroFull.
            # -------------------------------------------------------------
            # robust JSON decode (handle both normal JSON and python‐repr)
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("secrets: %s", secrets)
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            mpc_instance = getattr(self, "mpc_instance", None)
            noagg_generation_metric = proof_metadata(
                mpc_instance, protocol="aggtrans-noagg",
                operation="noagg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None, batch_size=len(proofs_lst),
            )
            comandproofwithzero = timed_call(
                mpc_instance, noagg_generation_metric,
                "commitment_opening_generation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)
            # logging.info("serialized_commitment: %s", serialized_commitment)


            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            # logging.info("proof_at_zero_Honly: %s", proof_at_zero_Honly)

            noagg_artifacts = prepare_aggtrans_noagg(
                library=lib,
                old_commitments=original_commitment,
                fresh_commitments=deser_comandproofwithzero["commitmentList"],
                old_witnesses=original_proof_no_val,
                fresh_witnesses=proof_at_zero_Honly,
                share_g=deser_comandproofwithzero.get("shareG", []),
                share_h=deser_comandproofwithzero.get("shareH", []),
                pedersen_combine=lambda share_g, share_h: timed_call(
                    mpc_instance, noagg_generation_metric,
                    "pedersen_commitment_preparation",
                    lib.pyPedersenCombine, share_g, share_h,
                ),
            )
            finalize_operation(
                mpc_instance, noagg_generation_metric,
                AGGTRANS_NOAGG_GENERATE_COMPONENTS, success=True,
            )

        if self.mode == "avss_with_aggtransfer": 
            logging.info("enter avss_with_aggtransfer")
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]
            proof_metric = proof_metadata(
                self.mpc_instance,
                protocol="aggtrans",
                operation="aggpub_generate",
                dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=len(proofs_lst),
            )

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            bacss_metric = proof_metadata(
                self.mpc_instance,
                protocol="aggtrans",
                operation="aggtrans_bacss_generate",
                dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=len(proofs_lst),
            )
            comandproofwithzero = timed_call(
                self.mpc_instance, bacss_metric,
                "commitment_opening_generation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )
            finalize_operation(
                self.mpc_instance, bacss_metric,
                AGGTRANS_BACSS_GENERATE_COMPONENTS, success=True,
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            fresh_openings = deser_comandproofwithzero.get("proofAtZero", [])
            aggtrans_v2 = None
            aggtrans_legacy = None
            if self.agg_kzg_mode in {"v2", "shadow"}:
                aggtrans_v2 = timed_call(
                    self.mpc_instance, proof_metric, "aggpub_prove",
                    lambda: prove_aggtrans_v2(
                        library=lib, srs_pk=self.srs_kzg['Pk'],
                        srs_vk=self.srs_kzg['Vk'],
                        dealer_local_id=self.my_id,
                        old_commitments=original_commitment,
                        fresh_commitments=deser_comandproofwithzero["commitmentList"],
                        old_openings=proofs_lst,
                        fresh_openings=fresh_openings,
                    ),
                )
            if self.agg_kzg_mode in {"legacy", "shadow"}:
                aggtrans_legacy = timed_call(
                    self.mpc_instance, proof_metric, "legacy_aggpub_prove",
                    lambda: prove_aggtrans_legacy(
                        library=lib,
                        fresh_commitments=deser_comandproofwithzero["commitmentList"],
                        old_openings=proofs_lst,
                        fresh_openings=fresh_openings,
                        share_g=deser_comandproofwithzero.get("shareG", []),
                        share_h=deser_comandproofwithzero.get("shareH", []),
                    ),
                )

            proof_metric.update(aggtrans_proof_size_metadata(
                self.agg_kzg_mode, v2=aggtrans_v2, legacy=aggtrans_legacy,
            ))

            finalize_operation(
                self.mpc_instance, proof_metric,
                aggtrans_generate_components(self.agg_kzg_mode), success=True,
            )

            # logging.info("self.public_keys: %s", self.public_keys)
            # logging.info("self.private_key: %s", self.private_key)          


            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggproofAtZero).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     0                 # C.int
            # )
            # logging.info("x=0 pyPubAggVerifyEval result: %s", ok)

            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_original_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggoriginalproof).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     self.my_id + 1                 # C.int
            # )
            # logging.info("x=my.id pyPubAggVerifyEval result: %s", ok)

            # # --------------------- 从这行开始，后续的代码都是用来测试 Poseidon + Bulletproof 的 --------------------

            # pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            # g0 = pk_dict["G1_g"][0]
            # h0 = pk_dict["G1_h"][0]

            # # read G1_g[0] X/Y 
            # gx_dec = int(g0["X"])
            # gy_dec = int(g0["Y"])

            # # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            # gx_bytes = long_to_bytes(gx_dec, 48)
            # gy_bytes = long_to_bytes(gy_dec, 48)

            # uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            # uncompressed_g_hex = uncompressed_g.hex()
            # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

            # # add h0
            # hx_dec = int(h0["X"])
            # hy_dec = int(h0["Y"])

            # # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            # hx_bytes = long_to_bytes(hx_dec, 48)
            # hy_bytes = long_to_bytes(hy_dec, 48)

            # uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            # uncompressed_h_hex = uncompressed_h.hex()
            # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
            
            # sk = "43066057178372115162090031665738480497785504495963485110743715314730498099898"
            # sk_hex = hex(int(sk))[2:]  # 去掉 0x 前缀
            # pk_x = "2540810243697281646753816249646546839680056672316758359369207562792691238809422685043919463202492103317975796630457"
            # pk_y = "50066053523316668810016801456660224022045904723296188340443488016713934584332814528641622484569632142481660547518"
            # pkx_bytes = long_to_bytes(int(pk_x), 48)
            # pky_bytes = long_to_bytes(int(pk_y), 48)

            # uncompressed_pk = b'\x04' + pkx_bytes + pky_bytes  # 0x04 + X || Y (uncompressed form)
            # uncompressed_pk_hex = uncompressed_pk.hex()
            # logging.info("uncompressed_pk.hex(): %s", uncompressed_pk.hex())

            # k = "6706283196960114501037797896778429581316608798606687574701835551207274422636"
            # k_hex = hex(int(k))[2:]  # 去掉 0x 前缀
            # k_x = "1414576985840271823358185120885954780171082639683846674231723237543180390154178096938117414806051004278910490643080"
            # k_y = "2646059067981507357143657154501587172603295817551133156830318975462005332733650918056918384628991898173670748015537"

            # r = "1757101419104903848312328479324811944822009314342771061452727681968477199489"
            # r_hex = hex(int(r))[2:]  # 去掉 0x 前缀
            # logging.info("r_hex: %s", r_hex)


            # payload = {
            #     "g": uncompressed_g_hex,
            #     "pk": uncompressed_pk_hex,
            #     "r": r_hex,
            #     "k": k_hex
            # }

            # json_input = json.dumps(payload).encode("utf-8")
            # ptr = lib_bulletproof.pyElGamalEncrypt(json_input)
            # logging.info("Elgamal done!")
            # result = json.loads(string_at(ptr).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr)

            # logging.info("Elgamal result: %s", result)

            # # 提取已是 hex 的 C1、C2 中的 X, Y
            # c1_x_str, c1_y_str = result["C1"].strip("()").split(",")
            # c2_x_str, c2_y_str = result["C2"].strip("()").split(",")

            # # 正确：用 int(x, 16) 明确指出是 hex 编码
            # c1_x_bytes = long_to_bytes(int(c1_x_str, 16), 48)
            # c1_y_bytes = long_to_bytes(int(c1_y_str, 16), 48)
            # c2_x_bytes = long_to_bytes(int(c2_x_str, 16), 48)
            # c2_y_bytes = long_to_bytes(int(c2_y_str, 16), 48)

            # c1_hex = (b'\x04' + c1_x_bytes + c1_y_bytes).hex()
            # c2_hex = (b'\x04' + c2_x_bytes + c2_y_bytes).hex()

            # logging.info("C1 uncompressed hex: %s", c1_hex)
            # logging.info("C2 uncompressed hex: %s", c2_hex)

            # # --- ElGamal 解密测试 ---
            # payload_dec = {
            #     "C1": c1_hex,
            #     "C2": c2_hex,
            #     "sk": sk_hex
            # }
            # json_input_dec = json.dumps(payload_dec).encode("utf-8")
            # ptr_dec = lib_bulletproof.pyElGamalDecrypt(json_input_dec)
            # result_dec = json.loads(string_at(ptr_dec).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr_dec)
            # logging.info("Elgamal decrypted message: %s", result_dec)

            # msg_x_str, msg_y_str = result_dec["message"].strip("()").split(",")
            # # 转换为 int
            # msg_x = int(msg_x_str, 16)
            # msg_y = int(msg_y_str, 16)
            # gk_x = int(k_x)
            # gk_y = int(k_y)
            # logging.info("msg_x: %s", msg_x)
            # logging.info("msg_y: %s", msg_y)
            # logging.info("gk_x: %s", gk_x)
            # logging.info("gk_y: %s", gk_y)

            # # 假设 proof_data 是你给出的 Claim 列表
            # proof_data = [
            #     {
            #         'H': {
            #             'X': '3745266854975719612369328163075316356437546587976323074075243596723375997055156776375695072565039068643712263780519',
            #             'Y': '2862635875034375207149747167738672980692528846424104937693511546815553940041994990281449645502568319374862734155723'
            #         },
            #         'ClaimedValue': '39717085216362713791605272371576796942938295723193556508027758597100637174017',
            #         'ClaimedValueAux': '21460181816851650248690820325580627225506435345474091454335450635704000694306'
            #     },
            #     {
            #         'H': {
            #             'X': '2042881334636470377695355532189955737722483351743485125603949488056168426976312777142141575962003900781715177250737',
            #             'Y': '2348247241808867285484989864378509317938286312402821458644613657106626740505693927128830108660399073036184801810482'
            #         },
            #         'ClaimedValue': '26859544678991499888612992246007769180277053423222697103657771338620412850897',
            #         'ClaimedValueAux': '29570473307959804945650000145185714158272994972862092909000046856425182372653'
            #     }
            # ]

            # # 构造 W（H 点）、m、m' 序列
            # W_list = []
            # m_list = []
            # m_prime_list = []

            # for item in proof_data:
            #     m_list.append(hex(int(item["ClaimedValue"]))[2:])
            #     m_prime_list.append(hex(int(item["ClaimedValueAux"]))[2:])
            # logging.info("m_list (hex): %s", m_list)
            # logging.info("m_prime_list (hex): %s", m_prime_list)

            # payload_W = {
            #     "g": uncompressed_g_hex,
            #     "h": uncompressed_h_hex,
            #     "m": m_list,
            #     "m_prime": m_prime_list
            # }

            # json_input_W = json.dumps(payload_W).encode("utf-8")
            # ptr_W = lib_bulletproof.pyComputeCommitmentGH(json_input_W)
            # result_W = json.loads(string_at(ptr_W).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr_W)
            # logging.info("result_W: %s", result_W)

            # W_list = []
            # for point in result_W:
            #     x_hex, y_hex = point.strip("()").split(",")
            #     x_bytes = long_to_bytes(int(x_hex, 16), 48)
            #     y_bytes = long_to_bytes(int(y_hex, 16), 48)
            #     W_uncompressed = b'\x04' + x_bytes + y_bytes
            #     W_list.append(W_uncompressed.hex())
            # logging.info("W_list (uncompressed hex): %s", W_list)

            # # 构造 pyProveFull 输入 payload
            # payload_proof = {
            #     "g": uncompressed_g_hex,
            #     "h": uncompressed_h_hex,
            #     "pk": uncompressed_pk_hex,
            #     "C1": c1_hex,
            #     "C2": c2_hex,
            #     "r": r_hex,
            #     "r_prime": k_hex,
            #     "m": m_list,
            #     "m_prime": m_prime_list,
            #     "W": W_list
            # }

            # # 执行证明
            # json_input_proof = json.dumps(payload_proof).encode("utf-8")
            # ptr_proof = lib_bulletproof.pyProveFull(json_input_proof)
            # result_proof = json.loads(string_at(ptr_proof).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr_proof)
            # logging.info("Bulletproof result is OK")
            # # logging.info("Bulletproof result: %s", result_proof)

            # # logging.info("Proof is hex? %s", all(c in "0123456789abcdefABCDEF" for c in result_proof))
            # proof = result_proof["proof"]

            # # === Bulletproof pyVerifyFull 测试 ===
            # payload_verify = {
            #     "g": uncompressed_g_hex,
            #     "h": uncompressed_h_hex,
            #     "pk": uncompressed_pk_hex,
            #     "C1": c1_hex,
            #     "C2": c2_hex,
            #     "W": W_list,              # W_list 是 G1 uncompressed 编码 hex 字符串数组
            #     "proof": proof     # result_proof 是 pyProveFull 返回的 base64 编码字符串
            # }

            # json_input_verify = json.dumps(payload_verify).encode("utf-8")
            # ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
            # result_verify = json.loads(string_at(ptr_verify).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr_verify)


            # logging.info("Bulletproof verify result: %s", result_verify)

            # # ------------------------------------------------------------------
            # # Poseidon‑derived symmetric encryption / decryption round‑trip test
            # # ------------------------------------------------------------------
            # #
            # #   • Encrypt (m_i , m'_i)  →  (c_i , c'_i)
            # #   • Decrypt using  (g^k , sk)  →  (m_i , m'_i)  ––– should match
            # #
            # #   Inputs already in scope:
            # #       uncompressed_pk_hex   – receiver public key  pk   (hex)
            # #       k_hex                 – ephemeral scalar     k
            # #       m_list , m_prime_list – hex scalars of secrets
            # #       sk_hex                – receiver secret key  sk
            # #       k_x , k_y             – coordinates of g^k  (from earlier)
            # # ------------------------------------------------------------------

            # # ----------------- 测试 Poseidon + Bulletproof 的对称加密解密 -----------------
            # # Build uncompressed hex for g^k (needed by decrypt)
            # gk_x_bytes = long_to_bytes(int(k_x), 48)
            # gk_y_bytes = long_to_bytes(int(k_y), 48)
            # uncompressed_gk_hex = (b"\x04" + gk_x_bytes + gk_y_bytes).hex()

            # cipher_pairs = []
            # for mi_hex, mpi_hex in zip(m_list, m_prime_list):
            #     enc_payload = {
            #         "pk": uncompressed_pk_hex,
            #         "k":  k_hex,
            #         "m":  mi_hex,
            #         "m_prime": mpi_hex
            #     }
            #     ptr_enc = lib_bulletproof.pySymEncrypt(json.dumps(enc_payload).encode("utf-8"))
            #     cipher = json.loads(string_at(ptr_enc).decode("utf-8"))
            #     lib_bulletproof.pyFreeString(ptr_enc)
            #     cipher_pairs.append((mi_hex, mpi_hex, cipher["c"], cipher["c_prime"]))
            #     logging.info("SymEncrypt → (c, c') = (%s, %s)", cipher["c"], cipher["c_prime"])

            # # Decrypt and check we recover the original plaintexts
            # for plaintext_m, plaintext_mp, c_hex, cp_hex in cipher_pairs:
            #     dec_payload = {
            #         "gk": uncompressed_gk_hex,
            #         "sk": sk_hex,
            #         "c":  c_hex,
            #         "c_prime": cp_hex
            #     }
            #     ptr_dec = lib_bulletproof.pySymDecrypt(json.dumps(dec_payload).encode("utf-8"))
            #     dec_result = json.loads(string_at(ptr_dec).decode("utf-8"))
            #     lib_bulletproof.pyFreeString(ptr_dec)

            #     # Equality check should ignore leading‑zero padding differences.
            #     ok_m  = (int(dec_result["m"], 16)       == int(plaintext_m, 16))
            #     ok_mp = (int(dec_result["m_prime"], 16) == int(plaintext_mp, 16))
            #     logging.info(
            #         "SymDecrypt check – m ok? %s, m' ok? %s (m=%s, m'=%s)",
            #         ok_m, ok_mp, dec_result["m"], dec_result["m_prime"]
            #     )

        if self.mode == "avss_with_pvtransfer": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )
           
            # ------------ PVTrans Lines 104-105 ------------
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")

            challenge = lib.pyDeriveChallenge(serialized_commitment)
            # logging.info("challenge: %s", challenge)

            aggproofAtZero = lib.pyAggProveEvalZero(
                serialized_proofAtZero,
                challenge
            )
            logging.info("aggproofAtZero: %s", aggproofAtZero)
            dser_aggproofAtZero = json.loads(aggproofAtZero.decode('utf-8'))["aggH"]
            # logging.info("dser_aggproofAtZero: %s", dser_aggproofAtZero)
            ser_aggproofAtZero = json.dumps(dser_aggproofAtZero).encode('utf-8')

            # --- aggregate each node’s proofList (H‑only) and fold with γ ---
            aggregated_proofList = []
            for i in range(self.n):
                # 取出第 i 个节点的 proof 列表并只保留 H 字段
                node_proofs = deser_comandproofwithzero["proofList"][i]
                node_H_only = [{"H": p["H"]} for p in node_proofs]

                serialized_node_H = json.dumps(node_H_only).encode("utf-8")
                agg_node = lib.pyAggProveEvalZero(
                    serialized_node_H,
                    challenge          # γ 的十进制字符串
                )
                dser_agg_node = json.loads(agg_node.decode("utf-8"))["aggH"]
                aggregated_proofList.append(
                    json.dumps(dser_agg_node).encode("utf-8")
                )

            # --------- PVTrans Lines 107-109 ------------
            # ------------------------------------------------------------------
            # Encrypt per‑node data:
            #   • fresh (r, k) scalars for this node
            #   • ElGamal encrypt g^k  →  (C1, C2)
            #   • Poseidon‑derived symmetric encrypt each (m, m′) share
            # ------------------------------------------------------------------
            # Decode the public key list (bytes → JSON list)
            public_keys_list = json.loads(self.public_keys.decode("utf-8"))
            pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            g0 = pk_dict["G1_g"][0]
            h0 = pk_dict["G1_h"][0]

            # read G1_g[0] X/Y 
            gx_dec = int(g0["X"])
            gy_dec = int(g0["Y"])

            # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            gx_bytes = long_to_bytes(gx_dec, 48)
            gy_bytes = long_to_bytes(gy_dec, 48)

            uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_g_hex = uncompressed_g.hex()

            # add h0
            hx_dec = int(h0["X"])
            hy_dec = int(h0["Y"])

            # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            hx_bytes = long_to_bytes(hx_dec, 48)
            hy_bytes = long_to_bytes(hy_dec, 48)

            uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            uncompressed_h_hex = uncompressed_h.hex()

            enc_results = []   # accumulate per‑node encryption artefacts for later use
            for node_idx, pk_entry in enumerate(public_keys_list):
                # pk_entry might already be a hex string or a dict with X/Y coords
                if isinstance(pk_entry, dict):
                    pkx = long_to_bytes(int(pk_entry["X"]), 48)
                    pky = long_to_bytes(int(pk_entry["Y"]), 48)
                    pk_hex = (b"\x04" + pkx + pky).hex()
                else:
                    pk_hex = pk_entry  # assume uncompressed hex

                # --- fresh randomness per node ---------------------------------
                r_hex = hex(random.getrandbits(256))[2:]
                k_hex = hex(random.getrandbits(256))[2:]

                # --- ElGamal: encrypt g^k under pk ------------------------------
                elg_payload = {
                    "g":  uncompressed_g_hex,  # base point prepared earlier
                    "pk": pk_hex,
                    "r":  r_hex,
                    "k":  k_hex
                }
                ptr_elg = lib_bulletproof.pyElGamalEncrypt(
                    json.dumps(elg_payload).encode("utf-8")
                )
                elg_out = json.loads(string_at(ptr_elg).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_elg)  # free C string

                C1_hex, C2_hex = elg_out["C1"], elg_out["C2"]

                # --- Poseidon symmetric encryption for each share --------------
                # Extract (m, m′) for this node from deser_comandproofwithzero["proofList"]
                node_proofs_full = deser_comandproofwithzero["proofList"][node_idx]
                m_list_node       = [hex(int(p["ClaimedValue"]))[2:]     for p in node_proofs_full]
                m_prime_list_node = [hex(int(p["ClaimedValueAux"]))[2:]  for p in node_proofs_full]

                # --- Compute W = g^m * h^{m'} for this node ---------------------
                payload_W = {
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex,
                    "m": m_list_node,
                    "m_prime": m_prime_list_node
                }
                ptr_W = lib_bulletproof.pyComputeCommitmentGH(json.dumps(payload_W).encode("utf-8"))
                result_W = json.loads(string_at(ptr_W).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_W)
                logging.info("[node %d] result_W: %s", node_idx, result_W)

                W_list_node = []
                for point in result_W:
                    x_hex, y_hex = point.strip("()").split(",")
                    x_bytes = long_to_bytes(int(x_hex, 16), 48)
                    y_bytes = long_to_bytes(int(y_hex, 16), 48)
                    W_uncompressed = b'\x04' + x_bytes + y_bytes
                    W_list_node.append(W_uncompressed.hex())

                cipher_shares = []
                for m_hex, mp_hex in zip(m_list_node, m_prime_list_node):
                    sym_payload = {
                        "pk": pk_hex,
                        "k":  k_hex,
                        "m":  m_hex,
                        "m_prime": mp_hex
                    }
                    ptr_sym = lib_bulletproof.pySymEncrypt(
                        json.dumps(sym_payload).encode("utf-8")
                    )
                    sym_out = json.loads(string_at(ptr_sym).decode("utf-8"))
                    lib_bulletproof.pyFreeString(ptr_sym)
                    cipher_shares.append((sym_out["c"], sym_out["c_prime"]))

                # --- Bulletproof full proof ------------------------------------
                payload_proof = {
                    "g":  uncompressed_g_hex,
                    "h":  uncompressed_h_hex,
                    "pk": pk_hex,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "r":  r_hex,
                    "r_prime": k_hex,
                    "m":  m_list_node,
                    "m_prime": m_prime_list_node,
                    "W":  W_list_node
                }
                ptr_proof = lib_bulletproof.pyProveFull(json.dumps(payload_proof).encode("utf-8"))
                proof_out = json.loads(string_at(ptr_proof).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_proof)
                proof_hex = proof_out["proof"]
                logging.info("[node %d] Bulletproof proof generated (len=%d hex)", node_idx, len(proof_hex))

                # Record everything for this node
                enc_results.append({
                    "node_id": node_idx,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "cipher_shares": cipher_shares,  # list of (c, c')
                    "W": W_list_node,                # list of uncompressed-hex points
                    "proof": proof_hex               # hex string
                })

            

            # enc_results is now a list you can attach to dispersal_msg_list or log

            logging.info("Per‑node encryption results prepared (len=%d)", len(enc_results))
            # ---- Bundle PV‑Transfer artefacts ---------------------------------
            #
            # We need to ship:
            #   • enc_results           – per‑node ciphertexts, W, proofs
            #   • serialized_commitment – polynomial commitment of all shares
            #   • ser_aggproofAtZero    – aggregated evaluation‑proof at 0
            #   • aggregated_proofList  – γ‑folded proofs per node
            #
            pvtransfer_payload = {
                "enc_results": enc_results,
                "commitment": (
                    serialized_commitment.decode("utf-8")
                    if isinstance(serialized_commitment, (bytes, bytearray))
                    else serialized_commitment
                ),
                "aggProofAtZero": (
                    ser_aggproofAtZero.decode("utf-8")
                    if isinstance(ser_aggproofAtZero, (bytes, bytearray))
                    else ser_aggproofAtZero
                ),
                "aggregated_proofList": [
                    p.decode("utf-8") if isinstance(p, (bytes, bytearray)) else p
                    for p in aggregated_proofList
                ],
            }
            # Store for later use when building dispersal messages
            self.pvtransfer_payload = pvtransfer_payload
            logging.info("PV‑Transfer payload assembled")
            
            # --- Convert dict → dataclass, serialize for RBC / TOB ---
            pv_obj = PVTransferPayload(
                enc_results=[EncResult(**er) for er in enc_results],
                commitment=pvtransfer_payload["commitment"],
                agg_proof_at_zero=pvtransfer_payload["aggProofAtZero"],
                aggregated_proof_list=pvtransfer_payload["aggregated_proofList"],
            )
            # 保存二进制版本，供后续 ΠGather / ΠSelectBlock / TOB 使用
            self.pvtransfer_bytes = pv_obj.to_bytes()
            logging.info(
                "PV-Transfer payload serialised (len=%d bytes)",
                len(self.pvtransfer_bytes),
            )

            # await self._run_local_gather(node_communicator)
            
        if self.mode == "avss_with_batch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            # logger.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed comandproof_right_inputs: {comandproof_right_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed deser_result: {deser_result}")
            # logger.info(f"[dealer {self.my_id}] parsed proof: {proof}")

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")
            
            # logging.info("serialized_proofAtZero: %s", serialized_proofAtZero)
            # logging.info("serialized_output_shareG: %s", serialized_output_shareG)
            # logging.info("serialized_output_shareH: %s", serialized_output_shareH)

            ab_shareGH = lib.pyComputeShareGH(
                self.srs_kzg['Pk'],
                serialized_left_proof,
                serialized_right_proof
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # logger.info("deser_ab_shareGH: %s", deser_ab_shareGH)
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            # logger.info("serialized_left_shareG: %s", serialized_left_shareG)
            # logger.info("serialized_left_shareH: %s", serialized_left_shareH)
            # logger.info("serialized_right_shareG: %s", serialized_right_shareG)
            # logger.info("serialized_right_shareH: %s", serialized_right_shareH)

        if self.mode == "avss_with_aggbatch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            # logging.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")

            proof_metric = proof_metadata(
                self.mpc_instance, protocol="batchmul",
                operation="ipakzg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=len(comandproof_left_inputs.get("proof", [])),
            )
            comandproofwithzero = timed_call(
                self.mpc_instance, proof_metric, "output_commitment_preparation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")

            ab_shareGH = timed_call(
                self.mpc_instance, proof_metric, "anchor_share_preparation",
                lib.pyComputeShareGH, self.srs_kzg['Pk'],
                serialized_left_proof, serialized_right_proof,
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            def _prepare_pedersen_commitments():
                return (
                    lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH),
                    lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH),
                    lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH),
                )

            ser_pedersen_left, ser_pedersen_right, ser_pedersen_output = timed_call(
                self.mpc_instance, proof_metric, "pedersen_commitment_preparation",
                _prepare_pedersen_commitments,
            )
            (
                ser_aggleftproof,
                ser_aggrightproof,
                ser_aggproofAtZero,
            ) = _generate_ipakzg_aggregate_witnesses(
                mpc_instance=self.mpc_instance,
                proof_metric=proof_metric,
                dealer_local_id=self.my_id,
                srs_pk=self.srs_kzg["Pk"],
                srs_vk=self.srs_kzg["Vk"],
                left_commitments=serialized_left_commitment,
                right_commitments=serialized_right_commitment,
                output_commitments=serialized_commitment,
                left_pedersen=ser_pedersen_left,
                right_pedersen=ser_pedersen_right,
                output_pedersen=ser_pedersen_output,
                left_openings=comandproof_left_inputs["proof"],
                right_openings=comandproof_right_inputs["proof"],
                output_openings=deser_comandproofwithzero["proofAtZero"],
            )
            finalize_operation(
                self.mpc_instance, proof_metric,
                BATCHMUL_GENERATE_COMPONENTS, success=True,
            )


        serialized_ephemeralpublicsecretkey = lib.pyKeyEphemeralGen(self.srs_kzg['Pk'], self.public_keys)
        
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')

        dispersal_msg_list = [None] * n
        shared_keys = [None] * n
        serialized_publickeys = json.loads(self.public_keys.decode('utf-8'))
        for i in range(n):
            shared_keys[i] = lib.pySharedKeysGen_sender(json.dumps(serialized_publickeys[i]).encode('utf-8'), serialized_ephemeralsecretkey)
            if self.mode == "avss_without_proof":
                logging.info("enter avss_without_proof mode")
                z = proofandshares[i]
            if self.mode == "avss_with_proof":
                z = (proofandshares[i], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs)
            if self.mode == "avss_with_transfer":
                z = proofandshares[i]
            if self.mode == "avss_with_aggtransfer":
                z = proofandshares[i]
            if self.mode == "avss_with_batch_multiplication":
                z = (
                    proofandshares[i],
                    serialized_left_commitment,
                    serialized_left_proof, 
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof, 
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof                   
                )
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                z = proofandshares[i]
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), z)


        broadcast_msg = _build_hbacss_broadcast_payload(
            self, serialized_commitment, serialized_ephemeralpublickey,
            locals(),
        )
        _record_hbacss_payload_calibration(
            self, broadcast_msg, dispersal_msg_list, locals()
        )
        return broadcast_msg, dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, dealer_id, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        
        (
            serialized_commitment,
            serialized_ephemeral_public_key,
            transfer_public_payload,
        ) = _parse_hbacss_broadcast_payload(self, rbc_msg)
        
        serialized_private_key = json.loads(json.loads(self.private_key.decode('utf-8')))

        serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeral_public_key, json.dumps(serialized_private_key[f'{dealer_id}']).encode('utf-8'))
        # self.tagvars[tag]['shared_key'] = serialized_sharedkey
        # self.tagvars[tag]['ephemeral_public_key'] = serialized_ephemeral_public_key
        try:
            if self.mode == "avss_without_proof":
                serialized_proofandshares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_proof":
                serialized_proofandshares, serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_transfer":
                noagg_payload = combine_aggtrans_noagg_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = noagg_payload.proof_and_shares
                serialized_original_commitment = noagg_payload.old_commitments
            if self.mode == "avss_with_aggtransfer":
                aggtrans_payload = combine_aggtrans_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = aggtrans_payload.proof_and_shares
                serialized_original_commitment = aggtrans_payload.old_commitments
            if self.mode == "avss_with_batch_multiplication":
                (
                    serialized_proofandshares,
                    serialized_left_commitment,
                    serialized_left_proof,
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof,
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof
                ) = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                batchmul_payload = combine_batchmul_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = batchmul_payload.proof_and_shares
                serialized_left_commitment = batchmul_payload.left_commitments
                serialized_right_commitment = batchmul_payload.right_commitments
                ser_aggleftproof = batchmul_payload.left_witness
                ser_aggrightproof = batchmul_payload.right_witness
                ser_aggproofAtZero = batchmul_payload.output_witness
                ser_pedersen_left = batchmul_payload.left_pedersen
                ser_pedersen_right = batchmul_payload.right_pedersen
                ser_pedersen_output = batchmul_payload.output_pedersen
                proof = batchmul_payload.factor_proof

                # # --- reconstruct two public proof‑and‑share lists ---
                # # 1) evaluation at x = i      (original proof)
                # # 2) evaluation at x = 0      (proofAtZero)
                # #
                # # Each element becomes {"H": ..., "G": shareG[i], "HClaim": shareH[i]}
                # #
                # deser_orig_proof = json.loads(serialized_original_proof.decode("utf-8"))
                # deser_P0         = json.loads(serialized_proofAtZero.decode("utf-8"))
                # deser_G          = json.loads(serialized_shareG.decode("utf-8"))
                # deser_H          = json.loads(serialized_shareH.decode("utf-8"))

                # # helper to fuse H, G, Ĥ
                # def _fuse(H_arr, G_arr, Hhat_arr):
                #     fused = []
                #     for idx in range(len(H_arr)):
                #         fused.append({
                #             "H": H_arr[idx]["H"],
                #             "GClaim": G_arr[idx],
                #             "HClaim": Hhat_arr[idx]
                #         })
                #     return fused

                # fused_proof_and_shares      = _fuse(deser_orig_proof, deser_G, deser_H)
                # fused_proofanzero_andshares = _fuse(deser_P0, deser_G, deser_H)

                # logging.info("fused_proof_and_shares: %s", fused_proof_and_shares)
                # logging.info("fused_proofanzero_andshares: %s", fused_proofanzero_andshares)

                # serialized_proofandshares_pub      = json.dumps(fused_proof_and_shares).encode("utf-8")
                # serialized_proofandshares_zero_pub = json.dumps(fused_proofanzero_andshares).encode("utf-8")
                
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
         
         
        if all_shares_valid:
            if self.mode == "avss_without_proof":
                if lib.pyBatchVerify(self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    all_shares_valid = False
            if self.mode == "avss_with_proof":
                if lib.pyBatchVerify(
                    self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                    ) == int(1) and lib.pyBatchhiddenverify(self.srs_kzg['Vk'], 
                    self.tagvars[tag]['committment_ab'], serialized_zkProof_ab, dealer_id) == int(1) and lib.pyBatchhiddenzeroverify(self.srs_kzg['Vk'], 
                    serialized_commitment, serialized_zkProof_c_zero) == int(1) and lib.pyProdverify(
                    self.srs_kzg['Vk'], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs) == int(1):
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    return False
            if self.mode == "avss_with_transfer":
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans-noagg",
                    operation="batch_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_original_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, proof_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                old_anchor_valid, fresh_zero_valid = (
                    _verify_aggtrans_noagg_relations(
                        mpc_instance=mpc_instance,
                        proof_metric=proof_metric,
                        dealer_local_id=dealer_id,
                        srs_vk=self.srs_kzg['Vk'],
                        old_commitments=serialized_original_commitment,
                        fresh_commitments=serialized_commitment,
                        old_witnesses=noagg_payload.old_witnesses,
                        fresh_witnesses=noagg_payload.fresh_witnesses,
                        pedersen=noagg_payload.pedersen,
                    )
                )
                finalize_operation(
                    mpc_instance, proof_metric,
                    AGGTRANS_NOAGG_VERIFY_COMPONENTS,
                    success=(
                        bacss_share_valid
                        and old_anchor_valid
                        and fresh_zero_valid
                    ),
                )
                if bacss_share_valid and old_anchor_valid and fresh_zero_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_aggtransfer":
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans",
                    operation="aggpub_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_commitment.decode("utf-8"))),
                )
                proof_metric.update(aggtrans_proof_size_metadata(
                    self.agg_kzg_mode, v2=aggtrans_payload.v2,
                    legacy=aggtrans_payload.legacy,
                ))
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans",
                    operation="aggtrans_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    AGGTRANS_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                component = (
                    "legacy_aggpub_verify"
                    if self.agg_kzg_mode == "legacy" else "aggpub_verify"
                )
                aggtrans_verification = timed_call(
                    mpc_instance, proof_metric, component,
                    lambda: verify_aggtrans(
                        self.agg_kzg_mode, library=lib,
                        srs_pk=self.srs_kzg['Pk'],
                        srs_vk=self.srs_kzg['Vk'],
                        dealer_local_id=dealer_id,
                        receiver_local_id=self.my_id,
                        fresh_commitments=serialized_commitment,
                        payload=aggtrans_payload,
                    ),
                    success=lambda result: result.accepted,
                )
                fresh_zero_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.fresh_zero_valid
                )
                old_anchor_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.old_anchor_valid
                )
                finalize_operation(
                    mpc_instance, proof_metric,
                    aggtrans_verify_components(self.agg_kzg_mode),
                    success=fresh_zero_valid and old_anchor_valid,
                )
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_aggtrans_verification(
                        dealer_local_id=dealer_id,
                        bacss_share_valid=bacss_share_valid,
                        fresh_zero_valid=fresh_zero_valid,
                        old_anchor_valid=old_anchor_valid,
                    )

                if bacss_share_valid and fresh_zero_valid and old_anchor_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == ("avss_with_agg" + "batch_multiplication"):
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left_list = json.loads(ser_pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(ser_pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(ser_pedersen_output.decode("utf-8"))
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="ipakzg_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                def _verify_factor_proof():
                    result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                    try:
                        result_json = string_at(result_ptr).decode("utf-8")
                        logger.info("verifier_result_json: %s", result_json)
                        return bool(json.loads(result_json).get("verified", False))
                    finally:
                        lib_bulletproof.pyFreeString(result_ptr)

                product_proof_valid = timed_call(
                    mpc_instance, proof_metric, "factor_verify",
                    _verify_factor_proof, success=bool,
                )
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="batchmul_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    BATCHMUL_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                (
                    left_anchor_valid,
                    right_anchor_valid,
                    output_zero_valid,
                ) = _verify_ipakzg_aggregate_relations(
                    mpc_instance=mpc_instance,
                    proof_metric=proof_metric,
                    dealer_local_id=dealer_id,
                    srs_pk=self.srs_kzg["Pk"],
                    srs_vk=self.srs_kzg["Vk"],
                    left_commitments=serialized_left_commitment,
                    right_commitments=serialized_right_commitment,
                    output_commitments=serialized_commitment,
                    left_pedersen=ser_pedersen_left,
                    right_pedersen=ser_pedersen_right,
                    output_pedersen=ser_pedersen_output,
                    left_witness=ser_aggleftproof,
                    right_witness=ser_aggrightproof,
                    output_witness=ser_aggproofAtZero,
                )
                proof_valid = (
                    product_proof_valid and left_anchor_valid
                    and right_anchor_valid and output_zero_valid
                )
                finalize_operation(
                    mpc_instance, proof_metric, BATCHMUL_VERIFY_COMPONENTS,
                    success=proof_valid,
                )
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_batchmul_verification(
                        dealer_local_id=dealer_id,
                        product_proof_valid=product_proof_valid,
                        bacss_share_valid=bacss_share_valid,
                        left_anchor_valid=left_anchor_valid,
                        right_anchor_valid=right_anchor_valid,
                        output_zero_valid=output_zero_valid,
                    )
                if proof_valid and bacss_share_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                    self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_batch_multiplication":
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left = lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH)
                pedersen_right = lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH)
                pedersen_out = lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH)

                # logger.info("pedersen_left: %s", pedersen_left)
                # logger.info("pedersen_right: %s", pedersen_right)
                # logger.info("pedersen_out: %s", pedersen_out)

                pedersen_left_list = json.loads(pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(pedersen_out.decode("utf-8"))

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                verifier_result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                verifier_result_json = string_at(verifier_result_ptr).decode("utf-8")

                logger.info("verifier_result_json: %s", verifier_result_json)
                lib_bulletproof.pyFreeString(verifier_result_ptr)

                # Add check for verification result
                if json.loads(verifier_result_json).get("verified", False):
                    logging.info("inner product verified successfully")
                    if lib.pyBatchVerify(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                        ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_left_commitment, serialized_left_proof, serialized_left_shareG, serialized_left_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_right_commitment, serialized_right_proof, serialized_right_shareG, serialized_right_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofAtZero, serialized_output_shareG, serialized_output_shareH, -1
                    ) == int(1):
                        logging.info("shares verified successfully")
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                        self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                        self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                    else:
                        logging.info("shares verification FAILED")
                        return False
                else:
                    logging.info("inner product verification FAILED")
                    return False
    
        return all_shares_valid

    #@profile
    async def avss(self, avss_id, coms=None, values=None, dealer_id=None, client_mode=False):

        
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )
        
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"
        logging.info("[%d] AVSS tag: %s", self.my_id, acsstag)
        logging.info("[%d] RBC tag: %s", self.my_id, rbctag)



        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []
        if self.mode == "avss_with_proof":
            self.tagvars[acsstag]['committment_ab'] = coms
            

        # In the client_mode, the dealer is the last node
        n = self.n 
        broadcast_msg = None
        dispersal_msg_list = None
        
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(acsstag, values, n)


            
        member_list = [(self.mpc_instance.layer_ID) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID+1) + i)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logging.info("[%d] Starting reliable broadcast", self.my_id)
        # if self.my_id == 0:
        asyncio.create_task(
        rbc_dyn(
            rbctag,
            self.my_id,
            n+1,
            self.t,
            self.my_id,
            broadcast_msg,
            recv,
            send,
            member_list,
            n
        ))
        
        # if self.my_id == 0:
        avidtag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVID"
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        
        send, recv = self.get_send(avidtag), self.subscribe_recv(avidtag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid_dyn = AVID_DYNAMIC(n+1, self.t, self.my_id, recv, send, n, member_list)
        logging.info("self.msgmode: %s", self.mode)
        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid_dyn, avidtag, dispersal_msg_list))

        # asyncio.create_task(avid_dyn.retrieve(acsstag, self.my_id))
        # await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)   

class ACSS_Foll(Hbacss0):
    #@profile
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, msgmode, mpc_instance):  
        
        self.mpc_instance = mpc_instance

        
        super().__init__(public_keys, private_key, crs, n, t, my_id, send, recv, msgmode)

    async def _recv_loop(self, q, dealer_id):           
        avid, tag, dispersal_msg_list = await q.get()
        if self.my_id < dealer_id:
            await avid.disperse(tag, self.my_id, dispersal_msg_list)
        else: 
            await avid.disperse(tag, self.my_id+1, dispersal_msg_list)
        
        
    def __enter__(self):
        # self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
                
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # TODO: Add the handle implication
        pass
        # commitments =  self.tagvars[tag]['commitments']
        # # discard if PKj ! = g^SKj
        # if self.public_keys[j] != pow(self.g, j_sk):
        #     return False
        # # decrypt and verify
        # implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        # j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # # Same as the batch size
        # secret_count = len(commitments)

        # try:
        #     j_shares, j_auxes, j_witnesses = SymmetricCrypto.decrypt(
        #         str(j_shared_key).encode(), implicate_msg
        #     )
        # except Exception as e:  # TODO specific exception
        #     logger.warn("Implicate confirmed, bad encryption:", e)
        #     return True
        # return not self.poly_commit.batch_verify_eval(
        #     commitments, j + 1, j_shares, j_auxes, j_witnesses
        # )



    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
        #     logger.debug("[%d] sent_kdi_broadcast", self.my_id)
        #     kdi = self.tagvars[tag]['shared_key']
        #     multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
        #     self.kdi_broadcast_sent = True
        # if self.tagvars[tag]['all_shares_valid']:
        #     return

        # if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
        #     logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
        #     avid = self.tagvars[tag]['avid']
        #     retrieved_msg = await avid.retrieve(tag, sender)
        #     try:
        #         j_shares, j_witnesses = SymmetricCrypto.decrypt(
        #             str(avss_msg[1]).encode(), retrieved_msg
        #         )
        #     except Exception as e:  # TODO: Add specific exception
        #         logger.debug("Implicate confirmed, bad encryption:", e)
        #     commitments = self.tagvars[tag]['commitments']
        #     if (self.poly_commit.batch_verify_eval(commitments,
        #                                            sender + 1, j_shares, j_witnesses)):
        #         if not self.saved_shares[sender]:
        #             self.saved_shared_actual_length += 1
        #             self.saved_shares[sender] = j_shares

        # # if t+1 in the saved_set, interpolate and sell all OK
        # if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
        #     logger.debug("[%d] interpolating", self.my_id)
        #     # Batch size
        #     shares = []
        #     secret_count = len(self.tagvars[tag]['commitments'])
        #     for i in range(secret_count):
        #         phi_coords = [
        #             (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
        #         ]
        #         shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
        #     self.tagvars[tag]['all_shares_valid'] = True
        #     self.tagvars[tag]['shares'] = shares
        #     self.tagvars[tag]['in_share_recovery'] = False
        #     self.interpolated = True
        #     multicast((HbAVSSMessageType.OK, ""))
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        # self.tagvars[tag] = {}
        self._init_recovery_vars(tag)


        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)
        logging.info("multicast list: %s", multi_list)

        def multicast(msg):
            for i in range(self.n):
                num = i + self.mpc_instance.layer_ID * self.n
                logging.info("multicast to %d", num)
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        # self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable broadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        logging.info("before avid.retrieve")
        if self.my_id < dealer_id:
            dispersal_msg = await avid.retrieve(tag, self.my_id)
        else:
            dispersal_msg = await avid.retrieve(tag, self.my_id + 1)
        logging.info("after avid.retrieve dispersal_msg")

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(dealer_id, tag, dispersal_msg, rbc_msg)
        logging.info("after _handle_dealer_msgs, all_shares_valid")
        logging.info("self.tagvars[tag]['all_shares_valid']: %s", self.tagvars[tag]['all_shares_valid'])

        # obtain
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False
        
        if self.tagvars[tag]['all_shares_valid']:
            if self.mode == "avss_without_proof":
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                logging.info(f"avss_without_proof dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_proof":
                logging.debug(f"dealer_id: {dealer_id}")
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
            if self.mode == "avss_with_transfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggtransfer": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['original_commitments']))   
            if self.mode == "avss_with_aggbatch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            if self.mode == "avss_with_batch_multiplication": 
                logging.debug(f"dealer_id: {dealer_id}")
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'], self.tagvars[tag]['left_commitments'], self.tagvars[tag]['right_commitments']))
            output = True
            # return (dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments'])
            multicast((HbAVSSMessageType.OK, ""))
            
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()
            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                logging.info("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                logging.info("[%d] OK set: %s", self.my_id, ok_set)
            logging.info("output: %s", output)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logging.info("[%d] exit", self.my_id)
                break

    # ------------------------------------------------------------------
    #  Helper: run local ΠGather + ΠSelectBlock
    # ------------------------------------------------------------------
    async def _run_local_gather(self, node_communicator):
        """
        把 self.pvtransfer_bytes 当作 B_i，启动 YosoGather，
        等它跑完 Strongly-Stable 选块协议。
        """
        from beaver.gather import YosoGather   # 延迟 import 避免循环

        g = YosoGather(
            self.public_keys, self.private_key,
            self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            self.pvtransfer_bytes          # ★ B_i
        )
        task = asyncio.create_task(g.run_gather(node_communicator))
        await task         # ← 在协程内合法使用 await
        g.kill()

        logging.info(
            "[%d] ΠGather done – |U₃|=%d, g=%s, |C|=%d",
            self.my_id,
            len(getattr(g, "U", {})),
            getattr(g, "g", "NA"),
            len(getattr(g, "final_block", b"")),
        )

    #@profile
    def _get_dealer_msg(self, acsstag, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        proofandshares = []
        if self.mode == "avss_without_proof":
            commitmentlistandprooflist = lib.pyCommit(self.srs_kzg['Pk'], values, self.t)
            
            deserialized_commitmentlistandprooflist = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deserialized_commitmentlistandprooflist['commitmentList']).encode('utf-8')            
            for i in range(self.n):
                proofandshares.append(json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8'))
            # logging.info("avss_without_proof proofandshares: %s", proofandshares)
        if self.mode == "avss_with_proof":
            deserialized_commandprooflist = json.loads(values.decode('utf-8'))            
            serialized_commitmentlist = json.dumps(deserialized_commandprooflist['commitment']).encode('utf-8')
            serialized_prooflist = json.dumps(deserialized_commandprooflist['proof']).encode('utf-8')
            commitmentlistandprooflist = lib.pyParseRandom(self.srs_kzg['Pk'], serialized_commitmentlist, serialized_prooflist, self.t, self.my_id)

            deser_comsandproofs = json.loads(commitmentlistandprooflist.decode('utf-8'))
            # logging.info("deser_comsandproofs: %s", deser_comsandproofs)
            serialized_commitment = json.dumps(deser_comsandproofs['commitments_c']).encode('utf-8') 
            serialized_zkProof_ab = json.dumps(deser_comsandproofs['zkProof_ab']).encode('utf-8') 
            serialized_zkProof_c_zero = json.dumps(deser_comsandproofs['zkProof_c_zero']).encode('utf-8') 
            serialized_prodProofs = json.dumps(deser_comsandproofs['prodProofs']).encode('utf-8') 
            logger.info(f"prodProofs size: {len(serialized_prodProofs)} bytes")
            logger.info(f"prodProofs count: {len(deser_comsandproofs['prodProofs'])}")
            
            for i in range(self.n):
                proofandshares.append(json.dumps(deser_comsandproofs['proofs_c'][i]).encode('utf-8'))   
            # logging.info("proofandshares: %s", proofandshares)

        if self.mode == "avss_with_transfer": 
            # `values` carries the serialized `com_and_proof_obj` produced in
            # setup_transfer.log.  Extract ClaimedValue / ClaimedValueAux,
            # build the two secret vectors, and obtain commitments & proofs
            # that also include f(0) related data via pyCommitWithZeroFull.
            # -------------------------------------------------------------
            # robust JSON decode (handle both normal JSON and python‐repr)
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("secrets: %s", secrets)
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            mpc_instance = getattr(self, "mpc_instance", None)
            noagg_generation_metric = proof_metadata(
                mpc_instance, protocol="aggtrans-noagg",
                operation="noagg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None, batch_size=len(proofs_lst),
            )
            comandproofwithzero = timed_call(
                mpc_instance, noagg_generation_metric,
                "commitment_opening_generation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)
            # logging.info("serialized_commitment: %s", serialized_commitment)


            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            # logging.info("proof_at_zero_Honly: %s", proof_at_zero_Honly)

            noagg_artifacts = prepare_aggtrans_noagg(
                library=lib,
                old_commitments=original_commitment,
                fresh_commitments=deser_comandproofwithzero["commitmentList"],
                old_witnesses=original_proof_no_val,
                fresh_witnesses=proof_at_zero_Honly,
                share_g=deser_comandproofwithzero.get("shareG", []),
                share_h=deser_comandproofwithzero.get("shareH", []),
                pedersen_combine=lambda share_g, share_h: timed_call(
                    mpc_instance, noagg_generation_metric,
                    "pedersen_commitment_preparation",
                    lib.pyPedersenCombine, share_g, share_h,
                ),
            )
            finalize_operation(
                mpc_instance, noagg_generation_metric,
                AGGTRANS_NOAGG_GENERATE_COMPONENTS, success=True,
            )

        if self.mode == "avss_with_aggtransfer": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            fresh_openings = deser_comandproofwithzero.get("proofAtZero", [])
            aggtrans_v2 = None
            aggtrans_legacy = None
            if self.agg_kzg_mode in {"v2", "shadow"}:
                aggtrans_v2 = prove_aggtrans_v2(
                    library=lib, srs_pk=self.srs_kzg['Pk'],
                    srs_vk=self.srs_kzg['Vk'], dealer_local_id=self.my_id,
                    old_commitments=original_commitment,
                    fresh_commitments=deser_comandproofwithzero["commitmentList"],
                    old_openings=proofs_lst, fresh_openings=fresh_openings,
                )
            if self.agg_kzg_mode in {"legacy", "shadow"}:
                aggtrans_legacy = prove_aggtrans_legacy(
                    library=lib,
                    fresh_commitments=deser_comandproofwithzero["commitmentList"],
                    old_openings=proofs_lst, fresh_openings=fresh_openings,
                    share_g=deser_comandproofwithzero.get("shareG", []),
                    share_h=deser_comandproofwithzero.get("shareH", []),
                )

            logging.info("self.public_keys: %s", self.public_keys)
            logging.info("self.private_key: %s", self.private_key)          


            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggproofAtZero).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     0                 # C.int
            # )
            # logging.info("x=0 pyPubAggVerifyEval result: %s", ok)

            # ok = lib.pyPubAggVerifyEval(
            #     self.srs_kzg['Vk'],            # SRS['Vk']
            #     serialized_original_commitment,   # 聚合前 C_i 列表
            #     json.dumps(dser_aggshareG).encode('utf-8'),
            #     json.dumps(dser_aggshareH).encode('utf-8'),
            #     json.dumps(dser_aggoriginalproof).encode('utf-8'),
            #     challenge,                # γ 的十进制字符串
            #     self.my_id + 1                 # C.int
            # )
            # logging.info("x=my.id pyPubAggVerifyEval result: %s", ok)

            # --------------------- 从这行开始，后续的代码都是用来测试 Poseidon + Bulletproof 的 --------------------

            pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            g0 = pk_dict["G1_g"][0]
            h0 = pk_dict["G1_h"][0]

            # read G1_g[0] X/Y 
            gx_dec = int(g0["X"])
            gy_dec = int(g0["Y"])

            # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            gx_bytes = long_to_bytes(gx_dec, 48)
            gy_bytes = long_to_bytes(gy_dec, 48)

            uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_g_hex = uncompressed_g.hex()
            logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

            # add h0
            hx_dec = int(h0["X"])
            hy_dec = int(h0["Y"])

            # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            hx_bytes = long_to_bytes(hx_dec, 48)
            hy_bytes = long_to_bytes(hy_dec, 48)

            uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            uncompressed_h_hex = uncompressed_h.hex()
            logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
            
            sk = "43066057178372115162090031665738480497785504495963485110743715314730498099898"
            sk_hex = hex(int(sk))[2:]  # 去掉 0x 前缀
            pk_x = "2540810243697281646753816249646546839680056672316758359369207562792691238809422685043919463202492103317975796630457"
            pk_y = "50066053523316668810016801456660224022045904723296188340443488016713934584332814528641622484569632142481660547518"
            pkx_bytes = long_to_bytes(int(pk_x), 48)
            pky_bytes = long_to_bytes(int(pk_y), 48)

            uncompressed_pk = b'\x04' + pkx_bytes + pky_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_pk_hex = uncompressed_pk.hex()
            logging.info("uncompressed_pk.hex(): %s", uncompressed_pk.hex())

            k = "6706283196960114501037797896778429581316608798606687574701835551207274422636"
            k_hex = hex(int(k))[2:]  # 去掉 0x 前缀
            k_x = "1414576985840271823358185120885954780171082639683846674231723237543180390154178096938117414806051004278910490643080"
            k_y = "2646059067981507357143657154501587172603295817551133156830318975462005332733650918056918384628991898173670748015537"

            r = "1757101419104903848312328479324811944822009314342771061452727681968477199489"
            r_hex = hex(int(r))[2:]  # 去掉 0x 前缀
            logging.info("r_hex: %s", r_hex)


            payload = {
                "g": uncompressed_g_hex,
                "pk": uncompressed_pk_hex,
                "r": r_hex,
                "k": k_hex
            }

            json_input = json.dumps(payload).encode("utf-8")
            ptr = lib_bulletproof.pyElGamalEncrypt(json_input)
            logging.info("Elgamal done!")
            result = json.loads(string_at(ptr).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr)

            logging.info("Elgamal result: %s", result)

            # 提取已是 hex 的 C1、C2 中的 X, Y
            c1_x_str, c1_y_str = result["C1"].strip("()").split(",")
            c2_x_str, c2_y_str = result["C2"].strip("()").split(",")

            # 正确：用 int(x, 16) 明确指出是 hex 编码
            c1_x_bytes = long_to_bytes(int(c1_x_str, 16), 48)
            c1_y_bytes = long_to_bytes(int(c1_y_str, 16), 48)
            c2_x_bytes = long_to_bytes(int(c2_x_str, 16), 48)
            c2_y_bytes = long_to_bytes(int(c2_y_str, 16), 48)

            c1_hex = (b'\x04' + c1_x_bytes + c1_y_bytes).hex()
            c2_hex = (b'\x04' + c2_x_bytes + c2_y_bytes).hex()

            logging.info("C1 uncompressed hex: %s", c1_hex)
            logging.info("C2 uncompressed hex: %s", c2_hex)

            # --- ElGamal 解密测试 ---
            payload_dec = {
                "C1": c1_hex,
                "C2": c2_hex,
                "sk": sk_hex
            }
            json_input_dec = json.dumps(payload_dec).encode("utf-8")
            ptr_dec = lib_bulletproof.pyElGamalDecrypt(json_input_dec)
            result_dec = json.loads(string_at(ptr_dec).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_dec)
            logging.info("Elgamal decrypted message: %s", result_dec)

            msg_x_str, msg_y_str = result_dec["message"].strip("()").split(",")
            # 转换为 int
            msg_x = int(msg_x_str, 16)
            msg_y = int(msg_y_str, 16)
            gk_x = int(k_x)
            gk_y = int(k_y)
            logging.info("msg_x: %s", msg_x)
            logging.info("msg_y: %s", msg_y)
            logging.info("gk_x: %s", gk_x)
            logging.info("gk_y: %s", gk_y)

            # 假设 proof_data 是你给出的 Claim 列表
            proof_data = [
                {
                    'H': {
                        'X': '3745266854975719612369328163075316356437546587976323074075243596723375997055156776375695072565039068643712263780519',
                        'Y': '2862635875034375207149747167738672980692528846424104937693511546815553940041994990281449645502568319374862734155723'
                    },
                    'ClaimedValue': '39717085216362713791605272371576796942938295723193556508027758597100637174017',
                    'ClaimedValueAux': '21460181816851650248690820325580627225506435345474091454335450635704000694306'
                },
                {
                    'H': {
                        'X': '2042881334636470377695355532189955737722483351743485125603949488056168426976312777142141575962003900781715177250737',
                        'Y': '2348247241808867285484989864378509317938286312402821458644613657106626740505693927128830108660399073036184801810482'
                    },
                    'ClaimedValue': '26859544678991499888612992246007769180277053423222697103657771338620412850897',
                    'ClaimedValueAux': '29570473307959804945650000145185714158272994972862092909000046856425182372653'
                }
            ]

            # 构造 W（H 点）、m、m' 序列
            W_list = []
            m_list = []
            m_prime_list = []

            for item in proof_data:
                m_list.append(hex(int(item["ClaimedValue"]))[2:])
                m_prime_list.append(hex(int(item["ClaimedValueAux"]))[2:])
            logging.info("m_list (hex): %s", m_list)
            logging.info("m_prime_list (hex): %s", m_prime_list)

            payload_W = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "m": m_list,
                "m_prime": m_prime_list
            }

            json_input_W = json.dumps(payload_W).encode("utf-8")
            ptr_W = lib_bulletproof.pyComputeCommitmentGH(json_input_W)
            result_W = json.loads(string_at(ptr_W).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_W)
            logging.info("result_W: %s", result_W)

            W_list = []
            for point in result_W:
                x_hex, y_hex = point.strip("()").split(",")
                x_bytes = long_to_bytes(int(x_hex, 16), 48)
                y_bytes = long_to_bytes(int(y_hex, 16), 48)
                W_uncompressed = b'\x04' + x_bytes + y_bytes
                W_list.append(W_uncompressed.hex())
            logging.info("W_list (uncompressed hex): %s", W_list)

            # 构造 pyProveFull 输入 payload
            payload_proof = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "pk": uncompressed_pk_hex,
                "C1": c1_hex,
                "C2": c2_hex,
                "r": r_hex,
                "r_prime": k_hex,
                "m": m_list,
                "m_prime": m_prime_list,
                "W": W_list
            }

            # 执行证明
            json_input_proof = json.dumps(payload_proof).encode("utf-8")
            ptr_proof = lib_bulletproof.pyProveFull(json_input_proof)
            result_proof = json.loads(string_at(ptr_proof).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_proof)
            logging.info("Bulletproof result is OK")
            # logging.info("Bulletproof result: %s", result_proof)

            # logging.info("Proof is hex? %s", all(c in "0123456789abcdefABCDEF" for c in result_proof))
            proof = result_proof["proof"]

            # === Bulletproof pyVerifyFull 测试 ===
            payload_verify = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "pk": uncompressed_pk_hex,
                "C1": c1_hex,
                "C2": c2_hex,
                "W": W_list,              # W_list 是 G1 uncompressed 编码 hex 字符串数组
                "proof": proof     # result_proof 是 pyProveFull 返回的 base64 编码字符串
            }

            json_input_verify = json.dumps(payload_verify).encode("utf-8")
            ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
            result_verify = json.loads(string_at(ptr_verify).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_verify)


            logging.info("Bulletproof verify result: %s", result_verify)

            # ------------------------------------------------------------------
            # Poseidon‑derived symmetric encryption / decryption round‑trip test
            # ------------------------------------------------------------------
            #
            #   • Encrypt (m_i , m'_i)  →  (c_i , c'_i)
            #   • Decrypt using  (g^k , sk)  →  (m_i , m'_i)  ––– should match
            #
            #   Inputs already in scope:
            #       uncompressed_pk_hex   – receiver public key  pk   (hex)
            #       k_hex                 – ephemeral scalar     k
            #       m_list , m_prime_list – hex scalars of secrets
            #       sk_hex                – receiver secret key  sk
            #       k_x , k_y             – coordinates of g^k  (from earlier)
            # ------------------------------------------------------------------

            # ----------------- 测试 Poseidon + Bulletproof 的对称加密解密 -----------------
            # Build uncompressed hex for g^k (needed by decrypt)
            gk_x_bytes = long_to_bytes(int(k_x), 48)
            gk_y_bytes = long_to_bytes(int(k_y), 48)
            uncompressed_gk_hex = (b"\x04" + gk_x_bytes + gk_y_bytes).hex()

            cipher_pairs = []
            for mi_hex, mpi_hex in zip(m_list, m_prime_list):
                enc_payload = {
                    "pk": uncompressed_pk_hex,
                    "k":  k_hex,
                    "m":  mi_hex,
                    "m_prime": mpi_hex
                }
                ptr_enc = lib_bulletproof.pySymEncrypt(json.dumps(enc_payload).encode("utf-8"))
                cipher = json.loads(string_at(ptr_enc).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_enc)
                cipher_pairs.append((mi_hex, mpi_hex, cipher["c"], cipher["c_prime"]))
                logging.info("SymEncrypt → (c, c') = (%s, %s)", cipher["c"], cipher["c_prime"])

            # Decrypt and check we recover the original plaintexts
            for plaintext_m, plaintext_mp, c_hex, cp_hex in cipher_pairs:
                dec_payload = {
                    "gk": uncompressed_gk_hex,
                    "sk": sk_hex,
                    "c":  c_hex,
                    "c_prime": cp_hex
                }
                ptr_dec = lib_bulletproof.pySymDecrypt(json.dumps(dec_payload).encode("utf-8"))
                dec_result = json.loads(string_at(ptr_dec).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_dec)

                # Equality check should ignore leading‑zero padding differences.
                ok_m  = (int(dec_result["m"], 16)       == int(plaintext_m, 16))
                ok_mp = (int(dec_result["m_prime"], 16) == int(plaintext_mp, 16))
                logging.info(
                    "SymDecrypt check – m ok? %s, m' ok? %s (m=%s, m'=%s)",
                    ok_m, ok_mp, dec_result["m"], dec_result["m_prime"]
                )

        if self.mode == "avss_with_pvtransfer": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)
            try:
                com_and_proof_obj = json.loads(values_str)
            except json.JSONDecodeError:
                com_and_proof_obj = json.loads(values_str.replace("'", '"'))

            proofs_lst = com_and_proof_obj.get("proof", [])
            secrets      = [p["ClaimedValue"]     for p in proofs_lst]
            secrets_aux  = [p["ClaimedValueAux"] for p in proofs_lst]

            # logging.info("len secrets: %s", len(secrets))
            # logging.info("secrets_aux: %s", secrets_aux)

            # --- keep original commitment and proof (without secret values) ---
            original_commitment = com_and_proof_obj.get("commitment", [])
            serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")
            # logging.info("serialized_original_commitment: %s", serialized_original_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

            serialized_secrets      = json.dumps(secrets).encode("utf-8")
            serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )
           
            # ------------ PVTrans Lines 104-105 ------------
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")

            challenge = lib.pyDeriveChallenge(serialized_commitment)
            # logging.info("challenge: %s", challenge)

            aggproofAtZero = lib.pyAggProveEvalZero(
                    serialized_proofAtZero,
                    challenge         # γ 的十进制字符串
                )
            logging.info("aggproofAtZero: %s", aggproofAtZero)
            dser_aggproofAtZero = json.loads(aggproofAtZero.decode('utf-8'))["aggH"]
            # logging.info("dser_aggproofAtZero: %s", dser_aggproofAtZero)
            ser_aggproofAtZero = json.dumps(dser_aggproofAtZero).encode('utf-8')

            # --- aggregate each node’s proofList (H‑only) and fold with γ ---
            aggregated_proofList = []
            for i in range(self.n):
                # 取出第 i 个节点的 proof 列表并只保留 H 字段
                node_proofs = deser_comandproofwithzero["proofList"][i]
                node_H_only = [{"H": p["H"]} for p in node_proofs]

                serialized_node_H = json.dumps(node_H_only).encode("utf-8")
                agg_node = lib.pyAggProveEvalZero(
                    serialized_node_H,
                    challenge          # γ 的十进制字符串
                )
                dser_agg_node = json.loads(agg_node.decode("utf-8"))["aggH"]
                aggregated_proofList.append(
                    json.dumps(dser_agg_node).encode("utf-8")
                )

            # --------- PVTrans Lines 107-109 ------------
            # ------------------------------------------------------------------
            # Encrypt per‑node data:
            #   • fresh (r, k) scalars for this node
            #   • ElGamal encrypt g^k  →  (C1, C2)
            #   • Poseidon‑derived symmetric encrypt each (m, m′) share
            # ------------------------------------------------------------------
            # Decode the public key list (bytes → JSON list)
            public_keys_list = json.loads(self.public_keys.decode("utf-8"))
            pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
            g0 = pk_dict["G1_g"][0]
            h0 = pk_dict["G1_h"][0]

            # read G1_g[0] X/Y 
            gx_dec = int(g0["X"])
            gy_dec = int(g0["Y"])

            # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
            # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

            gx_bytes = long_to_bytes(gx_dec, 48)
            gy_bytes = long_to_bytes(gy_dec, 48)

            uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
            uncompressed_g_hex = uncompressed_g.hex()

            # add h0
            hx_dec = int(h0["X"])
            hy_dec = int(h0["Y"])

            # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
            # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

            hx_bytes = long_to_bytes(hx_dec, 48)
            hy_bytes = long_to_bytes(hy_dec, 48)

            uncompressed_h = b'\x04' + hx_bytes + hy_bytes
            uncompressed_h_hex = uncompressed_h.hex()

            enc_results = []   # accumulate per‑node encryption artefacts for later use
            for node_idx, pk_entry in enumerate(public_keys_list):
                # pk_entry might already be a hex string or a dict with X/Y coords
                if isinstance(pk_entry, dict):
                    pkx = long_to_bytes(int(pk_entry["X"]), 48)
                    pky = long_to_bytes(int(pk_entry["Y"]), 48)
                    pk_hex = (b"\x04" + pkx + pky).hex()
                else:
                    pk_hex = pk_entry  # assume uncompressed hex

                # --- fresh randomness per node ---------------------------------
                r_hex = hex(random.getrandbits(256))[2:]
                k_hex = hex(random.getrandbits(256))[2:]

                # --- ElGamal: encrypt g^k under pk ------------------------------
                elg_payload = {
                    "g":  uncompressed_g_hex,  # base point prepared earlier
                    "pk": pk_hex,
                    "r":  r_hex,
                    "k":  k_hex
                }
                ptr_elg = lib_bulletproof.pyElGamalEncrypt(
                    json.dumps(elg_payload).encode("utf-8")
                )
                elg_out = json.loads(string_at(ptr_elg).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_elg)  # free C string

                C1_hex, C2_hex = elg_out["C1"], elg_out["C2"]

                # --- Poseidon symmetric encryption for each share --------------
                # Extract (m, m′) for this node from deser_comandproofwithzero["proofList"]
                node_proofs_full = deser_comandproofwithzero["proofList"][node_idx]
                m_list_node       = [hex(int(p["ClaimedValue"]))[2:]     for p in node_proofs_full]
                m_prime_list_node = [hex(int(p["ClaimedValueAux"]))[2:]  for p in node_proofs_full]

                # --- Compute W = g^m * h^{m'} for this node ---------------------
                payload_W = {
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex,
                    "m": m_list_node,
                    "m_prime": m_prime_list_node
                }
                ptr_W = lib_bulletproof.pyComputeCommitmentGH(json.dumps(payload_W).encode("utf-8"))
                result_W = json.loads(string_at(ptr_W).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_W)
                logging.info("[node %d] result_W: %s", node_idx, result_W)

                W_list_node = []
                for point in result_W:
                    x_hex, y_hex = point.strip("()").split(",")
                    x_bytes = long_to_bytes(int(x_hex, 16), 48)
                    y_bytes = long_to_bytes(int(y_hex, 16), 48)
                    W_uncompressed = b'\x04' + x_bytes + y_bytes
                    W_list_node.append(W_uncompressed.hex())

                cipher_shares = []
                for m_hex, mp_hex in zip(m_list_node, m_prime_list_node):
                    sym_payload = {
                        "pk": pk_hex,
                        "k":  k_hex,
                        "m":  m_hex,
                        "m_prime": mp_hex
                    }
                    ptr_sym = lib_bulletproof.pySymEncrypt(
                        json.dumps(sym_payload).encode("utf-8")
                    )
                    sym_out = json.loads(string_at(ptr_sym).decode("utf-8"))
                    lib_bulletproof.pyFreeString(ptr_sym)
                    cipher_shares.append((sym_out["c"], sym_out["c_prime"]))

                # --- Bulletproof full proof ------------------------------------
                payload_proof = {
                    "g":  uncompressed_g_hex,
                    "h":  uncompressed_h_hex,
                    "pk": pk_hex,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "r":  r_hex,
                    "r_prime": k_hex,
                    "m":  m_list_node,
                    "m_prime": m_prime_list_node,
                    "W":  W_list_node
                }
                ptr_proof = lib_bulletproof.pyProveFull(json.dumps(payload_proof).encode("utf-8"))
                proof_out = json.loads(string_at(ptr_proof).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_proof)
                proof_hex = proof_out["proof"]
                logging.info("[node %d] Bulletproof proof generated (len=%d hex)", node_idx, len(proof_hex))

                # Record everything for this node
                enc_results.append({
                    "node_id": node_idx,
                    "C1": C1_hex,
                    "C2": C2_hex,
                    "cipher_shares": cipher_shares,  # list of (c, c')
                    "W": W_list_node,                # list of uncompressed-hex points
                    "proof": proof_hex               # hex string
                })

            

            # enc_results is now a list you can attach to dispersal_msg_list or log

            logging.info("Per‑node encryption results prepared (len=%d)", len(enc_results))
            # ---- Bundle PV‑Transfer artefacts ---------------------------------
            #
            # We need to ship:
            #   • enc_results           – per‑node ciphertexts, W, proofs
            #   • serialized_commitment – polynomial commitment of all shares
            #   • ser_aggproofAtZero    – aggregated evaluation‑proof at 0
            #   • aggregated_proofList  – γ‑folded proofs per node
            #
            pvtransfer_payload = {
                "enc_results": enc_results,
                "commitment": (
                    serialized_commitment.decode("utf-8")
                    if isinstance(serialized_commitment, (bytes, bytearray))
                    else serialized_commitment
                ),
                "aggProofAtZero": (
                    ser_aggproofAtZero.decode("utf-8")
                    if isinstance(ser_aggproofAtZero, (bytes, bytearray))
                    else ser_aggproofAtZero
                ),
                "aggregated_proofList": [
                    p.decode("utf-8") if isinstance(p, (bytes, bytearray)) else p
                    for p in aggregated_proofList
                ],
            }
            # Store for later use when building dispersal messages
            self.pvtransfer_payload = pvtransfer_payload
            logging.info("PV‑Transfer payload assembled")
            
            # --- Convert dict → dataclass, serialize for RBC / TOB ---
            pv_obj = PVTransferPayload(
                enc_results=[EncResult(**er) for er in enc_results],
                commitment=pvtransfer_payload["commitment"],
                agg_proof_at_zero=pvtransfer_payload["aggProofAtZero"],
                aggregated_proof_list=pvtransfer_payload["aggregated_proofList"],
            )
            # 保存二进制版本，供后续 ΠGather / ΠSelectBlock / TOB 使用
            self.pvtransfer_bytes = pv_obj.to_bytes()
            logging.info(
                "PV-Transfer payload serialised (len=%d bytes)",
                len(self.pvtransfer_bytes),
            )

            # await self._run_local_gather(node_communicator)
            
        if self.mode == "avss_with_batch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            # logger.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed comandproof_right_inputs: {comandproof_right_inputs}")
            # logger.info(f"[dealer {self.my_id}] parsed deser_result: {deser_result}")
            # logger.info(f"[dealer {self.my_id}] parsed proof: {proof}")

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            comandproofwithzero = lib.pyCommitWithZeroFull(
                self.srs_kzg['Pk'],
                serialized_secrets,
                serialized_secrets_aux,
                self.t
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")
            
            # logging.info("serialized_proofAtZero: %s", serialized_proofAtZero)
            # logging.info("serialized_output_shareG: %s", serialized_output_shareG)
            # logging.info("serialized_output_shareH: %s", serialized_output_shareH)

            ab_shareGH = lib.pyComputeShareGH(
                self.srs_kzg['Pk'],
                serialized_left_proof,
                serialized_right_proof
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # logger.info("deser_ab_shareGH: %s", deser_ab_shareGH)
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            # logger.info("serialized_left_shareG: %s", serialized_left_shareG)
            # logger.info("serialized_left_shareH: %s", serialized_left_shareH)
            # logger.info("serialized_right_shareG: %s", serialized_right_shareG)
            # logger.info("serialized_right_shareH: %s", serialized_right_shareH)

        if self.mode == "avss_with_aggbatch_multiplication": 
            if isinstance(values, bytes):
                values_str = values.decode("utf-8")
            else:
                values_str = str(values)

            try:
                combined_obj = json.loads(values_str)
            except json.JSONDecodeError:
                combined_obj = json.loads(values_str.replace("'", '"'))

            comandproof_left_inputs = combined_obj.get("left", {})
            comandproof_right_inputs = combined_obj.get("right", {})
            deser_result = combined_obj.get("result", {})
            proof = combined_obj.get("proof", [])

            # --- keep original commitment and proof (without secret values) ---
            # commiments and evaluation proofs of left inputs
            left_commitment = comandproof_left_inputs.get("commitment", [])
            serialized_left_commitment = json.dumps(left_commitment).encode("utf-8")
            # logging.info("serialized_left_commitment: %s", serialized_left_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_left_inputs.get("proof", [])
            left_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_left_proof = json.dumps(left_proof_no_val).encode("utf-8")
            # logging.info("serialized_left_proof: %s", serialized_left_proof)

            # commiments and evaluation proofs of right inputs
            right_commitment = comandproof_right_inputs.get("commitment", [])
            serialized_right_commitment = json.dumps(right_commitment).encode("utf-8")
            # logging.info("serialized_right_commitment: %s", serialized_right_commitment)

            # strip ClaimedValue / ClaimedValueAux from the original proofs
            proofs_lst = comandproof_right_inputs.get("proof", [])
            right_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
            serialized_right_proof = json.dumps(right_proof_no_val).encode("utf-8")
            # logging.info("serialized_right_proof: %s", serialized_right_proof)

            secrets = deser_result["value"]
            secrets_aux = deser_result["aux"]

            serialized_secrets = json.dumps(secrets).encode('utf-8')
            serialized_secrets_aux = json.dumps(secrets_aux).encode('utf-8')

            serialized_left_proof = json.dumps(comandproof_left_inputs["proof"]).encode('utf-8')
            serialized_right_proof = json.dumps(comandproof_right_inputs["proof"]).encode('utf-8')

            # logging.info(f"[dealer {self.my_id}] parsed comandproof_left_inputs: {comandproof_left_inputs}")

            stage6_mpc_instance = getattr(self, "mpc_instance", None)
            stage6_proof_metric = proof_metadata(
                stage6_mpc_instance, protocol="batchmul",
                operation="ipakzg_generate", dealer_local_id=self.my_id,
                receiver_local_id=None,
                batch_size=len(comandproof_left_inputs.get("proof", [])),
            )
            comandproofwithzero = timed_call(
                stage6_mpc_instance, stage6_proof_metric,
                "output_commitment_preparation",
                lib.pyCommitWithZeroFull, self.srs_kzg['Pk'],
                serialized_secrets, serialized_secrets_aux, self.t,
            )
            # logger.info("comandproofwithzero result: %s", comandproofwithzero)

            deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
            serialized_commitment = json.dumps(
                deser_comandproofwithzero["commitmentList"]
            ).encode("utf-8")
            # logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

            # Populate per‑party proof list
            for i in range(self.n):
                proofandshares.append(
                    json.dumps(deser_comandproofwithzero["proofList"][i]).encode('utf-8')
                )

            # --- extract extra fields we also need to ship ---
            # keep only the curve point H inside each element of proofAtZero
            proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]

            serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
            serialized_output_shareG     = json.dumps(deser_comandproofwithzero.get("shareG", [])).encode("utf-8")
            serialized_output_shareH     = json.dumps(deser_comandproofwithzero.get("shareH", [])).encode("utf-8")

            ab_shareGH = timed_call(
                stage6_mpc_instance, stage6_proof_metric,
                "anchor_share_preparation",
                lib.pyComputeShareGH, self.srs_kzg['Pk'],
                serialized_left_proof, serialized_right_proof,
            )
            deser_ab_shareGH = json.loads(ab_shareGH.decode('utf-8'))
            # --- split and serialize four fields ---
            serialized_left_shareG = json.dumps(deser_ab_shareGH["shareG_left"]).encode("utf-8")
            serialized_left_shareH = json.dumps(deser_ab_shareGH["shareH_left"]).encode("utf-8")
            serialized_right_shareG = json.dumps(deser_ab_shareGH["shareG_right"]).encode("utf-8")
            serialized_right_shareH = json.dumps(deser_ab_shareGH["shareH_right"]).encode("utf-8")

            def _prepare_pedersen_commitments():
                return (
                    lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH),
                    lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH),
                    lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH),
                )

            ser_pedersen_left, ser_pedersen_right, ser_pedersen_output = timed_call(
                stage6_mpc_instance, stage6_proof_metric,
                "pedersen_commitment_preparation",
                _prepare_pedersen_commitments,
            )
            (
                ser_aggleftproof,
                ser_aggrightproof,
                ser_aggproofAtZero,
            ) = _generate_ipakzg_aggregate_witnesses(
                mpc_instance=stage6_mpc_instance,
                proof_metric=stage6_proof_metric,
                dealer_local_id=self.my_id,
                srs_pk=self.srs_kzg["Pk"],
                srs_vk=self.srs_kzg["Vk"],
                left_commitments=serialized_left_commitment,
                right_commitments=serialized_right_commitment,
                output_commitments=serialized_commitment,
                left_pedersen=ser_pedersen_left,
                right_pedersen=ser_pedersen_right,
                output_pedersen=ser_pedersen_output,
                left_openings=comandproof_left_inputs["proof"],
                right_openings=comandproof_right_inputs["proof"],
                output_openings=deser_comandproofwithzero["proofAtZero"],
            )
            finalize_operation(
                stage6_mpc_instance, stage6_proof_metric,
                BATCHMUL_GENERATE_COMPONENTS, success=True,
            )

        
        serialized_ephemeralpublicsecretkey = lib.pyKeyEphemeralGen(self.srs_kzg['Pk'], self.public_keys)
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')

        dispersal_msg_list = [None] * n
        shared_keys = [None] * n
        serialized_publickeys = json.loads(self.public_keys.decode('utf-8'))
        for i in range(n):
            shared_keys[i] = lib.pySharedKeysGen_sender(json.dumps(serialized_publickeys[i]).encode('utf-8'), serialized_ephemeralsecretkey)
            if self.mode == "avss_without_proof":
                z = proofandshares[i]
            if self.mode == "avss_with_proof":
                z = (proofandshares[i], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs)
            if self.mode == "avss_with_transfer":
                z = proofandshares[i]
            if self.mode == "avss_with_aggtransfer":
                z = proofandshares[i]
            if self.mode == "avss_with_batch_multiplication":
                z = (
                    proofandshares[i],
                    serialized_left_commitment,
                    serialized_left_proof, 
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof, 
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof                   
                )
            if self.mode == "avss_with_aggbatch_multiplication":
                z = proofandshares[i]
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), z)



        broadcast_msg = _build_hbacss_broadcast_payload(
            self, serialized_commitment, serialized_ephemeralpublickey,
            locals(),
        )
        _record_hbacss_payload_calibration(
            self, broadcast_msg, dispersal_msg_list, locals()
        )
        return broadcast_msg, dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, dealer_id, tag, dispersal_msg, rbc_msg):
        logging.info("Handling dealer messages for dealer_id: %s, tag: %s", dealer_id, tag)
        all_shares_valid = True
        
        (
            serialized_commitment,
            serialized_ephemeral_public_key,
            transfer_public_payload,
        ) = _parse_hbacss_broadcast_payload(self, rbc_msg)
        
        serialized_private_key = json.loads(json.loads(self.private_key.decode('utf-8')))

        serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeral_public_key, json.dumps(serialized_private_key[f'{dealer_id}']).encode('utf-8'))
        # self.tagvars[tag]['shared_key'] = serialized_sharedkey
        # self.tagvars[tag]['ephemeral_public_key'] = serialized_ephemeral_public_key
        try:
            if self.mode == "avss_without_proof":
                logging.info("Decrypting dispersal message from dealer_id %s", dealer_id)
                serialized_proofandshares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
                # logging.info("Decrypted proofandshares: %s", serialized_proofandshares) 
            if self.mode == "avss_with_proof":
                serialized_proofandshares, serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_transfer":
                noagg_payload = combine_aggtrans_noagg_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = noagg_payload.proof_and_shares
                serialized_original_commitment = noagg_payload.old_commitments
            if self.mode == "avss_with_aggtransfer":
                aggtrans_payload = combine_aggtrans_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = aggtrans_payload.proof_and_shares
                serialized_original_commitment = aggtrans_payload.old_commitments
            if self.mode == "avss_with_batch_multiplication":
                (
                    serialized_proofandshares,
                    serialized_left_commitment,
                    serialized_left_proof,
                    serialized_left_shareG,
                    serialized_left_shareH,
                    serialized_right_commitment,
                    serialized_right_proof,
                    serialized_right_shareG,
                    serialized_right_shareH,
                    serialized_proofAtZero,
                    serialized_output_shareG,
                    serialized_output_shareH,
                    proof
                ) = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_aggbatch_multiplication":
                batchmul_payload = combine_batchmul_payload(
                    SymmetricCrypto.decrypt(
                        str(serialized_sharedkey).encode(), dispersal_msg
                    ),
                    transfer_public_payload,
                )
                serialized_proofandshares = batchmul_payload.proof_and_shares
                serialized_left_commitment = batchmul_payload.left_commitments
                serialized_right_commitment = batchmul_payload.right_commitments
                ser_aggleftproof = batchmul_payload.left_witness
                ser_aggrightproof = batchmul_payload.right_witness
                ser_aggproofAtZero = batchmul_payload.output_witness
                ser_pedersen_left = batchmul_payload.left_pedersen
                ser_pedersen_right = batchmul_payload.right_pedersen
                ser_pedersen_output = batchmul_payload.output_pedersen
                proof = batchmul_payload.factor_proof

                # # --- reconstruct two public proof‑and‑share lists ---
                # # 1) evaluation at x = i      (original proof)
                # # 2) evaluation at x = 0      (proofAtZero)
                # #
                # # Each element becomes {"H": ..., "G": shareG[i], "HClaim": shareH[i]}
                # #
                # deser_orig_proof = json.loads(serialized_original_proof.decode("utf-8"))
                # deser_P0         = json.loads(serialized_proofAtZero.decode("utf-8"))
                # deser_G          = json.loads(serialized_shareG.decode("utf-8"))
                # deser_H          = json.loads(serialized_shareH.decode("utf-8"))

                # # helper to fuse H, G, Ĥ
                # def _fuse(H_arr, G_arr, Hhat_arr):
                #     fused = []
                #     for idx in range(len(H_arr)):
                #         fused.append({
                #             "H": H_arr[idx]["H"],
                #             "GClaim": G_arr[idx],
                #             "HClaim": Hhat_arr[idx]
                #         })
                #     return fused

                # fused_proof_and_shares      = _fuse(deser_orig_proof, deser_G, deser_H)
                # fused_proofanzero_andshares = _fuse(deser_P0, deser_G, deser_H)

                # logging.info("fused_proof_and_shares: %s", fused_proof_and_shares)
                # logging.info("fused_proofanzero_andshares: %s", fused_proofanzero_andshares)

                # serialized_proofandshares_pub      = json.dumps(fused_proof_and_shares).encode("utf-8")
                # serialized_proofandshares_zero_pub = json.dumps(fused_proofanzero_andshares).encode("utf-8")
                
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
         
         
        if all_shares_valid:
            if self.mode == "avss_without_proof":
                if lib.pyBatchVerify(self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    logging.info("shares verification FAILED")
                    all_shares_valid = False
            if self.mode == "avss_with_proof":
                if lib.pyBatchVerify(
                    self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                    ) == int(1) and lib.pyBatchhiddenverify(self.srs_kzg['Vk'], 
                    self.tagvars[tag]['committment_ab'], serialized_zkProof_ab, dealer_id) == int(1) and lib.pyBatchhiddenzeroverify(self.srs_kzg['Vk'], 
                    serialized_commitment, serialized_zkProof_c_zero) == int(1) and lib.pyProdverify(
                    self.srs_kzg['Vk'], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs) == int(1):
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    return False
            if self.mode == "avss_with_transfer":
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans-noagg",
                    operation="batch_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_original_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, proof_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                old_anchor_valid, fresh_zero_valid = (
                    _verify_aggtrans_noagg_relations(
                        mpc_instance=mpc_instance,
                        proof_metric=proof_metric,
                        dealer_local_id=dealer_id,
                        srs_vk=self.srs_kzg['Vk'],
                        old_commitments=serialized_original_commitment,
                        fresh_commitments=serialized_commitment,
                        old_witnesses=noagg_payload.old_witnesses,
                        fresh_witnesses=noagg_payload.fresh_witnesses,
                        pedersen=noagg_payload.pedersen,
                    )
                )
                finalize_operation(
                    mpc_instance, proof_metric,
                    AGGTRANS_NOAGG_VERIFY_COMPONENTS,
                    success=(
                        bacss_share_valid
                        and old_anchor_valid
                        and fresh_zero_valid
                    ),
                )
                if bacss_share_valid and old_anchor_valid and fresh_zero_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_aggtransfer":
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans",
                    operation="aggpub_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_commitment.decode("utf-8"))),
                )
                proof_metric.update(aggtrans_proof_size_metadata(
                    self.agg_kzg_mode, v2=aggtrans_payload.v2,
                    legacy=aggtrans_payload.legacy,
                ))
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="aggtrans",
                    operation="aggtrans_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(json.loads(serialized_commitment.decode("utf-8"))),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    AGGTRANS_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                component = (
                    "legacy_aggpub_verify"
                    if self.agg_kzg_mode == "legacy" else "aggpub_verify"
                )
                aggtrans_verification = timed_call(
                    mpc_instance, proof_metric, component,
                    lambda: verify_aggtrans(
                        self.agg_kzg_mode, library=lib,
                        srs_pk=self.srs_kzg['Pk'],
                        srs_vk=self.srs_kzg['Vk'],
                        dealer_local_id=dealer_id,
                        receiver_local_id=self.my_id,
                        fresh_commitments=serialized_commitment,
                        payload=aggtrans_payload,
                    ),
                    success=lambda result: result.accepted,
                )
                fresh_zero_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.fresh_zero_valid
                )
                old_anchor_valid = (
                    aggtrans_verification.pok_ped_valid
                    and aggtrans_verification.old_anchor_valid
                )
                finalize_operation(
                    mpc_instance, proof_metric,
                    aggtrans_verify_components(self.agg_kzg_mode),
                    success=fresh_zero_valid and old_anchor_valid,
                )
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_aggtrans_verification(
                        dealer_local_id=dealer_id,
                        bacss_share_valid=bacss_share_valid,
                        fresh_zero_valid=fresh_zero_valid,
                        old_anchor_valid=old_anchor_valid,
                    )

                if bacss_share_valid and fresh_zero_valid and old_anchor_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['original_commitments'] = serialized_original_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_aggbatch_multiplication":
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left_list = json.loads(ser_pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(ser_pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(ser_pedersen_output.decode("utf-8"))
                mpc_instance = getattr(self, "mpc_instance", None)
                proof_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="ipakzg_verify", dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                def _verify_factor_proof():
                    result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                    try:
                        result_json = string_at(result_ptr).decode("utf-8")
                        logger.info("verifier_result_json: %s", result_json)
                        return bool(json.loads(result_json).get("verified", False))
                    finally:
                        lib_bulletproof.pyFreeString(result_ptr)

                product_proof_valid = timed_call(
                    mpc_instance, proof_metric, "factor_verify",
                    _verify_factor_proof, success=bool,
                )
                bacss_metric = proof_metadata(
                    mpc_instance, protocol="batchmul",
                    operation="batchmul_bacss_verify",
                    dealer_local_id=dealer_id,
                    receiver_local_id=self.my_id,
                    batch_size=len(pedersen_left_list),
                )
                bacss_share_valid = timed_call(
                    mpc_instance, bacss_metric, "evaluation_proof_verify",
                    lib.pyBatchVerify, self.srs_kzg['Vk'],
                    serialized_commitment, serialized_proofandshares, self.my_id,
                    success=lambda result: result == int(1),
                ) == int(1)
                finalize_operation(
                    mpc_instance, bacss_metric,
                    BATCHMUL_BACSS_VERIFY_COMPONENTS,
                    success=bacss_share_valid,
                )
                (
                    left_anchor_valid,
                    right_anchor_valid,
                    output_zero_valid,
                ) = _verify_ipakzg_aggregate_relations(
                    mpc_instance=mpc_instance,
                    proof_metric=proof_metric,
                    dealer_local_id=dealer_id,
                    srs_pk=self.srs_kzg["Pk"],
                    srs_vk=self.srs_kzg["Vk"],
                    left_commitments=serialized_left_commitment,
                    right_commitments=serialized_right_commitment,
                    output_commitments=serialized_commitment,
                    left_pedersen=ser_pedersen_left,
                    right_pedersen=ser_pedersen_right,
                    output_pedersen=ser_pedersen_output,
                    left_witness=ser_aggleftproof,
                    right_witness=ser_aggrightproof,
                    output_witness=ser_aggproofAtZero,
                )
                proof_valid = (
                    product_proof_valid and left_anchor_valid
                    and right_anchor_valid and output_zero_valid
                )
                finalize_operation(
                    mpc_instance, proof_metric, BATCHMUL_VERIFY_COMPONENTS,
                    success=proof_valid,
                )
                fault_controller = getattr(mpc_instance, "fault_controller", None)
                if fault_controller is not None:
                    fault_controller.record_batchmul_verification(
                        dealer_local_id=dealer_id,
                        product_proof_valid=product_proof_valid,
                        bacss_share_valid=bacss_share_valid,
                        left_anchor_valid=left_anchor_valid,
                        right_anchor_valid=right_anchor_valid,
                        output_zero_valid=output_zero_valid,
                    )
                if proof_valid and bacss_share_valid:
                    logging.info("shares verified successfully")
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                    self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                    self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                else:
                    logging.info("shares verification FAILED")
                    return False
            if self.mode == "avss_with_batch_multiplication":
                # === generate g^p h^r commitment ===
                logger.info("[PedersenCommit] invoking pyPedersenCommit...")

                pedersen_left = lib.pyPedersenCombine(serialized_left_shareG, serialized_left_shareH)
                pedersen_right = lib.pyPedersenCombine(serialized_right_shareG, serialized_right_shareH)
                pedersen_out = lib.pyPedersenCombine(serialized_output_shareG, serialized_output_shareH)

                # logger.info("pedersen_left: %s", pedersen_left)
                # logger.info("pedersen_right: %s", pedersen_right)
                # logger.info("pedersen_out: %s", pedersen_out)

                pedersen_left_list = json.loads(pedersen_left.decode("utf-8"))
                pedersen_right_list = json.loads(pedersen_right.decode("utf-8"))
                pedersen_out_list = json.loads(pedersen_out.decode("utf-8"))

                pedersen_com = []
                for i in range(len(pedersen_left_list)):
                    pedersen_com.append(pedersen_left_list[i])
                    pedersen_com.append(pedersen_right_list[i])
                    pedersen_com.append(pedersen_out_list[i])

                commitment_strs = [
                    f"({int(p['X']):096X},{int(p['Y']):096X})" for p in pedersen_com
                ]

                # logger.info("pedersen commitments: %s", commitment_strs)

                pk_dict = json.loads(self.srs_kzg["Pk"].decode("utf-8"))
                g0 = pk_dict["G1_g"][0]
                h0 = pk_dict["G1_h"][0]

                # read G1_g[0] X/Y 
                gx_dec = int(g0["X"])
                gy_dec = int(g0["Y"])

                # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
                # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

                gx_bytes = long_to_bytes(gx_dec, 48)
                gy_bytes = long_to_bytes(gy_dec, 48)

                uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
                uncompressed_g_hex = uncompressed_g.hex()
                # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

                # add h0
                hx_dec = int(h0["X"])
                hy_dec = int(h0["Y"])

                # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
                # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

                hx_bytes = long_to_bytes(hx_dec, 48)
                hy_bytes = long_to_bytes(hy_dec, 48)

                uncompressed_h = b'\x04' + hx_bytes + hy_bytes
                uncompressed_h_hex = uncompressed_h.hex()
                # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())
                
                verifier_input = {
                    "proof": proof,
                    "commitments": commitment_strs,
                    "g": uncompressed_g_hex,
                    "h": uncompressed_h_hex
                }

                # verify inner product
                verifier_json = json.dumps(verifier_input).encode("utf-8")
                verifier_result_ptr = lib_bulletproof.pyVerifyFactors(verifier_json)
                verifier_result_json = string_at(verifier_result_ptr).decode("utf-8")

                logger.info("verifier_result_json: %s", verifier_result_json)
                lib_bulletproof.pyFreeString(verifier_result_ptr)

                # Add check for verification result
                if json.loads(verifier_result_json).get("verified", False):
                    logging.info("inner product verified successfully")
                    if lib.pyBatchVerify(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                        ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_left_commitment, serialized_left_proof, serialized_left_shareG, serialized_left_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_right_commitment, serialized_right_proof, serialized_right_shareG, serialized_right_shareH, dealer_id
                    ) == int(1) and lib.pyBatchVerifyPub(
                        self.srs_kzg['Vk'], serialized_commitment, serialized_proofAtZero, serialized_output_shareG, serialized_output_shareH, -1
                    ) == int(1):
                        logging.info("shares verified successfully")
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                        self.tagvars[tag]['left_commitments'] = serialized_left_commitment
                        self.tagvars[tag]['right_commitments'] = serialized_right_commitment
                    else:
                        logging.info("shares verification FAILED")
                        return False
                else:
                    logging.info("inner product verification FAILED")
                    return False

        logging.info("all_shares_valid: %s", all_shares_valid)
        return all_shares_valid

    #@profile
    async def avss(self, avss_id, shares_num, coms=None, values=None, dealer_id=None, client_mode=False):
        
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        # if values is not None:
        #     if dealer_id is None:
        #         dealer_id = self.my_id
        #     assert dealer_id == self.my_id, "Only dealer can share values."
        # # If `values` is not passed then the node is a 'Recipient'
        # # Verify that the `dealer_id` is not the same as `self.my_id`
        # elif dealer_id is not None:
        #     assert dealer_id != self.my_id
        # if client_mode:
        #     assert dealer_id is not None
        #     assert dealer_id == self.n
        # assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )
        logging.info("[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
                     self.my_id, avss_id, dealer_id, client_mode)
        
        self.shares_num = shares_num
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        logging.info("[%d] AVSS tag: %s", self.my_id, acsstag)
        logging.info("[%d] RBC tag: %s", self.my_id, rbctag)

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []
        if self.mode == "avss_with_proof":
            self.tagvars[acsstag]['committment_ab'] = coms
            

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None

        logging.info("[%d] Starting AVSS with shares_num: %d, dealer_id: %d, client_mode: %s",
                     self.my_id, shares_num, dealer_id, client_mode)    
        

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
            
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        if self.my_id < dealer_id:
            rbc_msg = await rbc_dyn(
                rbctag,
                self.my_id,
                n+1,
                self.t,
                dealer_id,
                broadcast_msg,
                recv,
                send,
                member_list,
                n
            )  
        else: 
            rbc_msg = await rbc_dyn(
                rbctag,
                self.my_id+1,
                n+1,
                self.t,
                dealer_id,
                broadcast_msg,
                recv,
                send,
                member_list,
                n
            )  
        logging.info("[%d] Received RBC message", self.my_id)


        avidtag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVID"
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue, dealer_id))
        
        send, recv = self.get_send(avidtag), self.subscribe_recv(avidtag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid_dyn = AVID_DYNAMIC(n+1, self.t, dealer_id, recv, send, n, member_list)
        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid_dyn, avidtag, dispersal_msg_list))
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid_dyn)


class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # ls = len(self.tagvars[tag]['commitments']) // (self.t + 1)
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['finished_interpolating_commits']:
        #     all_commits = [ [] for l in range(ls)]
        #     for l in range(ls):
        #         known_commits = self.tagvars[tag]['commitments'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #         known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
        #         # line 502
        #         interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
        #         #interpolated_commits = known_commits + known_commits + known_commits
        #         all_commits[l] = known_commits + interpolated_commits
        #     self.tagvars[tag]['all_commits'] = all_commits
        #     self.tagvars[tag]['finished_interpolating_commits'] = True

        #     #init some variables we'll need later
        #     self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
        #     self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
        #     self.tagvars[tag]['r1_aux_coords_l'] = [[] for l in range(ls)]
        #     self.tagvars[tag]['r2_aux_coords_l'] = [[] for l in range(ls)]
        #     self.tagvars[tag]['sent_r2'] = False
        #     self.tagvars[tag]['r1_set'] = set()
        #     self.tagvars[tag]['r2_set'] = set()
            
        #     if self.tagvars[tag]['all_shares_valid']:
        #         logger.debug("[%d] prev sent r1", self.my_id)
        #         all_evalproofs = [ [] for l in range(ls)]
        #         all_points = [ [] for l in range(ls)]
        #         all_aux_points = [[] for l in range(ls)]
        #         for l in range(ls):
        #             # the proofs for the specific shares held by this node
        #             known_evalproofs = self.tagvars[tag]['witnesses'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
        #             # line 504
        #             interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
        #                                     range(self.t + 1, self.n)]
        #             #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
        #             all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
        #             # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
        #             known_points = self.tagvars[tag]['shares'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
        #             mypoly = self.poly.interpolate(known_point_coords)
        #             interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
        #             all_points[l] = known_points + interpolated_points

        #             #auxes
        #             known_auxes = self.tagvars[tag]['auxes'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_aux_coords = [[i + 1, known_auxes[i]] for i in range(self.t + 1)]
        #             my_aux_poly = self.poly.interpolate(known_aux_coords)
        #             interpolated_aux_points = [my_aux_poly(i + 1) for i in range(self.t + 1, self.n)]
        #             all_aux_points[l] = known_auxes + interpolated_aux_points


        #         logger.debug("[%d] in between r1", self.my_id)
        #         # lines 505-506
        #         for j in range(self.n):
        #             send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)] , [ all_aux_points[l][j] for l in range(ls)], [all_evalproofs[l][j] for l in range(ls)]))
        #         logger.debug("[%d] sent r1", self.my_id)

        # if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
        #     logger.debug("[%d] prev sent r2", self.my_id)
        #     _, points, aux_points, proofs = avss_msg
        #     all_commits = self.tagvars[tag]['all_commits']
        #     if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, aux_points, proofs):
        #         if sender not in self.tagvars[tag]['r1_set']:
        #             self.tagvars[tag]['r1_set'].add(sender)
        #             for l in range(ls):
        #                 self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
        #                 self.tagvars[tag]['r1_aux_coords_l'][l].append([sender, aux_points[l]])
        #             #r1_coords.append([sender, point])
        #         if len(self.tagvars[tag]['r1_set']) == self.t + 1:
        #             #r1_poly = self.poly.interpolate(r1_coords)
        #             r1_poly_l = [ [] for l in range(ls)]
        #             r1_aux_poly_l = [[] for l in range(ls)]
        #             for l in range(ls):
        #                 r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
        #                 r1_aux_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_aux_coords_l'][l])
        #             for j in range(self.n):
        #                 r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
        #                 r1_aux_points_j = [r1_aux_poly_l[l](j) for l in range(ls)]
        #                 #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
        #                 send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j, r1_aux_points_j))
        #             self.tagvars[tag]['sent_r2'] = True
        #             logger.debug("[%d] sent r2", self.my_id)

        # if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
        #     _, points, aux_points = avss_msg
        #     if sender not in self.tagvars[tag]['r2_set']:
        #         self.tagvars[tag]['r2_set'].add(sender)
        #         #r2_coords.append([sender, point])
        #         for l in range(ls):
        #             self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
        #             self.tagvars[tag]['r2_aux_coords_l'][l].append([sender, aux_points[l]])
        #     if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
        #         # todo, replace with robust interpolate that takes at least 2t+1 values
        #         # this will still interpolate the correct degree t polynomial if all points are correct
        #         r2_poly_l = [ [] for l in range(ls)]
        #         r2_aux_poly_l = [[] for l in range(ls)]
        #         shares = []
        #         auxes = []
        #         for l in range(ls):
        #             r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
        #             shares += [r2_poly(i) for i in range(self.t + 1)]
        #             r2_aux_poly = self.poly.interpolate(self.tagvars[tag]['r2_aux_coords_l'][l])
        #             auxes += [r2_aux_poly(i) for i in range(self.t + 1)]
        #         multicast((HbAVSSMessageType.OK, ""))

        #         self.tagvars[tag]['all_shares_valid'] = True
        #         self.tagvars[tag]['shares'] = shares
        #         self.tagvars[tag]['auxes'] = auxes
