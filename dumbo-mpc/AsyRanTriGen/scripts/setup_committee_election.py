"""Generate standalone committee-election TBLS and CURVE configurations."""

import argparse
import base64
import hashlib
import json
import os
import pickle
import uuid

import zmq

from beaver.broadcast.crypto.boldyreva import dealer
from committee_election.model import (
    CandidateCommittee,
    CandidateRegistry,
    CommitteeMember,
)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_standalone_registry(
    *, run_id, n, candidate_count, base_port, peer_ips=None
):
    candidates = []
    for candidate_index in range(candidate_count):
        members = []
        for local_id in range(n):
            global_party_id = candidate_index * n + local_id
            label = f"{run_id}:candidate:{candidate_index}:member:{local_id}"
            if peer_ips is None:
                endpoint_id = f"localhost:{base_port + n + global_party_id}"
            else:
                endpoint_id = f"{peer_ips[local_id]}:{base_port + 1 + candidate_index}"
            members.append(
                CommitteeMember(
                    global_party_id=global_party_id,
                    endpoint_id=endpoint_id,
                    authenticated_identity_digest=_digest(label + ":auth"),
                    protocol_public_key_digest=_digest(label + ":protocol-key"),
                )
            )
        candidates.append(
            CandidateCommittee(
                committee_id=f"candidate-{candidate_index:02d}",
                members=tuple(members),
            )
        )
    return CandidateRegistry(
        registry_id=f"standalone-{run_id}",
        committee_size=n,
        candidates=tuple(candidates),
    )


def generate_configs(
    *, n, t, candidate_count, base_port, output_dir, run_id=None, peer_ips=None
):
    if n < 3 * t + 1:
        raise ValueError("n must satisfy n >= 3*t+1")
    if candidate_count < 1:
        raise ValueError("candidate_count must be positive")
    if peer_ips is not None and len(peer_ips) != n:
        raise ValueError(f"peer_ips must contain exactly n={n} addresses")
    if not 1024 <= base_port <= 65535 - (candidate_count + 1) * n:
        raise ValueError("base_port does not leave room for the registry endpoints")
    run_id = run_id or uuid.uuid4().hex
    os.makedirs(output_dir, exist_ok=True)
    if peer_ips is None:
        peers = [f"localhost:{base_port + node_id}" for node_id in range(n)]
    else:
        peers = [f"{peer_ips[node_id]}:{base_port}" for node_id in range(n)]
    curve_keypairs = [zmq.curve_keypair() for _ in range(n)]
    curve_public_keys = [pair[0].decode("ascii") for pair in curve_keypairs]
    public_key, private_keys = dealer(n, t + 1)
    public_key_b64 = base64.b64encode(pickle.dumps(public_key)).decode("ascii")
    private_key_b64s = [
        base64.b64encode(pickle.dumps(private_key)).decode("ascii")
        for private_key in private_keys
    ]
    registry = build_standalone_registry(
        run_id=run_id,
        n=n,
        candidate_count=candidate_count,
        base_port=base_port,
        peer_ips=peer_ips,
    )
    paths = []
    for node_id in range(n):
        path = os.path.join(output_dir, f"local.{node_id}.json")
        value = {
            "N": n,
            "layers": 1,
            "my_id": node_id,
            "my_send_id": node_id,
            "peers": peers,
            "t": t,
            "total_cm": 0,
            "extra": {
                "curve_public_key": curve_public_keys[node_id],
                "curve_public_keys": curve_public_keys,
                "curve_secret_key": curve_keypairs[node_id][1].decode("ascii"),
                "curve_zap_domain": "continuum-election-v1",
                "election_registry": registry.to_dict(),
                "private_key": private_key_b64s[node_id],
                "public_key": public_key_b64,
                "run_id": run_id,
            },
        }
        with open(path, "w", encoding="utf-8") as config_file:
            json.dump(value, config_file, indent=2, sort_keys=True)
            config_file.write("\n")
        paths.append(path)
    return paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--N", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--K", type=int, required=True)
    parser.add_argument("--base-port", type=int, default=12000)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-id")
    parser.add_argument(
        "--ip-file",
        help="distributed mode: exactly N server IPs; all servers bind --base-port",
    )
    args = parser.parse_args()
    peer_ips = None
    if args.ip_file:
        with open(args.ip_file, encoding="utf-8") as ip_file:
            peer_ips = [line.strip() for line in ip_file if line.strip()]
        if len(peer_ips) < args.N:
            parser.error(f"--ip-file contains fewer than N={args.N} addresses")
        peer_ips = peer_ips[:args.N]
    paths = generate_configs(
        n=args.N,
        t=args.t,
        candidate_count=args.K,
        base_port=args.base_port,
        output_dir=args.output_dir,
        run_id=args.run_id,
        peer_ips=peer_ips,
    )
    print(json.dumps({"config_count": len(paths), "output_dir": args.output_dir}))


if __name__ == "__main__":
    main()
