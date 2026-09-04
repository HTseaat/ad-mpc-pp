"""Canonical parameters and local committee configuration for stages 1--5."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple


CONFIG_SCHEMA = 1
PROTOCOL_NAME = "continuum-trusted-setup-single-chain"
SUPPORTED_CURVE = "BLS12-381"


class ParameterError(ValueError):
    """A setup parameter is invalid or unsupported by the current stage."""


class ConfigMismatchError(ValueError):
    """Committee node configurations do not describe exactly the same run."""


def _require_plain_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParameterError(f"{name} must be an integer")
    return value


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _next_power_of_two(value: int) -> int:
    return 1 << (value - 1).bit_length()


@dataclass(frozen=True)
class SetupParams:
    n: int
    t: int
    requested_powers: int
    effective_powers: int
    log_q: int
    curve: str
    run_id: str

    @classmethod
    def create(
        cls,
        n: int,
        t: int,
        requested_powers: int,
        *,
        curve: str = SUPPORTED_CURVE,
        run_id: Optional[str] = None,
    ) -> "SetupParams":
        n = _require_plain_int("n", n)
        t = _require_plain_int("t", t)
        requested_powers = _require_plain_int(
            "requested_powers", requested_powers
        )
        run_id = uuid.uuid4().hex if run_id is None else run_id

        if n < 1:
            raise ParameterError("n must be positive")
        if t < 1:
            raise ParameterError("t must be at least 1")
        if n < 3 * t + 1:
            raise ParameterError("n must satisfy n >= 3*t + 1")
        if requested_powers < 2:
            raise ParameterError("requested_powers must be at least 2")
        if requested_powers < t + 1:
            raise ParameterError("requested_powers must be at least t + 1")
        if not _is_power_of_two(n):
            raise ParameterError(
                "the current adapter requires n to be a power of two for the upstream NTT"
            )
        if curve != SUPPORTED_CURVE:
            raise ParameterError(
                f"unsupported curve {curve!r}; expected {SUPPORTED_CURVE}"
            )
        if not isinstance(run_id, str) or not run_id.strip():
            raise ParameterError("run_id must be a non-empty string")

        effective_powers = _next_power_of_two(requested_powers)
        log_q = effective_powers.bit_length() - 1
        return cls(
            n=n,
            t=t,
            requested_powers=requested_powers,
            effective_powers=effective_powers,
            log_q=log_q,
            curve=curve,
            run_id=run_id,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SetupParams":
        try:
            params = cls.create(
                data["n"],
                data["t"],
                data["requested_powers"],
                curve=data.get("curve", SUPPORTED_CURVE),
                run_id=data["run_id"],
            )
        except KeyError as exc:
            raise ParameterError(f"missing setup parameter: {exc.args[0]}") from exc

        for derived_name in ("effective_powers", "log_q"):
            if derived_name in data and data[derived_name] != getattr(
                params, derived_name
            ):
                raise ParameterError(
                    f"serialized {derived_name} does not match the derived value"
                )
        return params

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def identity(self) -> Tuple[Any, ...]:
        return (
            self.n,
            self.t,
            self.requested_powers,
            self.effective_powers,
            self.log_q,
            self.curve,
            self.run_id,
        )


def _committee_digest(params: SetupParams, peers: Sequence[str]) -> str:
    payload = {
        "params": params.as_dict(),
        "peers": list(peers),
        "protocol": PROTOCOL_NAME,
        "schema": CONFIG_SCHEMA,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class NodeConfig:
    params: SetupParams
    node_id: int
    peers: Tuple[str, ...]
    committee_digest: str

    @classmethod
    def create(
        cls, params: SetupParams, node_id: int, peers: Sequence[str]
    ) -> "NodeConfig":
        node_id = _require_plain_int("node_id", node_id)
        peers = tuple(peers)
        if not 0 <= node_id < params.n:
            raise ParameterError("node_id must satisfy 0 <= node_id < n")
        if len(peers) != params.n:
            raise ParameterError("the peer list length must equal n")
        if any(not isinstance(peer, str) or not peer.strip() for peer in peers):
            raise ParameterError("every peer entry must be a non-empty string")
        if len(set(peers)) != len(peers):
            raise ParameterError("peer entries must be unique")
        return cls(
            params=params,
            node_id=node_id,
            peers=peers,
            committee_digest=_committee_digest(params, peers),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NodeConfig":
        if data.get("schema") != CONFIG_SCHEMA:
            raise ConfigMismatchError("unsupported node-config schema")
        if data.get("protocol") != PROTOCOL_NAME:
            raise ConfigMismatchError("unexpected protocol name")
        try:
            config = cls.create(
                SetupParams.from_dict(data["params"]),
                data["node_id"],
                data["peers"],
            )
        except KeyError as exc:
            raise ConfigMismatchError(
                f"missing node-config field: {exc.args[0]}"
            ) from exc
        if data.get("committee_digest") != config.committee_digest:
            raise ConfigMismatchError("committee digest mismatch")
        return config

    def as_dict(self) -> dict:
        return {
            "schema": CONFIG_SCHEMA,
            "protocol": PROTOCOL_NAME,
            "params": self.params.as_dict(),
            "node_id": self.node_id,
            "peers": list(self.peers),
            "committee_digest": self.committee_digest,
        }


def write_local_configs(
    params: SetupParams,
    output_dir: Path,
    *,
    host: str = "127.0.0.1",
    base_port: int = 17000,
    force: bool = False,
) -> Tuple[Path, ...]:
    output_dir = Path(output_dir)
    base_port = _require_plain_int("base_port", base_port)
    if not 1 <= base_port <= 65535 or base_port + params.n - 1 > 65535:
        raise ParameterError("base_port range does not fit all committee nodes")
    if not host.strip():
        raise ParameterError("host must be non-empty")

    output_dir.mkdir(parents=True, exist_ok=True)
    peers = tuple(f"{host}:{base_port + node_id}" for node_id in range(params.n))
    paths = []
    for node_id in range(params.n):
        path = output_dir / f"local.{node_id}.json"
        if path.exists() and not force:
            raise FileExistsError(f"refusing to overwrite {path}")
        config = NodeConfig.create(params, node_id, peers)
        path.write_text(
            json.dumps(config.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        paths.append(path)
    return tuple(paths)


def load_committee_configs(paths: Iterable[Path]) -> Tuple[NodeConfig, ...]:
    configs = []
    for path in paths:
        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigMismatchError(f"cannot load {path}: {exc}") from exc
        configs.append(NodeConfig.from_dict(data))

    if not configs:
        raise ConfigMismatchError("no node configurations supplied")
    expected = configs[0]
    if len(configs) != expected.params.n:
        raise ConfigMismatchError("the number of node configs must equal n")
    if {config.node_id for config in configs} != set(range(expected.params.n)):
        raise ConfigMismatchError("node IDs must be exactly 0..n-1")

    for config in configs[1:]:
        if config.params != expected.params:
            raise ConfigMismatchError("nodes disagree on setup parameters")
        if config.peers != expected.peers:
            raise ConfigMismatchError("nodes disagree on the peer list")
        if config.committee_digest != expected.committee_digest:
            raise ConfigMismatchError("nodes disagree on the committee digest")
    return tuple(sorted(configs, key=lambda config: config.node_id))


def load_committee_config_dir(directory: Path) -> Tuple[NodeConfig, ...]:
    directory = Path(directory)
    return load_committee_configs(sorted(directory.glob("local.*.json")))
