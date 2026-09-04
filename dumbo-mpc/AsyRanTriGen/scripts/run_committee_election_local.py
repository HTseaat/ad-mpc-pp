"""Robust local multiprocess launcher for the standalone election benchmark."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from scripts.analyze_committee_election import analyze, load_metrics
from scripts.run_committee_election import FINISHED_MARKER
from scripts.setup_committee_election import generate_configs


def _has_finished_marker(log_path):
    try:
        with open(log_path, encoding="utf-8") as log_file:
            return any(line.rstrip("\n") == FINISHED_MARKER for line in log_file)
    except FileNotFoundError:
        return False


def run_local(*, n, t, candidate_count, base_port, output_dir, omitted, timeout):
    output_path = Path(output_dir).resolve()
    if output_path.exists() and any(output_path.iterdir()):
        raise ValueError(f"output directory is not empty: {output_path}")
    config_dir = output_path / "config"
    log_dir = output_path / "logs"
    config_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    config_paths = generate_configs(
        n=n,
        t=t,
        candidate_count=candidate_count,
        base_port=base_port,
        output_dir=str(config_dir),
    )
    project_dir = Path(__file__).resolve().parents[1]
    cleanup = project_dir / "scripts" / "cleanup_local_test.sh"
    subprocess.run(
        [str(cleanup), str(n), str(base_port), "1"],
        cwd=str(project_dir),
        check=True,
    )
    environment = dict(os.environ)
    environment["ZMQ_AUTH_MODE"] = "curve"
    environment["COMMITTEE_ELECTION_TIMEOUT_SECONDS"] = str(timeout)
    if omitted is not None:
        environment["COMMITTEE_ELECTION_OMIT_LOCAL_ID"] = str(omitted)
    processes = []
    log_files = []
    log_paths = []
    started_at = time.monotonic()
    try:
        for node_id, config_path in enumerate(config_paths):
            log_path = log_dir / f"node-{node_id}.log"
            log_file = open(log_path, "w", encoding="utf-8")
            log_files.append(log_file)
            log_paths.append(log_path)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    "-m",
                    "scripts.run_committee_election",
                    "-d",
                    "-f",
                    config_path,
                ],
                cwd=str(project_dir),
                env=environment,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            processes.append(process)
        deadline = time.monotonic() + timeout + 15.0
        protocol_finished = False
        while True:
            if all(_has_finished_marker(log_path) for log_path in log_paths):
                protocol_finished = True
                break
            if not any(process.poll() is None for process in processes):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("local election launcher exceeded its deadline")
            failed = [
                (node_id, process.returncode)
                for node_id, process in enumerate(processes)
                if process.poll() not in (None, 0)
            ]
            if failed:
                raise RuntimeError(f"committee-election process failure: {failed}")
            time.sleep(0.05)
        if not protocol_finished:
            protocol_finished = all(
                _has_finished_marker(log_path) for log_path in log_paths
            )
        if not protocol_finished:
            failures = [
                (node_id, process.returncode)
                for node_id, process in enumerate(processes)
                if process.returncode != 0
            ]
            if failures:
                raise RuntimeError(f"committee-election process failure: {failures}")
            raise RuntimeError("committee-election processes exited without completion")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log_file in log_files:
            log_file.close()
    summary = analyze(load_metrics(str(log_dir), n))
    summary["launcher_elapsed_ms"] = (time.monotonic() - started_at) * 1000.0
    summary["omitted_local_id"] = omitted
    summary_path = output_path / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=2, sort_keys=True)
        summary_file.write("\n")
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--N", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--K", type=int, default=4)
    parser.add_argument("--base-port", type=int, default=12000)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--omit", type=int)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.omit is not None and not 0 <= args.omit < args.N:
        parser.error("--omit must identify a configured party")
    summary = run_local(
        n=args.N,
        t=args.t,
        candidate_count=args.K,
        base_port=args.base_port,
        output_dir=args.output_dir,
        omitted=args.omit,
        timeout=args.timeout,
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
