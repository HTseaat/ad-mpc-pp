"""
Asynchronous Common Subset (ACS) – *YOSO‑style sketch*

This module glues together **n** parallel Yoso‑RBC instances and (in the
future) a Binary Agreement (ABA) layer to agree on one RBC output set.
For a first workable prototype we keep things *minimal*:

    •   We instantiate an **RBC_i** for *every* node `i ∈ {0 … n‑1}`.
        Each instance is given a *unique* tag‑prefix `"RBC<i>|"` so their
        message spaces are disjoint on the transport.

    •   Each node locally proposes a value `v` via its own RBC instance
        and simultaneously listens for the outputs of **all** instances.

    •   Once at least **N − t** RBCs have *delivered*, every node outputs
        *exactly that set* (the rest are filled with ⊥) — this matches the
        common‑subset property provided all honest nodes eventually reach
        the same threshold.  A full production ACS would additionally run
        *asynchronous binary agreement* on the “delivery‑bitmap” to ensure
        identical views; wiring an ABA in is left as a TODO.

The code follows the same coroutine pattern as `yosorbc.py`:

        • `YosoACS.submit(value)`   – called *once* by every node
        • `YosoACS.reactor()`       – single long‑running task per node
        • `YosoACS.output_queue`    – (`set_of_values`, bitmap)

The transport (`send`, `recv`) is exactly the same wrapper pair used by
YosoRBC so that the two layers can share the same underlying messenger.
"""
import asyncio
import logging
import json
from typing import List, Dict, Set, Tuple, Optional, Callable

from beaver.yosorbc import YosoRBC        # reuse the RBC we already have
from beaver.utils.misc import wrap_send, subscribe_recv


# ---------------------------------------------------------------------------
#  Helper: build a *tag‑prefixed* send / recv so multiple RBCs do not clash
# ---------------------------------------------------------------------------
def make_tagged_io(prefix: str,
                   raw_send: Callable[[int, bytes], None],
                   raw_recv: Callable[[], asyncio.Future]):
    """
    Given a bare `(send, recv)` pair from the network layer, return:

        send(tag, dest, data)      – wrap_send‑style closure
        recv(tag) → awaitable      – subscribe_recv‑style closure

    but *internally* pre‑pends `prefix` to every textual tag so we can run
    many protocol instances in parallel without string collisions.
    """
    # First split the raw_recv for tag‑level multiplexing
    recv_task, recv_router = subscribe_recv(raw_recv)

    def _tagged_wrap(tag: str):
        real_tag = f"{prefix}{tag}"
        return wrap_send(real_tag, raw_send)

    def _tagged_recv(tag: str):
        real_tag = f"{prefix}{tag}"
        return recv_router(real_tag)

    return _tagged_wrap, _tagged_recv, recv_task


# ---------------------------------------------------------------------------
#  Main ACS class
# ---------------------------------------------------------------------------
class YosoACS:
    def __init__(self,
                 n: int,
                 t: int,
                 my_id: int,
                 rbc_builder,           # callable → YosoRBC  (dependency‑inject)
                 send, recv):           # underlying network I/O
        """
        • `rbc_builder(prefix, proposer_id, send, recv)` must return a
          *fresh* YosoRBC instance whose message tags are all prefixed
          with `prefix`.  A thin wrapper is provided below.

        The remaining parameters mirror those of YosoRBC.
        """
        self.n, self.t, self.my_id = n, t, my_id
        self._raw_send, self._raw_recv = send, recv

        # Logging ─ follow the per‑node file layout used in yosorbc.py
        logfile = f'./log/acs-{my_id}.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile, filemode='w'
        )
        self.logger = logging.getLogger(f"acs{my_id}")

        # ---------------------------------------------------------------
        #  Spawn one RBC instance per proposer
        # ---------------------------------------------------------------
        self.rbcs: List[YosoRBC] = []
        self.rbc_tasks: List[asyncio.Task] = []
        self.rbc_outputs: Dict[int, bytes] = {}   # proposer_id → payload
        self._output_sent = False                 # ensure we output only once

        for pid in range(n):
            prefix = f"RBC{pid}|"

            # Create tagged send/recv for this instance only
            wrap_send_fn, recv_fn, recv_task = make_tagged_io(
                prefix, send, recv
            )
            # The rbc_builder must accept **kwargs exactly like YosoRBC
            rbc = rbc_builder(
                prefix=prefix,
                proposer_id=pid,
                send=send, recv=recv,       # raw I/O (wrapped inside)
                wrap_send=wrap_send_fn,
                recv_fn=recv_fn
            )
            self.rbcs.append(rbc)
            # Spawn reactor immediately
            tsk = asyncio.create_task(rbc.reactor())
            self.rbc_tasks.append(tsk)
            # Keep the extra recv_task alive so the router does not exit
            self.rbc_tasks.append(recv_task)

        self.output_queue: "asyncio.Queue[Tuple[List[Optional[bytes]], List[bool]]]" = asyncio.Queue()

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------
    async def submit(self, value: bytes):
        """
        Propose `value` to the ACS by pushing it through our *own* RBC
        instance (index == my_id).  Must be called once by every node.
        """
        await self.rbcs[self.my_id].sender(value)

    async def reactor(self):
        """
        Main event‑loop:

            • Wait on *all* RBC output queues concurrently
            • Record deliveries; once ≥ N − t have arrived, output the set
            • Cancel remaining tasks and return
        """
        # Build wait‑set mapping `asyncio.Task → proposer_id`
        wait_set: Dict[asyncio.Task, int] = {}
        for pid, rbc in enumerate(self.rbcs):
            task = asyncio.create_task(rbc.output_queue.get())
            wait_set[task] = pid

        while wait_set:
            done, _ = await asyncio.wait(wait_set.keys(), return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                pid = wait_set.pop(fut)
                try:
                    (payload, _hash) = fut.result()        # second item unused now
                except asyncio.CancelledError:
                    continue
                self.rbc_outputs[pid] = payload
                self.logger.info("[DELIVER] RBC_%d delivered (%d bytes)", pid, len(payload))

            # ----------------------------------------------------------
            #  Common‑subset shortcut: output after ≥ N − t deliveries
            # ----------------------------------------------------------
            if (not self._output_sent) and len(self.rbc_outputs) >= self.n - self.t:
                bitmap = [pid in self.rbc_outputs for pid in range(self.n)]
                ordered_vals: List[Optional[bytes]] = [
                    self.rbc_outputs.get(pid) for pid in range(self.n)
                ]
                await self.output_queue.put((ordered_vals, bitmap))
                self.logger.info("[OUTPUT] ACS delivered with %d values", len(self.rbc_outputs))
                self._output_sent = True

                # We *could* cancel the still‑running RBC reactors here.
                for t in self.rbc_tasks:
                    t.cancel()
                # Drain outstanding tasks in wait_set
                for t in wait_set.keys():
                    t.cancel()
                return


# ---------------------------------------------------------------------------
#  Convenience builder for the RBC instances
# ---------------------------------------------------------------------------
def default_rbc_builder(**kwargs) -> YosoRBC:
    """
    Small wrapper that adapts the argument list of YosoRBC to what ACS
    provides.  The project already supplies all cryptographic plumbing
    through the surrounding context, so the builder only needs to grab
    them from the global CONFIG dict set by the driver.
    """
    # Import inside to avoid circular deps
    from beaver.node_config import CONFIG    # hypothetical central state
    pid = kwargs["proposer_id"]

    return YosoRBC(
        CONFIG.public_keys,
        CONFIG.private_key,
        CONFIG.pkbls, CONFIG.skbls,
        CONFIG.n, CONFIG.t, CONFIG.srs,
        pid,                      # my_id *inside* the RBC instance
        kwargs["wrap_send"],      # customised send/recv that include prefix
        kwargs["recv_fn"]
    )