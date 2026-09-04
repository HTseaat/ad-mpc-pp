"""Transport-compatible communication counters for local setup runs."""

from __future__ import annotations

import pickle
from collections import defaultdict
from typing import Any

from .bootstrap import activate_upstream


activate_upstream()

from adkg.router import SimpleRouter  # noqa: E402


class MeasuredRouter(SimpleRouter):
    """Count the pickle payload bytes used by upstream's real ZMQ transport.

    Self-sends are excluded, matching ``NodeCommunicator``: local delivery uses
    an in-process queue, while only remote destinations call ``pickle.dumps``.
    ZMQ/TCP framing bytes are intentionally not included.
    """

    def __init__(self, num_parties: int):
        self.sent_bytes = [0] * num_parties
        self.sent_messages = [0] * num_parties
        self.sent_bytes_by_tag = [defaultdict(int) for _ in range(num_parties)]
        super().__init__(num_parties)

    def send(self, player_id: int, dest_id: int, message: object):
        if player_id != dest_id:
            encoded_size = len(pickle.dumps(message))
            self.sent_bytes[player_id] += encoded_size
            self.sent_messages[player_id] += 1
            tag: Any = message[0] if isinstance(message, tuple) and message else "?"
            self.sent_bytes_by_tag[player_id][str(tag)] += encoded_size
        super().send(player_id, dest_id, message)

    def bytes_by_tag(self) -> tuple[dict[str, int], ...]:
        return tuple(dict(sorted(counts.items())) for counts in self.sent_bytes_by_tag)
