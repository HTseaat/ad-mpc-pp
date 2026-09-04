import asyncio

import pytest

from adkg.shuffle_ipc import AdjacentNodeCommunicator, adjacent_peer_ids


def test_first_middle_last_adjacent_peer_counts():
    n = 4
    layers = 5
    assert len(adjacent_peer_ids(0, n, layers)) == 2 * n - 1
    assert len(adjacent_peer_ids(2 * n, n, layers)) == 3 * n - 1
    assert len(adjacent_peer_ids((layers - 1) * n, n, layers)) == 2 * n - 1


def test_adjacent_topology_excludes_distance_two():
    peers = adjacent_peer_ids(4, n=4, physical_layers=5)
    assert set(range(12, 16)).isdisjoint(peers)
    assert set(range(0, 4)).issubset(peers)
    assert set(range(8, 12)).issubset(peers)


def test_non_adjacent_send_fails_closed():
    peers = [object()] * 20
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    communicator = AdjacentNodeCommunicator(
        peers,
        my_id=4,
        allowed_peer_ids=adjacent_peer_ids(4, n=4, physical_layers=5),
        auth_mode="null",
    )
    try:
        with pytest.raises(ValueError, match="forbidden non-adjacent send"):
            communicator.send(12, "must-not-cross-two-layers")
    finally:
        communicator.zmq_context.destroy(linger=0)
        loop.close()
        asyncio.set_event_loop(None)


@pytest.mark.parametrize("global_id", [-1, 20])
def test_adjacent_topology_rejects_invalid_identity(global_id):
    with pytest.raises(ValueError):
        adjacent_peer_ids(global_id, n=4, physical_layers=5)
