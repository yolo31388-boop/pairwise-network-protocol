"""网络协议 - 修复验证测试（15）"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.protocol import (  # noqa: E402
    NetworkProtocol, Packet, IntegrityError, RateLimitError,
    PRIORITY_CHAT, PRIORITY_SKILL, PRIORITY_CRITICAL,
)


def make_state():
    return {"player_id": "p1", "hp": 100, "mana": 50,
            "position": {"x": 1.5, "y": 2.5}, "level": 3}


class TestBinarySerialize:
    def test_binary_more_compact(self):
        np = NetworkProtocol()
        data = {"x": 1.5, "y": 2.5, "hp": 100}
        result = np.serialize_data(data)
        assert len(result) < 50
        state = make_state()
        binary = np.serialize_data(state)
        assert len(binary) < len(json.dumps(state).encode())

    def test_incremental_sync_smaller_and_mergable(self):
        np = NetworkProtocol()
        old = make_state()
        new = dict(old)
        new["hp"] = 90
        full = np.serialize_data(new)
        delta = np.serialize_data(new, base=old)
        assert len(delta) < len(full)
        assert np.deserialize_data(delta, base=old) == new

    def test_version_compatible_with_legacy_json(self):
        np = NetworkProtocol()
        state = make_state()
        legacy = np.serialize_data(state, version=1)
        assert np.deserialize_data(legacy) == state
        raw_json = json.dumps(state).encode()
        assert np.deserialize_data(raw_json) == state
        binary = np.serialize_data(state, version=2)
        assert np.deserialize_data(binary) == state


class TestCompressionIntegrity:
    def test_compressed_data_valid(self):
        np = NetworkProtocol()
        data = b"test data 12345"
        compressed = np.compress_data(data)
        assert compressed != data or len(compressed) <= len(data)
        assert np.decompress_data(compressed) == data

    def test_corrupted_data_rejected(self):
        np = NetworkProtocol()
        compressed = bytearray(np.compress_data(b"important server state"))
        compressed[-1] ^= 0xFF
        with pytest.raises(IntegrityError):
            np.decompress_data(bytes(compressed))

    def test_incremental_compression_uses_history(self):
        np = NetworkProtocol()
        frame1 = b'{"player_id":"p1","hp":100,"position":{"x":1.0,"y":2.0}}'
        frame2 = b'{"player_id":"p1","hp":99,"position":{"x":1.0,"y":2.0}}'
        c1 = np.compress_data(frame1)
        c2 = np.compress_data(frame2)
        assert np.decompress_data(c1) == frame1
        assert np.decompress_data(c2) == frame2
        standalone = NetworkProtocol().compress_data(frame2)
        assert len(c2) < len(standalone)


class TestIncrementalReconnect:
    def test_reconnect_incremental(self):
        np = NetworkProtocol()
        client = {"hp": 100, "pos": (0, 0)}
        server = {"hp": 90, "pos": (1, 1), "mana": 50}
        result = np.handle_reconnect(client, server)
        assert "mana" in result
        assert np.handle_reconnect(server, server) == {}

    def test_reconnect_server_authoritative(self):
        np = NetworkProtocol()
        client = {"hp": 99999, "_version": 999}
        server = {"hp": 90, "_version": 10}
        result = np.handle_reconnect(client, server)
        assert result == {"hp": 90, "_version": 10}

    def test_reconnect_rate_limited_per_client(self):
        np = NetworkProtocol()
        now = time.time()
        for _ in range(5):
            np.handle_reconnect({}, {"hp": 1}, client_id="p1", now=now)
        with pytest.raises(RateLimitError):
            np.handle_reconnect({}, {"hp": 1}, client_id="p1", now=now)
        np.handle_reconnect({}, {"hp": 1}, client_id="p2", now=now)


class TestCheatDetection:
    def test_invalid_hp_rejected(self):
        np = NetworkProtocol()
        packet = Packet(1, time.time(), {"hp": 999999})
        assert np.validate_packet(packet) is False

    def test_timestamp_replay_and_future_rejected(self):
        np = NetworkProtocol()
        now = time.time()
        assert np.validate_packet(Packet(1, now - 3600, {"hp": 100}), now) is False
        assert np.validate_packet(Packet(2, now + 3600, {"hp": 100}), now) is False
        assert np.validate_packet(Packet(3, now, {"hp": 100}), now) is True

    def test_sequence_duplicate_and_reorder_rejected(self):
        np = NetworkProtocol()
        now = time.time()
        assert np.validate_packet(Packet(5, now, {"hp": 100}), now) is True
        assert np.validate_packet(Packet(5, now, {"hp": 100}), now) is False
        assert np.validate_packet(Packet(3, now, {"hp": 100}), now) is False
        assert np.validate_packet(Packet(6, now, {"hp": 100}), now) is True


class TestAdaptiveRate:
    def test_rate_adapts_to_network(self):
        np = NetworkProtocol()
        rate = np.flow_control({"loss": 0.5, "latency": 200})
        assert rate < 60
        assert np.flow_control({"loss": 0.0, "latency": 10}) == 60

    def test_lost_critical_packet_retransmitted(self):
        np = NetworkProtocol()
        now = time.time()
        packet = Packet(1, now, {"skill": "fireball"}, priority=PRIORITY_CRITICAL)
        np.send_packet(packet, now=now)
        assert np.get_retransmissions(now=now + 0.1) == []
        assert np.get_retransmissions(now=now + 1.0) == [packet]
        np.handle_ack(1)
        assert np.get_retransmissions(now=now + 2.0) == []

    def test_priority_queue_puts_skill_before_chat(self):
        np = NetworkProtocol()
        now = time.time()
        chat = Packet(1, now, {"msg": "hello"}, priority=PRIORITY_CHAT)
        skill = Packet(2, now, {"skill": "fireball"}, priority=PRIORITY_SKILL)
        np.queue_packet(chat)
        np.queue_packet(skill)
        assert np.next_packet() is skill
        assert np.next_packet() is chat
        assert np.next_packet() is None
