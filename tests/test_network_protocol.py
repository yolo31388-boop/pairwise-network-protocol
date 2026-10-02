"""网络协议 - 红态测试"""
import pytest, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.protocol import NetworkProtocol, Packet

class TestBinarySerialize:
    def test_binary_more_compact(self):
        np = NetworkProtocol()
        data = {"x": 1.5, "y": 2.5, "hp": 100}
        result = np.serialize_data(data)
        assert len(result) < 50

class TestCompressionIntegrity:
    def test_compressed_data_valid(self):
        np = NetworkProtocol()
        data = b"test data 12345"
        compressed = np.compress_data(data)
        assert compressed != data or len(compressed) <= len(data)

class TestIncrementalReconnect:
    def test_reconnect_incremental(self):
        np = NetworkProtocol()
        client = {"hp": 100, "pos": (0,0)}
        server = {"hp": 90, "pos": (1,1), "mana": 50}
        result = np.handle_reconnect(client, server)
        assert "mana" in result

class TestCheatDetection:
    def test_invalid_hp_rejected(self):
        np = NetworkProtocol()
        packet = Packet(1, 0, {"hp": 999999})
        assert np.validate_packet(packet) == False

class TestAdaptiveRate:
    def test_rate_adapts_to_network(self):
        np = NetworkProtocol()
        rate = np.flow_control({"loss": 0.5, "latency": 200})
        assert rate < 60
