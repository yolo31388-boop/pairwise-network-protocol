"""网络协议 - 含5个bug"""
from dataclasses import dataclass, field
import json

@dataclass
class Packet:
    seq: int
    timestamp: float
    data: dict
    priority: int = 0

class NetworkProtocol:
    def __init__(self):
        self.version: int = 1
        self.sent_packets: list = []
        self.received_seqs: set = set()

    def serialize_data(self, data: dict) -> bytes:
        # bug1: JSON序列化，全量
        return json.dumps(data).encode()

    def compress_data(self, data: bytes) -> bytes:
        # bug2: 固定字典，无校验
        return data

    def handle_reconnect(self, client_state: dict, server_state: dict) -> dict:
        # bug3: 全量同步，不校验
        return server_state

    def validate_packet(self, packet: Packet) -> bool:
        # bug4: 只检查格式
        return True

    def flow_control(self, network_condition: dict) -> int:
        # bug5: 固定频率
        return 60
