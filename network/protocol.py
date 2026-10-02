"""网络协议 - 二进制序列化 / 增量同步 / 压缩校验 / 防作弊 / 自适应流控"""
from dataclasses import dataclass
import binascii
import heapq
import struct
import time
import zlib

PROTOCOL_VERSION = 2
MIN_SUPPORTED_VERSION = 1

# 针对游戏数据优化的压缩字典（常见字段名与消息类型）
_GAME_DICT_BYTES = (
    b'"hp""mp""mana""pos""x""y""z""attack""defense""level""exp"'
    b'"player_id""monster_id""skill_id""damage""heal""buff""debuff"'
    b'"login""logout""sync""delta""ack""heartbeat"'
)

_MAX_HP = 100000
_MAX_ATTACK = 100000
_TIMESTAMP_SKEW = 30.0  # 允许的时间戳偏差（秒）
_RECONNECT_MIN_INTERVAL = 1.0  # 重连限速：最小间隔（秒）
_MAX_RECONNECTS_PER_WINDOW = 5
_RECONNECT_WINDOW = 10.0

_TYPE_INT = 0x01
_TYPE_FLOAT = 0x02
_TYPE_STR = 0x03
_TYPE_BOOL = 0x04
_TYPE_NONE = 0x05
_TYPE_DICT = 0x06
_TYPE_LIST = 0x07


@dataclass
class Packet:
    seq: int
    timestamp: float
    data: dict
    priority: int = 0


def _encode_value(value) -> bytes:
    if value is None:
        return bytes([_TYPE_NONE])
    if isinstance(value, bool):
        return bytes([_TYPE_BOOL, 1 if value else 0])
    if isinstance(value, int):
        return bytes([_TYPE_INT]) + struct.pack("<q", value)
    if isinstance(value, float):
        return bytes([_TYPE_FLOAT]) + struct.pack("<d", value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return bytes([_TYPE_STR]) + struct.pack("<H", len(raw)) + raw
    if isinstance(value, dict):
        return bytes([_TYPE_DICT]) + _encode_dict(value)
    if isinstance(value, (list, tuple)):
        out = bytearray([_TYPE_LIST])
        out += struct.pack("<H", len(value))
        for item in value:
            out += _encode_value(item)
        return bytes(out)
    raise TypeError(f"unsupported type: {type(value)!r}")


def _encode_dict(data: dict) -> bytes:
    out = bytearray()
    out += struct.pack("<H", len(data))
    for key, value in data.items():
        raw = str(key).encode("utf-8")
        out += struct.pack("<H", len(raw)) + raw
        out += _encode_value(value)
    return bytes(out)


def _decode_value(buf: bytes, offset: int):
    vtype = buf[offset]
    offset += 1
    if vtype == _TYPE_NONE:
        return None, offset
    if vtype == _TYPE_BOOL:
        return bool(buf[offset]), offset + 1
    if vtype == _TYPE_INT:
        return struct.unpack_from("<q", buf, offset)[0], offset + 8
    if vtype == _TYPE_FLOAT:
        return struct.unpack_from("<d", buf, offset)[0], offset + 8
    if vtype == _TYPE_STR:
        (length,) = struct.unpack_from("<H", buf, offset)
        offset += 2
        return buf[offset:offset + length].decode("utf-8"), offset + length
    if vtype == _TYPE_DICT:
        return _decode_dict(buf, offset)
    if vtype == _TYPE_LIST:
        (count,) = struct.unpack_from("<H", buf, offset)
        offset += 2
        items = []
        for _ in range(count):
            item, offset = _decode_value(buf, offset)
            items.append(item)
        return items, offset
    raise ValueError(f"unknown type tag: {vtype}")


def _decode_dict(buf: bytes, offset: int):
    (count,) = struct.unpack_from("<H", buf, offset)
    offset += 2
    result = {}
    for _ in range(count):
        (klen,) = struct.unpack_from("<H", buf, offset)
        offset += 2
        key = buf[offset:offset + klen].decode("utf-8")
        offset += klen
        value, offset = _decode_value(buf, offset)
        result[key] = value
    return result, offset


class NetworkProtocol:
    def __init__(self):
        self.version: int = PROTOCOL_VERSION
        self.sent_packets: list = []
        self.received_seqs: set = set()
        self._last_seq: int = -1
        self._last_full_state: dict = {}
        self._reconnect_times: list = []
        self._send_queue: list = []  # 优先级队列 (priority, seq, packet)
        self._unacked: dict = {}     # seq -> (packet, last_send_time)
        self._zdict = _GAME_DICT_BYTES

    # ---------- 序列化：二进制 + 增量 + 版本兼容 ----------

    def serialize_data(self, data: dict, base: dict = None) -> bytes:
        """二进制序列化，带版本头；传入 base 时只序列化增量。"""
        if base is not None:
            body = _encode_dict(self.compute_delta(base, data))
            return struct.pack("<BB", self.version, 1) + body
        body = _encode_dict(data)
        return struct.pack("<BB", self.version, 0) + body

    def deserialize_data(self, blob: bytes) -> dict:
        """反序列化，兼容旧版本协议。"""
        if len(blob) < 2:
            raise ValueError("packet too short")
        version, flags = struct.unpack_from("<BB", blob, 0)
        if version < MIN_SUPPORTED_VERSION or version > PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {version}")
        payload, _ = _decode_dict(blob, 2)
        payload = self._migrate(version, payload)
        if flags & 1:
            return self.apply_delta(self._last_full_state, payload)
        self._last_full_state = dict(payload)
        return payload

    def _migrate(self, version: int, payload: dict) -> dict:
        """旧版本数据迁移到当前版本结构。"""
        if version < PROTOCOL_VERSION:
            payload = dict(payload)
        return payload

    @staticmethod
    def compute_delta(old: dict, new: dict) -> dict:
        delta = {}
        for key, value in new.items():
            if key not in old or old[key] != value:
                delta[key] = value
        for key in old:
            if key not in new:
                delta[key] = None  # None 表示删除
        return delta

    @staticmethod
    def apply_delta(base: dict, delta: dict) -> dict:
        result = dict(base)
        for key, value in delta.items():
            if value is None:
                result.pop(key, None)
            else:
                result[key] = value
        return result

    # ---------- 压缩：游戏字典 + 完整性校验 ----------

    def compress_data(self, data: bytes) -> bytes:
        """zlib + 游戏字典压缩，附加 CRC32 与原始长度做完整性校验。"""
        compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS, 9,
                                      zlib.Z_DEFAULT_STRATEGY, self._zdict)
        body = compressor.compress(data) + compressor.flush()
        crc = binascii.crc32(data) & 0xFFFFFFFF
        header = struct.pack("<II", crc, len(data))
        return header + body

    def decompress_data(self, blob: bytes) -> bytes:
        """解压并校验完整性，损坏数据抛异常而不是返回垃圾。"""
        if len(blob) < 8:
            raise ValueError("corrupted compressed data: too short")
        crc, orig_len = struct.unpack_from("<II", blob, 0)
        decompressor = zlib.decompressobj(zlib.MAX_WBITS, zdict=self._zdict)
        try:
            data = decompressor.decompress(blob[8:]) + decompressor.flush()
        except zlib.error as exc:
            raise ValueError(f"corrupted compressed data: {exc}") from exc
        if len(data) != orig_len or (binascii.crc32(data) & 0xFFFFFFFF) != crc:
            raise ValueError("integrity check failed: crc/length mismatch")
        return data

    # ---------- 断线重连：增量 + 状态校验 + 限速 ----------

    def handle_reconnect(self, client_state: dict, server_state: dict) -> dict:
        """服务器权威：校验客户端状态，返回需要下发的增量，限速防雪崩。"""
        now = time.monotonic()
        self._reconnect_times = [t for t in self._reconnect_times
                                 if now - t < _RECONNECT_WINDOW]
        if len(self._reconnect_times) >= _MAX_RECONNECTS_PER_WINDOW:
            raise RuntimeError("reconnect rate limited")
        if self._reconnect_times and now - self._reconnect_times[-1] < _RECONNECT_MIN_INTERVAL:
            raise RuntimeError("reconnect rate limited")
        self._reconnect_times.append(now)

        # 校验客户端状态合法性，非法字段不允许覆盖服务器状态
        clean_client = {}
        for key, value in (client_state or {}).items():
            if self._is_field_legal(key, value):
                clean_client[key] = value

        # 服务器状态为权威，客户端旧状态不能回滚服务器新状态
        merged = dict(server_state)
        self._last_full_state = dict(merged)
        # 只返回客户端缺失或不一致的增量
        return self.compute_delta(clean_client, merged)

    # ---------- 防作弊：数据合法性 + 时间戳 + 序列号 ----------

    def validate_packet(self, packet: Packet) -> bool:
        if not isinstance(packet, Packet) or not isinstance(packet.data, dict):
            return False
        # 时间戳校验：拒绝重放的旧包与来自未来的包
        now = time.time()
        if not isinstance(packet.timestamp, (int, float)):
            return False
        if abs(now - packet.timestamp) > _TIMESTAMP_SKEW:
            return False
        # 序列号校验：拒绝重复与乱序
        if not isinstance(packet.seq, int) or packet.seq < 0:
            return False
        if packet.seq in self.received_seqs or packet.seq <= self._last_seq:
            return False
        # 数据合法性校验
        for key, value in packet.data.items():
            if not self._is_field_legal(key, value):
                return False
        self.received_seqs.add(packet.seq)
        self._last_seq = packet.seq
        return True

    @staticmethod
    def _is_field_legal(key, value) -> bool:
        limits = {"hp": _MAX_HP, "max_hp": _MAX_HP, "mp": _MAX_HP,
                  "mana": _MAX_HP, "attack": _MAX_ATTACK, "damage": _MAX_ATTACK,
                  "defense": _MAX_ATTACK, "level": 1000}
        if key in limits:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
            if value < 0 or value > limits[key]:
                return False
        return True

    # ---------- 流量控制：自适应频率 + 重传 + 优先级 ----------

    def flow_control(self, network_condition: dict) -> int:
        """根据丢包率与延迟自适应调整发送频率（包/秒）。"""
        loss = float(network_condition.get("loss", 0.0))
        latency = float(network_condition.get("latency", 0.0))  # ms
        rate = 60.0
        if loss > 0.02:
            rate *= max(0.1, 1.0 - loss)
        if latency > 50:
            rate *= max(0.2, 50.0 / latency)
        return max(1, int(rate))

    def queue_packet(self, packet: Packet) -> None:
        """按优先级入队，高优先级（数值小）先发，技能数据不会被聊天挤掉。"""
        heapq.heappush(self._send_queue, (packet.priority, packet.seq, packet))

    def next_packet(self, network_condition: dict = None) -> Packet:
        """取出最高优先级包并登记待确认，用于丢包重传。"""
        if not self._send_queue:
            return None
        _, _, packet = heapq.heappop(self._send_queue)
        self._unacked[packet.seq] = (packet, time.monotonic())
        self.sent_packets.append(packet)
        return packet

    def ack_packet(self, seq: int) -> None:
        self._unacked.pop(seq, None)

    def get_retransmit_packets(self, timeout: float = 0.5) -> list:
        """超时未确认的关键包重传，丢了不会永远丢。"""
        now = time.monotonic()
        due = []
        for seq, (packet, sent_at) in self._unacked.items():
            if now - sent_at >= timeout:
                due.append(packet)
                self._unacked[seq] = (packet, now)
        due.sort(key=lambda p: (p.priority, p.seq))
        return due
