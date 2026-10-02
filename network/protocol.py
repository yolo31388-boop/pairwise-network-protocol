"""网络协议 - 二进制序列化/增量同步/游戏优化压缩/安全重连/防作弊/自适应流控"""
from __future__ import annotations

import heapq
import json
import struct
import time
import zlib
from dataclasses import dataclass

# 数据包优先级：数值越大越优先（技能 > 移动 > 聊天）
PRIORITY_CHAT = 0
PRIORITY_MOVE = 1
PRIORITY_SKILL = 2
PRIORITY_CRITICAL = 3

# 协议版本
PROTOCOL_VERSION_LEGACY = 1   # JSON 明文，兼容旧客户端
PROTOCOL_VERSION_BINARY = 2   # 二进制 + 增量同步

_MAGIC = b"NP"
_FLAG_DELTA = 0x01

# 常见游戏字段名表（1 字节 ID 代替反复出现的键名字符串）
_FIELD_TABLE = [
    "player_id", "id", "name", "type", "hp", "max_hp", "mp", "mana",
    "attack", "atk", "defense", "damage", "level", "exp", "position",
    "x", "y", "z", "pos_x", "pos_y", "pos_z", "velocity", "skill",
    "state", "seq", "timestamp", "msg", "target",
]
_FIELD_IDS = {name: i for i, name in enumerate(_FIELD_TABLE)}
_TAG_INTERNED = 0x09

# 游戏数据合法性范围（防作弊）
_STAT_RANGES = {
    "hp": (0, 10000), "max_hp": (0, 10000),
    "mp": (0, 10000), "mana": (0, 10000),
    "attack": (0, 9999), "atk": (0, 9999),
    "defense": (0, 9999), "damage": (0, 9999),
    "level": (1, 999),
}
_COORD_KEYS = {"x", "y", "z", "pos_x", "pos_y", "pos_z"}
_MAX_COORD = 1_000_000

# 针对游戏数据优化的压缩字典（常见字段名与结构）
_GAME_ZDICT = (
    b'{"player_id":"","hp":0,"max_hp":0,"mana":0,"attack":0,"defense":0,'
    b'"position":{"x":0.0,"y":0.0,"z":0.0},"level":0,"exp":0,'
    b'"skill":"","damage":0,"seq":0,"timestamp":0.0,"state":{}}'
)


class IntegrityError(Exception):
    """压缩数据完整性校验失败"""


class RateLimitError(Exception):
    """断线重连频率超限"""


@dataclass
class Packet:
    seq: int
    timestamp: float
    data: dict
    priority: int = 0


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _decode_varint(buf, pos: int):
    shift = 0
    result = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7


def _encode_value(value, out: bytearray, is_key: bool = False) -> None:
    if is_key and isinstance(value, str) and value in _FIELD_IDS:
        out.append(_TAG_INTERNED)
        out.append(_FIELD_IDS[value])
        return
    if value is None:
        out.append(0x00)
    elif value is False:
        out.append(0x01)
    elif value is True:
        out.append(0x02)
    elif isinstance(value, int):
        out.append(0x03)
        zigzag = 2 * value if value >= 0 else -2 * value - 1
        out += _encode_varint(zigzag)
    elif isinstance(value, float):
        out.append(0x04)
        out += struct.pack(">d", value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out.append(0x05)
        out += _encode_varint(len(raw))
        out += raw
    elif isinstance(value, (bytes, bytearray)):
        out.append(0x06)
        out += _encode_varint(len(value))
        out += bytes(value)
    elif isinstance(value, (list, tuple)):
        out.append(0x07)
        out += _encode_varint(len(value))
        for item in value:
            _encode_value(item, out)
    elif isinstance(value, dict):
        out.append(0x08)
        out += _encode_varint(len(value))
        for key, item in value.items():
            _encode_value(key, out, is_key=True)
            _encode_value(item, out)
    else:
        raise TypeError(f"不支持的类型: {type(value)!r}")


def _decode_value(buf, pos: int, is_key: bool = False):
    tag = buf[pos]
    pos += 1
    if tag == 0x00:
        return None, pos
    if tag == 0x01:
        return False, pos
    if tag == 0x02:
        return True, pos
    if tag == 0x03:
        raw, pos = _decode_varint(buf, pos)
        return (raw >> 1) ^ -(raw & 1), pos
    if tag == 0x04:
        return struct.unpack(">d", buf[pos:pos + 8])[0], pos + 8
    if tag == _TAG_INTERNED:
        return _FIELD_TABLE[buf[pos]], pos + 1
    if tag == 0x05:
        length, pos = _decode_varint(buf, pos)
        return buf[pos:pos + length].decode("utf-8"), pos + length
    if tag == 0x06:
        length, pos = _decode_varint(buf, pos)
        return bytes(buf[pos:pos + length]), pos + length
    if tag == 0x07:
        count, pos = _decode_varint(buf, pos)
        items = []
        for _ in range(count):
            item, pos = _decode_value(buf, pos)
            items.append(item)
        return items, pos
    if tag == 0x08:
        count, pos = _decode_varint(buf, pos)
        result = {}
        for _ in range(count):
            key, pos = _decode_value(buf, pos, is_key=True)
            item, pos = _decode_value(buf, pos)
            result[key] = item
        return result, pos
    raise ValueError(f"未知的类型标签: {tag:#x}")


class NetworkProtocol:
    def __init__(self, *, base_rate: int = 60, min_rate: int = 5,
                 timestamp_window: float = 30.0,
                 retransmit_timeout: float = 0.5, max_retries: int = 5,
                 max_reconnects: int = 5, reconnect_window: float = 60.0):
        self.version: int = PROTOCOL_VERSION_BINARY
        self.sent_packets: list = []
        self.received_seqs: set = set()
        self.last_seq: int = -1
        # 流量控制参数
        self.base_rate = base_rate
        self.min_rate = min_rate
        self.timestamp_window = timestamp_window
        self.retransmit_timeout = retransmit_timeout
        self.max_retries = max_retries
        # 重连限速参数
        self.max_reconnects = max_reconnects
        self.reconnect_window = reconnect_window
        self._reconnect_log: dict = {}
        # 增量压缩：压缩器跨帧保留历史，相似帧只编码差异
        self._compressor = zlib.compressobj(
            9, zlib.DEFLATED, zlib.MAX_WBITS, 9,
            zlib.Z_DEFAULT_STRATEGY, _GAME_ZDICT)
        self._decompressor = zlib.decompressobj(
            zlib.MAX_WBITS, zdict=_GAME_ZDICT)
        # 待确认的关键包：seq -> [packet, sent_at, retries]
        self._pending_acks: dict = {}
        # 优先级发送队列：(-priority, seq, packet)
        self._send_queue: list = []

    # ---------- 序列化：二进制 + 增量 + 版本兼容 ----------

    def serialize_data(self, data: dict, base: dict | None = None,
                       version: int | None = None) -> bytes:
        version = self.version if version is None else version
        if version <= PROTOCOL_VERSION_LEGACY:
            # 旧版本客户端：退回 JSON，保证双向兼容
            return json.dumps(data, separators=(",", ":")).encode("utf-8")
        if base is not None:
            payload = self._compute_delta(base, data)
            flags = _FLAG_DELTA
        else:
            payload = data
            flags = 0
        body = bytearray()
        _encode_value(payload, body)
        return _MAGIC + bytes([version, flags]) + bytes(body)

    def deserialize_data(self, payload: bytes, base: dict | None = None) -> dict:
        if not payload.startswith(_MAGIC):
            # 更老的裸 JSON 客户端，直接兼容解析
            return json.loads(payload.decode("utf-8"))
        version = payload[2]
        flags = payload[3]
        if version <= PROTOCOL_VERSION_LEGACY:
            return json.loads(payload[4:].decode("utf-8"))
        data, _ = _decode_value(payload, 4)
        if flags & _FLAG_DELTA:
            if base is None:
                raise ValueError("收到增量数据但缺少基准状态")
            merged = dict(base)
            removed = data.pop("__del__", [])
            merged.update(data)
            for key in removed:
                merged.pop(key, None)
            return merged
        return data

    @staticmethod
    def _compute_delta(base: dict, current: dict) -> dict:
        delta = {k: v for k, v in current.items()
                 if k not in base or base[k] != v}
        removed = [k for k in base if k not in current]
        if removed:
            delta["__del__"] = removed
        return delta

    # ---------- 压缩：游戏字典 + 增量 + 完整性校验 ----------

    def compress_data(self, data: bytes) -> bytes:
        compressed = (self._compressor.compress(data)
                      + self._compressor.flush(zlib.Z_SYNC_FLUSH))
        crc = zlib.crc32(compressed)
        return struct.pack(">I", crc) + compressed

    def decompress_data(self, payload: bytes) -> bytes:
        if len(payload) < 4:
            raise IntegrityError("数据过短，缺少 CRC32 校验头")
        crc, = struct.unpack(">I", payload[:4])
        compressed = payload[4:]
        if zlib.crc32(compressed) != crc:
            raise IntegrityError("CRC32 校验失败，压缩数据已损坏")
        try:
            return self._decompressor.decompress(compressed)
        except zlib.error as exc:
            raise IntegrityError(f"解压失败: {exc}") from exc

    # ---------- 断线重连：增量同步 + 状态校验 + 限速 ----------

    def handle_reconnect(self, client_state: dict, server_state: dict,
                         client_id: str | None = None,
                         now: float | None = None) -> dict:
        now = time.time() if now is None else now
        if client_id is not None:
            self._enforce_reconnect_limit(client_id, now)
        # 校验客户端状态：版本号高于服务器说明是伪造/过期数据，整体忽略
        if client_state.get("_version", 0) > server_state.get("_version", 0):
            client_state = {}
        # 服务器状态为准，只回传增量；客户端旧状态永远覆盖不了服务器
        return {k: v for k, v in server_state.items()
                if client_state.get(k) != v}

    def _enforce_reconnect_limit(self, client_id: str, now: float) -> None:
        log = self._reconnect_log.setdefault(client_id, [])
        log[:] = [t for t in log if now - t < self.reconnect_window]
        if len(log) >= self.max_reconnects:
            raise RateLimitError(
                f"客户端 {client_id} 重连过于频繁，已限速")
        log.append(now)

    # ---------- 防作弊：数据合法性 + 时间戳 + 序列号 ----------

    def validate_packet(self, packet: Packet, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        # 格式检查
        if not isinstance(packet.seq, int) or packet.seq < 0:
            return False
        if not isinstance(packet.timestamp, (int, float)):
            return False
        if not isinstance(packet.data, dict):
            return False
        # 时间戳检查：拒绝重放的旧包和来自未来的包
        if abs(now - packet.timestamp) > self.timestamp_window:
            return False
        # 序列号检查：拒绝重复包和乱序包
        if packet.seq in self.received_seqs or packet.seq <= self.last_seq:
            return False
        # 数据合法性检查：拒绝被篡改的数值
        if not self._validate_data(packet.data):
            return False
        self.received_seqs.add(packet.seq)
        self.last_seq = max(self.last_seq, packet.seq)
        return True

    @staticmethod
    def _validate_data(data: dict) -> bool:
        for key, value in data.items():
            if key in _STAT_RANGES:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return False
                low, high = _STAT_RANGES[key]
                if not (low <= value <= high):
                    return False
            elif key in _COORD_KEYS:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return False
                if abs(value) > _MAX_COORD:
                    return False
            elif not isinstance(value, (int, float, str, bool, list, dict, type(None))):
                return False
        return True

    # ---------- 流量控制：自适应频率 + 丢包重传 + 优先级 ----------

    def flow_control(self, network_condition: dict) -> int:
        loss = min(max(float(network_condition.get("loss", 0.0)), 0.0), 1.0)
        latency = max(float(network_condition.get("latency", 0.0)), 0.0)
        rate = float(self.base_rate)
        rate *= 1.0 - loss                 # 丢包越多，频率越低
        if latency > 50.0:
            rate *= 50.0 / latency         # 高延迟按比例降频
        return max(self.min_rate, min(self.base_rate, int(rate)))

    def send_packet(self, packet: Packet, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self.sent_packets.append(packet)
        if packet.priority >= PRIORITY_CRITICAL:
            # 关键包登记待确认，超时未确认会重传
            self._pending_acks[packet.seq] = [packet, now, 0]

    def handle_ack(self, seq: int) -> None:
        self._pending_acks.pop(seq, None)

    def get_retransmissions(self, now: float | None = None) -> list:
        now = time.time() if now is None else now
        due = []
        for seq, entry in list(self._pending_acks.items()):
            packet, sent_at, retries = entry
            if now - sent_at < self.retransmit_timeout:
                continue
            if retries >= self.max_retries:
                del self._pending_acks[seq]
                continue
            entry[1] = now
            entry[2] = retries + 1
            due.append(packet)
        return due

    def queue_packet(self, packet: Packet) -> None:
        heapq.heappush(self._send_queue, (-packet.priority, packet.seq, packet))

    def next_packet(self) -> Packet | None:
        if not self._send_queue:
            return None
        return heapq.heappop(self._send_queue)[2]
