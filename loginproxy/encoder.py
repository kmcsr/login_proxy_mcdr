
import io
import json
import uuid
from typing import Self

from kpi.utils import assert_instanceof

from .structs import *

__all__ = [
	'DecodeError',
	'encode_byte', 'encode_short', 'encode_int', 'encode_long', 'encode_bool',
	'encode_varint', 'encode_string', 'encode_json',
	'send_package',
	'recv_byte', 'recv_varint', 'recv_varint2', 'recv_package',
	'PacketReader', 'PacketBuffer',
	'BitSet',
	'ServerStatus',
]

class DecodeError(Exception):
	def __init__(self, reason: str, got, require):
		super().__init__(reason + f', got {got} but require {require}')

def encode_byte(n: int) -> bytes:
	assert 0 <= n and n <= 0xff, f'{hex(n)} is not in range [0, 0xff]'
	return n.to_bytes(1, byteorder='big')

def encode_short(n: int) -> bytes:
	assert 0 <= n and n <= 0xffff, f'{hex(n)} is not in range [0, 0xffff]'
	return n.to_bytes(2, byteorder='big')

def encode_int(n: int) -> bytes:
	assert 0 <= n and n <= 0xffffffff, f'{hex(n)} is not in range [0, 0xffffffff]'
	return n.to_bytes(4, byteorder='big')

def encode_long(n: int) -> bytes:
	assert 0 <= n and n <= 0xffffffffffffffff, f'{hex(n)} is not in range [0, 0xffffffffffffffff]'
	return n.to_bytes(8, byteorder='big')

def encode_bool(v: bool) -> bytes:
	return b'\x01' if v else b'\x00'

def encode_varint(n: int) -> bytes:
	assert n >= 0
	if n == 0:
		return b'\x00'
	b = bytearray()
	while n > 0:
		x = n & 0x7f
		n >>= 7
		if n > 0:
			x |= 0x80
		b.append(x)
	return bytes(b)

def encode_string(s: str) -> bytes:
	b = s.encode('utf8')
	return encode_varint(len(b)) + b

def encode_json(obj: dict) -> bytes:
	s = json.dumps(obj).encode('utf8')
	return encode_varint(len(s)) + s

def send_package(c, pid: int, data: bytes):
	assert_instanceof(data, bytes)
	pidb = encode_varint(pid)
	c.sendall(encode_varint(len(pidb) + len(data)))
	c.sendall(pidb)
	c.sendall(data)

def recv_byte(c) -> int:
	try:
		return c.recv(1)[0]
	except IndexError:
		raise ConnectionAbortedError() from None

def recv_varint2(c) -> tuple[int, int]:
	leng = 0
	num = 0
	i = 0
	while True:
		n = recv_byte(c)
		leng += 1
		num |= (n & 0x7f) << i
		if n & 0x80 == 0:
			break
		i += 7
		if i >= 32:
			raise DecodeError('VarInt too big', '32-bit', str(i) + '-bit')
	return num, leng

def recv_varint(c) -> int:
	return recv_varint2(c)[0]

class PacketReader:
	__slots__ = ('_data', '_reader', '_id', '_read_id')
	def __init__(self, data: bytes, id: int | None = None):
		self._data = data
		self._reader = io.BytesIO(data)
		if id is None:
			self._id = self.read_varint()
			self._read_id = self._reader.seek(0, io.SEEK_CUR)
		else:
			self._id = id
			self._read_id = 0

	@property
	def size(self) -> int:
		return len(self._data)

	@property
	def reader(self) -> io.BytesIO:
		return self._reader

	@property
	def data(self) -> bytes:
		return self._data

	@property
	def id(self) -> int:
		return self._id

	@property
	def remain(self) -> int:
		return len(self._data) - self._reader.seek(0, io.SEEK_CUR)

	def reset(self) -> None:
		self._reader.seek(self._read_id, io.SEEK_SET)

	def read(self, n: int = -1, *, err='buf remain not enough') -> bytes:
		v = self._reader.read(n)
		if n >= 0:
			if len(v) > n:
				raise RuntimeError('Read returned too much data')
			if len(v) < n:
				raise DecodeError(err, len(v), n)
		return v

	def read_byte(self) -> int:
		v = self.read(1, err='EOF')
		return parse_byte(v)

	def read_ubyte(self) -> int:
		v = self.read(1, err='EOF')
		return parse_ubyte(v)

	def read_short(self) -> int:
		v = self.read(2, err='short length not correct')
		return parse_short(v)

	def read_ushort(self) -> int:
		v = self.read(2, err='short length not correct')
		return parse_ushort(v)

	def read_int(self) -> int:
		v = self.read(4, err='int length not correct')
		return parse_int(v)

	def read_uint(self) -> int:
		v = self.read(4, err='int length not correct')
		return parse_uint(v)

	def read_long(self) -> int:
		v = self.read(8, err='long length not correct')
		return parse_long(v)

	def read_ulong(self) -> int:
		v = self.read(8, err='long length not correct')
		return parse_ulong(v)

	def read_float(self) -> float:
		v = self.read(4, err='float length not correct')
		return parse_float(v)

	def read_double(self) -> float:
		v = self.read(8, err='double length not correct')
		return parse_double(v)

	def read_bool(self) -> bool:
		v = self.read_byte()
		return v != 0x00

	def read_varint(self) -> int:
		n, i = 0, 0
		while True:
			bt = self.read_ubyte()
			n |= (bt & 0x7f) << i
			if bt & 0x80 == 0:
				break
			i += 7
			if i > 32:
				raise DecodeError('VarInt too big', '32-bit', str(i) + '-bit')
		return n

	def read_varlong(self) -> int:
		n, i = 0, 0
		while True:
			bt = self.read_ubyte()
			n |= (bt & 0x7f) << i
			if bt & 0x80 == 0:
				break
			i += 7
			if i > 64:
				raise DecodeError('VarLong too big', '64-bit', str(i) + '-bit')
		return n

	def read_pos_1_8(self) -> tuple[int, int, int]:
		v = self.read_long()
		x = (v >> 38) & 0x3ffffff
		y = (v >> 26) & 0xfff
		z = v & 0x3ffffff
		return x, y, z

	def read_pos_1_14(self) -> tuple[int, int, int]:
		v = self.read_long()
		x = (v >> 38) & 0x3ffffff
		y = v & 0xfff
		z = (v >> 12) & 0x3ffffff
		return x, y, z

	def read_string(self) -> str:
		n = self.read_varint()
		s = self.read(n, err='string is shorter than expected')
		return s.decode('utf8')

	def read_json(self) -> dict:
		n = self.read_varint()
		b = self.read(n, err='json length is shorter than expected')
		return json.loads(b.decode('utf8'))

	def read_uuid(self) -> uuid.UUID:
		v = self.read(16, err='UUID length not correct')
		return uuid.UUID(bytes=v)

	def read_bytearray(self) -> bytes:
		n = self.read_varint()
		return self.read(n, err='bytearray is shorter than expected')

class PacketBuffer:
	__slots__ = ('_data')

	def __init__(self):
		self._data = b''

	@property
	def data(self) -> bytes:
		return self._data

	def write(self, data: bytes):
		self._data += data
		return self

	def write_byte(self, v: int):
		self._data += ByteStruct.pack(v)
		return self

	def write_ubyte(self, v: int):
		self._data += UByteStruct.pack(v)
		return self

	def write_short(self, v: int):
		self._data += ShortStruct.pack(v)
		return self

	def write_ushort(self, v: int):
		self._data += UShortStruct.pack(v)
		return self

	def write_int(self, v: int):
		self._data += IntStruct.pack(v)
		return self

	def write_uint(self, v: int):
		self._data += UIntStruct.pack(v)
		return self

	def write_long(self, v: int):
		self._data += LongStruct.pack(v)
		return self

	def write_ulong(self, v: int):
		self._data += ULongStruct.pack(v)
		return self

	def write_float(self, v :float):
		self._data += FloatStruct.pack(v)
		return self

	def write_double(self, v :float):
		self._data += DoubleStruct.pack(v)
		return self

	def write_bool(self, v: bool):
		self._data += encode_bool(v)
		return self

	def write_varint(self, v: int):
		assert v >> 32 == 0 and v >= 0, f'{hex(v)} is not in range'
		self._data += encode_varint(v)
		return self

	def write_varlong(self, v: int):
		assert v >> 64 == 0 and v >= 0, f'{hex(v)} is not in range'
		self._data += encode_varint(v)
		return self

	def write_pos_1_8(self, v: tuple[int, int, int]):
		x, y, z = v
		self.write_long(((x & 0x3ffffff) << 38) | ((y & 0xfff) << 26) | (z & 0x3ffffff))
		return self

	def write_pos_1_14(self, v: tuple[int, int, int]):
		x, y, z = v
		self.write_long(((x & 0x3ffffff) << 38) | ((z & 0x3ffffff) << 12) | (y & 0xfff))
		return self

	def write_string(self, v: str):
		b = v.encode('utf8')
		self.write_varint(len(b)).write(b)
		return self

	def write_json(self, v: dict):
		b = json.dumps(v).encode('utf8')
		self.write_varint(len(b)).write(b)
		return self

	def write_uuid(self, v: uuid.UUID):
		self.write(v.bytes)
		return self

	def write_bytearray(self, v: bytes):
		self.write_varint(len(v)).write(v)
		return self

class BitSet:
	def __init__(self, value: list[int]):
		self._value = value

	@property
	def value(self) -> list[int]:
		m = 0
		for n in reversed(self._value):
			if not n:
				break
			m += 1
		if m:
			self._value = self._value[:-m]
		return self._value

	def __getitem__(self, index: int, /) -> bool:
		i = index // 64
		if i >= len(self._value):
			return False
		return bool(self._value[i] & (1 << (index % 64)))

	def __setitem__(self, index: int, value: int, /):
		i = index // 64
		if i >= len(self._value):
			self._value.extend(0 for _ in range(len(self._value), i + 1))
		if value:
			self._value[i] |= 1 << (index % 64)
		else:
			self._value[i] &= ~(1 << (index % 64))

	def to_bytes(self, b: PacketBuffer):
		b.write_varint(len(self.value))
		for v in self.value:
			b.write_long(v)

	@classmethod
	def parse_from(cls, r: PacketReader):
		value = []
		for _ in range(r.read_varint()):
			v = r.read_long()
			value.append(v)
		return cls(value)

def recv_package(c, *, forwardto=None) -> PacketReader:
	plen, i = 0, 0
	n = recv_byte(c)
	if n == 0xfe:
		return PacketReader(b'', n)
	while True:
		plen |= (n & 0x7f) << i
		if n & 0x80 == 0:
			break
		i += 7
		if i >= 32:
			raise DecodeError('VarInt too big', '32-bit', str(i) + '-bit')
		n = recv_byte(c)
	data = b''
	while len(data) < plen:
		buf = c.recv(plen - len(data))
		if forwardto is not None:
			forwardto(buf)
		data += buf
	return PacketReader(data)

class ServerStatus:
	def __init__(self, version: str, protocol: int,
		max_player: int, online_player: int, sample_players: list[dict],
		description: dict, favicon: str | None,
		enforcesSecureChat: bool):
		self.version = version
		self.protocol = protocol
		self.max_player = max_player
		self.online_player = online_player
		self.sample_players = sample_players
		self.description = description
		self.favicon = favicon
		self.enforcesSecureChat = False

	def to_json(self) -> dict:
		res: dict = {
			'version': {
				'name': self.version,
				'protocol': self.protocol,
			},
			'players': {
				'max': self.max_player,
				'online': self.online_player,
			},
			'description': self.description,
			'enforcesSecureChat': self.enforcesSecureChat,
		}
		if len(self.sample_players) > 0:
			res['players']['sample'] = self.sample_players
		if self.favicon is not None:
			res['favicon'] = self.favicon
		return res

	@classmethod
	def from_json(cls, value: dict) -> Self:
		version = value['version']['name']
		protocol = value['version']['protocol']
		max_player = value['players']['max']
		online_player = value['players']['online']
		sample_players = value['players'].get('sample', [])
		description = value['description']
		favicon = value.get('favicon', None)
		enforcesSecureChat = value.get('enforcesSecureChat', False)
		return cls(version, protocol,
			max_player, online_player, sample_players,
			description, favicon,
			enforcesSecureChat)
