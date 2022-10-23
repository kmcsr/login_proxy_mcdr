
import io
import json
import uuid

__all__ = [
	'DecodeError',
	'encode_short', 'encode_int', 'encode_long', 'encode_bool', 'encode_varint', 'encode_string', 'encode_json',
	'send_package',
	'recv_byte', 'recv_package', 'Packet',
]

class DecodeError(Exception):
	def __init__(self, reason: str):
		super().__init__(reason)

def encode_short(n: int) -> bytes:
	assert 0 <= n and n <= 0xffff
	return n.to_bytes(2, byteorder='big')

def encode_int(n: int) -> bytes:
	assert 0 <= n and n <= 0xffffffff
	return n.to_bytes(4, byteorder='big')

def encode_long(n: int) -> bytes:
	assert 0 <= n and n <= 0xffffffffffffffff
	return n.to_bytes(8, byteorder='big')

def encode_bool(v: bool) -> bytes:
	return b'\x01' if v else b'\x00'

def encode_varint(n: int) -> bytes:
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
	s = s.encode('utf8')
	return encode_varint(len(s)) + s

def encode_json(obj: dict) -> bytes:
	s = json.dumps(obj).encode('utf8')
	return encode_varint(len(s)) + s

def send_package(c, pid: int, data: bytes):
	assert isinstance(data, bytes)
	pidb = encode_varint(pid)
	c.sendall(encode_varint(len(pidb) + len(data)))
	c.sendall(pidb)
	c.sendall(data)

def recv_byte(c) -> int:
	try:
		return c.recv(1)[0]
	except IndexError:
		raise ConnectionAbortedError() from None

class Packet:
	def __init__(self, data: bytes):
		self._size = len(data)
		self._reader = io.BytesIO(data)

	@property
	def size(self):
		return self._size

	@property
	def reader(self):
		return self._reader

	def read(self, n: int, *, err='buf length wrong'):
		v = self._reader.read(n)
		if len(v) != n:
			raise DecodeError(err)
		return v

	def read_byte(self) -> int:
		v = self.read(1, err='EOF')
		return v[0]

	def read_short(self) -> int:
		v = self.read(2, err='short length not correct')
		return int.from_bytes(v, byteorder='big')

	def read_int(self) -> int:
		v = self.read(4, err='int length not correct')
		return int.from_bytes(v, byteorder='big')

	def read_long(self) -> int:
		v = self.read(8, err='long length not correct')
		return int.from_bytes(v, byteorder='big')

	def read_bool(self) -> bool:
		v = self.read_byte()
		return v != 0x00

	def read_varint(self) -> int:
		n, i = 0, 0
		while True:
			bt = self.read_byte()
			n |= (bt & 0x7f) << i
			if bt & 0x80 == 0:
				break
			i += 7
			if i >= 32:
				raise DecodeError('VarInt too big')
		return n

	def read_string(self) -> str:
		n = self.read_varint()
		s = self.read(n, err='string is shorter than expected')
		return s.decode('utf8')

	def read_json(self) -> dict:
		n = self.read_varint()
		b = self.read(n, err='json length is shorter than expected')
		return json.loads(s.decode('utf8'))

	def read_uuid(self) -> uuid.UUID:
		v = self.read(16)
		if len(v) != 16:
			raise DecodeError('UUID length not correct')
		return uuid.UUID(bytes=v)

def recv_package(c) -> tuple[int, Packet]:
	plen, i = 0, 0
	n = recv_byte(c)
	if n == 0xfe:
		return n, None
	while True:
		plen |= (n & 0x7f) << i
		if n & 0x80 == 0:
			break
		i += 7
		if i >= 32:
			raise DecodeError('VarInt too big')
		n = recv_byte(c)
	data = b''
	while len(data) < plen:
		data += c.recv(plen - len(data))
	pkt = Packet(data)
	pid = pkt.read_varint()
	return pid, pkt
