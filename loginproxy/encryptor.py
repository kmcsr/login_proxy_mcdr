
from typing import Protocol

__all__ = [
	'IConnection', 'Encryptor', 'EncryptedConn',
	'new_aes',
]

class IConnection(Protocol):
	def recv(self, n: int) -> bytes:
		raise NotImplementedError()

	def sendall(self, data: bytes) -> None:
		raise NotImplementedError()

	def close(self) -> None:
		raise NotImplementedError()

class Encryptor:
	__slots__ = ('_secret', '_encryptor', '_decryptor')

	def __init__(self, secret: bytes):
		from Crypto.Cipher import AES

		self._secret = secret
		self._encryptor = AES.new(secret, AES.MODE_CFB, iv=secret, segment_size=8)
		self._decryptor = AES.new(secret, AES.MODE_CFB, iv=secret, segment_size=8)

	def secret(self) -> bytes:
		return self._secret

	def encrypt(self, data: bytes) -> bytes:
		return self._encryptor.encrypt(data)

	def decrypt(self, data: bytes) -> bytes:
		return self._decryptor.decrypt(data)

class EncryptedConn:
	__slots__ = ('_conn', '_encryptor')

	def __init__(self, conn: IConnection, encryptor: Encryptor):
		self._conn = conn
		self._encryptor = encryptor

	@property
	def conn(self) -> IConnection:
		return self._conn

	def recv(self, n: int) -> bytes:
		return self._encryptor.decrypt(self._conn.recv(n))

	def sendall(self, data: bytes) -> None:
		self._conn.sendall(self._encryptor.encrypt(data))

	def close(self) -> None:
		self._conn.close()

def new_aes(secret: bytes) -> Encryptor:
	return Encryptor(secret)
