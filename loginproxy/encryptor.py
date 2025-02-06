
from typing import Protocol

from Crypto.Cipher import AES

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
	def __init__(self, secret: bytes):
		self._secret = secret
		self._encryptor = AES.new(secret, AES.MODE_CFB, iv=secret, segment_size=8)

	def secret(self) -> bytes:
		return self._secret

	def encrypt(self, data: bytes) -> bytes:
		return self._encryptor.encrypt(data)

	def decrypt(self, data: bytes) -> bytes:
		return self._encryptor.decrypt(data)

class EncryptedConn:
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
