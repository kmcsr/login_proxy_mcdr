
import struct

__all__ = [
	'ByteStruct', 'UByteStruct', 'ShortStruct', 'UShortStruct',
	'IntStruct', 'UIntStruct', 'LongStruct', 'ULongStruct',
	'FloatStruct', 'DoubleStruct',
	'parse_byte', 'parse_ubyte', 'parse_short', 'parse_ushort',
	'parse_int', 'parse_uint', 'parse_long', 'parse_ulong',
	'parse_float', 'parse_double',
]

ByteStruct   = struct.Struct(">b")
UByteStruct  = struct.Struct(">B")
ShortStruct  = struct.Struct(">h")
UShortStruct = struct.Struct(">H")
IntStruct    = struct.Struct(">i")
UIntStruct   = struct.Struct(">I")
LongStruct   = struct.Struct(">q")
ULongStruct  = struct.Struct(">Q")
FloatStruct  = struct.Struct(">f")
DoubleStruct = struct.Struct(">d")

def parse_byte(buf: bytes):
	return ByteStruct.unpack(buf)[0]

def parse_ubyte(buf: bytes):
	return UByteStruct.unpack(buf)[0]

def parse_short(buf: bytes):
	return ShortStruct.unpack(buf)[0]

def parse_ushort(buf: bytes):
	return UShortStruct.unpack(buf)[0]

def parse_int(buf: bytes):
	return IntStruct.unpack(buf)[0]

def parse_uint(buf: bytes):
	return UIntStruct.unpack(buf)[0]

def parse_long(buf: bytes):
	return LongStruct.unpack(buf)[0]

def parse_ulong(buf: bytes):
	return ULongStruct.unpack(buf)[0]

def parse_float(buf: bytes):
	return FloatStruct.unpack(buf)[0]

def parse_double(buf: bytes):
	return DoubleStruct.unpack(buf)[0]
