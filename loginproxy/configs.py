
import copy
import ipaddress
import typing
from typing import List, Dict, Optional, ClassVar, Self, TypeVar

import mcdreforged.api.all as MCDR

from kpi.config import *
from kpi.utils import LazyData
from .utils import *

__all__ = [
	'MSG_ID', 'BIG_BLOCK_BEFOR', 'BIG_BLOCK_AFTER',
	'LPConfig', 'IPNetwork', 'ListConfig',
	'get_config', 'init',
]

MSG_ID = MCDR.RText('[LP]', color=MCDR.RColor.light_purple)
BIG_BLOCK_BEFOR = LazyData(lambda data:
	MCDR.RText('------------ {0} v{1} ::::'.format(data.name, data.version), color=MCDR.RColor.aqua))
BIG_BLOCK_AFTER = LazyData(lambda data:
	MCDR.RText(':::: {0} v{1} ============'.format(data.name, data.version), color=MCDR.RColor.aqua))

class LPConfig(Config, msg_id=MSG_ID):
	# 0:guest 1:user 2:helper 3:admin 4:owner
	class minimum_permission_level(JSONObject):
		list: int = 1
		query: int = 2
		banned: int = 2
		ban: int = 2
		banip: int = 3
		pardon: int = 3
		pardonip: int = 3
		whitelist: int = 2
		enable: int = 3
		disable: int = 3
		allow: int = 3
		allowip: int = 3
		remove: int = 3
		removeip: int = 3

	class proxy_addr(JSONObject):
		ip: Optional[str] = ''
		port: int = 25565
		ipv6: Optional[str] = '::'
		ipv6_port: int = 25565

	enable_whitelist: bool = False
	enable_ip_whitelist: bool = False
	whitelist_level: int = 3
	kick_cmd: Optional[str] = 'kick {name} {reason}'
	messages: Dict[str, str] = {
		'banned.name': 'Your account has been banned',
		'banned.ip': 'Your ip has been banned',
		'whitelist.name': 'Your account is not in the whitelist',
		'whitelist.ip': 'Your ip is not in the whitelist',
	}

	allow_transfer: bool = True
	enable_packet_proxy: bool = False
	online_mode: bool = False
	identify_by_online_uuid: bool = True
	uuid_cache_ttl: int = 60 * 60

	def check_player_level(self, name: str) -> bool:
		return get_server_instance().get_permission_level(name) >= self.whitelist_level

class IPNetwork(JSONSerializable):
	def __init__(self, ip: str | None = None):
		self._v = None if ip is None else ipaddress.ip_network(ip)

	@property
	def v(self):
		return self._v

	@v.setter
	def v(self, v):
		if isinstance(v, str):
			v = ipaddress.ip_network(v)
		assert_instanceof(v, (ipaddress.IPv4Network, ipaddress.IPv6Network))
		self._v = v

	@memo_wrapper
	def __deepcopy__(self, memo: dict):
		cls = self.__class__
		other = cls.__new__(cls)
		other._v = copy.deepcopy(self.v)
		return other

	@memo_wrapper
	def serialize(self, memo: dict) -> str:
		return str(self.v)

	def update(self, data: str):
		assert_instanceof(data, str)
		self.v = data

	def __iter__(self):
		return iter(self.v)

	def __contains__(self, other):
		if isinstance(other, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
			return other in self.v
		return False

	def __str__(self):
		return str(self.v)

	def __eq__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v == other.v
		return self.v == other

	def __ne__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v != other.v
		return self.v != other

	def __gt__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v > other.v
		return self.v > other

	def __lt__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v > other.v
		return self.v > other

	def __ge__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v > other.v
		return self.v > other

	def __le__(self, other):
		assert_instanceof(other, (str, IPNetwork, ipaddress.IPv4Network, ipaddress.IPv6Network))
		if isinstance(other, str):
			other = ipaddress.ip_network(other)
		elif isinstance(other, IPNetwork):
			return self.v > other.v
		return self.v > other

@typing.final
class ListConfig(JSONStorage):
	_instance: ClassVar[Optional[Self]] = None

	banned: List[str] = []
	allowed: List[str] = []
	bannedip: List[IPNetwork] = []
	allowedip: List[IPNetwork] = []

	@classmethod
	def instance(cls) -> Optional[Self]:
		return cls._instance

	def is_bannedip(self, ip):
		if isinstance(ip, str):
			ip = ipaddress.ip_address(ip)
		assert_instanceof(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
		for p in self.bannedip:
			if ip in p:
				return True
		return False

	def is_allowedip(self, ip):
		if isinstance(ip, str):
			ip = ipaddress.ip_address(ip)
		assert_instanceof(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
		for p in self.allowedip:
			if ip in p:
				return True
		return False

def get_config() -> LPConfig:
	return LPConfig.instance()

def init(server: MCDR.PluginServerInterface):
	global BIG_BLOCK_BEFOR, BIG_BLOCK_AFTER
	metadata = server.get_self_metadata()
	LazyData.load(BIG_BLOCK_BEFOR, metadata)
	LazyData.load(BIG_BLOCK_AFTER, metadata)
	LPConfig.init_instance(server, load_after_init=True).save()
	ListConfig._instance = ListConfig(server, 'list.json', sync_update=True, load_after_init=True)
