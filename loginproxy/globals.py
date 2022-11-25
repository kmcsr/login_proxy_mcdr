
from typing import List, Dict, Any

import mcdreforged.api.all as MCDR

from kpi.config import Config, JSONStorage
from .utils import *

__all__ = [
	'MSG_ID', 'BIG_BLOCK_BEFOR', 'BIG_BLOCK_AFTER', 'LPConfig', 'ListConfig', 'get_config', 'init', 'destory'
]

MSG_ID = MCDR.RText('[LP]', color=MCDR.RColor.light_purple)
BIG_BLOCK_BEFOR = LazyData(lambda data:
	MCDR.RText('------------ {0} v{1} ::::'.format(data.name, data.version), color=MCDR.RColor.aqua))
BIG_BLOCK_AFTER = LazyData(lambda data:
	MCDR.RText(':::: {0} v{1} ============'.format(data.name, data.version), color=MCDR.RColor.aqua))

class LPConfig(Config, msg_id=MSG_ID):
	# 0:guest 1:user 2:helper 3:admin 4:owner
	minimum_permission_level: Dict[str, int] = {
		'help':      0,
		'list':      1,
		'query':     2,
		'banned':    2,
		'ban':       2,
		'banip':     3,
		'pardon':    3,
		'pardonip':  3,
		'whitelist': 2,
		'enable':    3,
		'disable':   3,
		'allow':     3,
		'allowip':   3,
		'remove':    3,
		'removeip':  3,
	}
	proxy_addr: dict = {
		'ip': '',
		'port': 25565
	}
	enable_whitelist: bool = False
	enable_ip_whitelist: bool = False
	whitelist_level: int = 3
	kick_cmd: str = 'kick {name} {reason}'
	messages: Dict[str, str] = {
		'banned.name': 'Your account has been banned',
		'banned.ip': 'Your ip has been banned',
		'whitelist.name': 'Your account not in the whitelist',
		'whitelist.ip': 'Your ip not in the whitelist',
	}

class ListConfig(JSONStorage):
	_instance = None

	banned: List[str] = []
	bannedip: List[str] = []
	allow: List[str] = []
	allowip: List[str] = []

	def __init__(self, *args, sync_update=True, **kwargs):
		super().__init__(*args, sync_update=sync_update, **kwargs)

	@classmethod
	def instance(cls):
		return cls._instance

def get_config():
	return LPConfig.instance

def init(server: MCDR.PluginServerInterface):
	global BIG_BLOCK_BEFOR, BIG_BLOCK_AFTER
	metadata = server.get_self_metadata()
	LazyData.load(BIG_BLOCK_BEFOR, metadata)
	LazyData.load(BIG_BLOCK_AFTER, metadata)
	source = server.get_plugin_command_source()
	LPConfig.init_instance(server, load_after_init=True)
	ListConfig._instance = ListConfig(server, load_after_init=True)

def destory(server: MCDR.PluginServerInterface):
	cfg = get_config()
	if cfg is not None:
		cfg.save()
	lst = ListConfig.instance()
	if lst is not None:
		lst.save()
