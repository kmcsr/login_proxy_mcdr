
from typing import List, Dict, Any

import mcdreforged.api.all as MCDR

from kpi.config import Config

__all__ = [
	'MSG_ID', 'BIG_BLOCK_BEFOR', 'BIG_BLOCK_AFTER', 'LPConfig', 'ListConfig', 'get_config', 'init', 'destory'
]

MSG_ID = MCDR.RText('[LP]', color=MCDR.RColor.light_purple)
BIG_BLOCK_BEFOR = '------------ {0} v{1} ::::'
BIG_BLOCK_AFTER = ':::: {0} v{1} ============'

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
	kick_cmd: str = 'kick {name} {reason}'
	messages: Dict[str, str] = {
		'banned.name': 'Your account has been banned',
		'banned.ip': 'Your ip has been banned',
		'whitelist.name': 'Your account not in the whitelist',
		'whitelist.ip': 'Your ip not in the whitelist',
	}

class ListConfig(MCDR.Serializable):
	_instance = None

	banned: List[str] = []
	bannedip: List[str] = []
	allow: List[str] = []
	allowip: List[str] = []

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._server = None

	def save(self, source: MCDR.CommandSource):
		self._server.save_config_simple(self, file_name='list.json')
		source.reply('List file saved SUCCESS')

	@classmethod
	def load(cls, source: MCDR.CommandSource, server: MCDR.PluginServerInterface = None):
		oldConfig = cls.instance()
		if server is None:
			assert isinstance(oldConfig, cls)
			server = oldConfig._server
		cls._instance = server.load_config_simple(target_class=cls, file_name='list.json', echo_in_console=isinstance(source, MCDR.PlayerCommandSource), source_to_reply=source)
		cls._instance._server = server

	@classmethod
	def instance(cls):
		return cls._instance

def get_config():
	return LPConfig.instance()

def init(server: MCDR.PluginServerInterface):
	global BIG_BLOCK_BEFOR, BIG_BLOCK_AFTER
	metadata = server.get_self_metadata()
	BIG_BLOCK_BEFOR = MCDR.RText(BIG_BLOCK_BEFOR.format(metadata.name, metadata.version), color=MCDR.RColor.aqua)
	BIG_BLOCK_AFTER = MCDR.RText(BIG_BLOCK_AFTER.format(metadata.name, metadata.version), color=MCDR.RColor.aqua)
	source = server.get_plugin_command_source()
	LPConfig.load(source, server)
	ListConfig.load(source, server)

def destory(server: MCDR.PluginServerInterface):
	source = server.get_plugin_command_source()
	lst = ListConfig.instance()
	if lst is not None:
		lst.save(source)
