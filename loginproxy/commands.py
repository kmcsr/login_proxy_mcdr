
import threading
import time
import uuid
from typing import TypeVar

import mcdreforged.api.all as MCDR

from kpi.command import *

from .configs import *
from .utils import *
from .api import *
from . import mojang

Prefix = '!!lp'

def register(server: MCDR.PluginServerInterface):
	cfg = get_config()
	lists = ListConfig.instance()
	assert lists is not None

	Commands(config=cfg, lists=lists).register_to(server)

def tr_res(key, *args, **kwargs):
	return tr(f'message.response.{key}', *args, **kwargs)

def parse_network_or_error(source: MCDR.CommandSource, ip: str):
	try:
		return IPNetwork(ip)
	except ValueError:
		send_message(source, MSG_ID,
			MCDR.RText(tr('message.error.must_be_ip'), color=MCDR.RColor.red, styles=MCDR.RStyle.underlined))
		return None

Self = TypeVar("Self", bound="Commands")

class Commands(PermCommandSet):
	Prefix = Prefix
	HelpMessage = 'Login Proxy help message'

	def __init__(self, *args, config: LPConfig, lists: ListConfig, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self.__config = config
		self.__lists = lists
		self.__api_cache_lock = threading.Lock()
		self.__api_cache_expire = 0.0
		self.__id2name: dict[uuid.UUID, str] = {}
		self.__name2id: dict[str, uuid.UUID] = {}

	@property
	def config(self):
		return self.__config

	@property
	def lists(self):
		return self.__lists

	def has_permission(self, src: MCDR.CommandSource, literal: str) -> bool:
		return self.config.has_permission(src, literal)

	def help(self, source: MCDR.CommandSource):
		send_message(source, BIG_BLOCK_BEFOR, tr('help_msg', Prefix), BIG_BLOCK_AFTER, sep='\n')

	def get_player_uuid(self, name: str) -> uuid.UUID | None:
		now = time.time()
		uid = self.__name2id.get(name, None) if now < self.__api_cache_expire else None
		if uid is None:
			with self.__api_cache_lock:
				if now >= self.__api_cache_expire:
					self.__name2id.clear()
					self.__id2name.clear()
					self.__api_cache_expire = now + self.config.uuid_cache_ttl
				uid = self.__name2id.get(name, None)
				if uid is None:
					uid = mojang.get_player_uuid(name)
					if uid is not None:
						self.__id2name[uid] = name
						self.__name2id[name.lower()] = uid
		return uid

	def get_player_name(self, uid: uuid.UUID) -> str | None:
		now = time.time()
		name = self.__id2name.get(uid, None) if now < self.__api_cache_expire else None
		if name is None:
			with self.__api_cache_lock:
				if now >= self.__api_cache_expire:
					self.__name2id.clear()
					self.__id2name.clear()
					self.__api_cache_expire = now + self.config.uuid_cache_ttl
				name = self.__id2name.get(uid, None)
				if name is None:
					name = mojang.get_player_name(uid)
					if name is not None:
						self.__id2name[uid] = name
						self.__name2id[name.lower()] = uid
		return name

	def _format_uuid(self, player: str) -> str:
		try:
			uid = uuid.UUID(player)
		except ValueError:
			return player
		name = self.get_player_name(uid)
		return f'<unknown>({uid})' if name is None else f'{name}({uid})'

	@Literal(['list', 'ls'])
	def list(self, source: MCDR.CommandSource):
		send_message(source, BIG_BLOCK_BEFOR)
		send_message(source, 'Connected players:')
		conns = get_proxy().get_conns()
		gens = []
		if self.has_permission(source, 'query'):
			gens.append(lambda c: new_command(c.ip, action=MCDR.RAction.suggest_command))
		if self.has_permission(source, 'ban'):
			gens.append(lambda c: new_command('{0} ban {1}'.format(Prefix, c.name),
				text='[BAN]', color=MCDR.RColor.red, styles=None))
		if self.has_permission(source, 'banip'):
			gens.append(lambda c: new_command('{0} banip {1}'.format(Prefix, c.ip),
				text='[BANIP]', color=MCDR.RColor.red, styles=None))
		for c in conns:
			send_message(source, '-',
				new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
				*[g(c) for g in gens]
			)
		send_message(source, BIG_BLOCK_AFTER)

	@Literal('query')
	def query(self, source: MCDR.CommandSource, name: str):
		c = get_proxy().get_conn(name)
		if c is None:
			send_message(source, MSG_ID, MCDR.RText('Connot find player {}'.
				format(name), color=MCDR.RColor.red))
			return
		args = []
		if self.has_permission(source, 'ban'):
			args.append(new_command('{0} ban {1}'.format(Prefix, c.name),
				text='[BAN]', color=MCDR.RColor.red, styles=None))
		if self.has_permission(source, 'banip'):
			args.append(new_command('{0} banip {1}'.format(Prefix, c.ip),
				text='[BANIP]', color=MCDR.RColor.red, styles=None))
		send_message(source, '-',
			new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
			new_command(c.ip, action=MCDR.RAction.suggest_command),
			*args
		)

	@Literal('banned')
	def banned(self, source: MCDR.CommandSource):
		send_message(source, BIG_BLOCK_BEFOR)
		send_message(source, 'Banned players:')
		for p in self.lists.banned:
			send_message(source, '-', self._format_uuid(p), new_command(
				'{0} pardon {1}'.format(Prefix, p), text='[-]',
				action=MCDR.RAction.suggest_command, color=MCDR.RColor.red, styles=None).
				h('Pardon player {}'.format(p)))
		send_message(source, 'Banned ips:')
		for p in self.lists.bannedip:
			sp = str(p)
			send_message(source, '-', sp, new_command(
				'{0} pardonip {1}'.format(Prefix, sp), text='[-]',
				action=MCDR.RAction.suggest_command, color=MCDR.RColor.red, styles=None).
				h('Pardon ip {}'.format(sp)))
		send_message(source, BIG_BLOCK_AFTER)

	@Literal('ban')
	def ban(self, source: MCDR.CommandSource, name: str):
		names = name
		namel = name.lower()
		if self.config.online_mode and self.config.identify_by_online_uuid:
			try:
				uid = uuid.UUID(name)
			except ValueError:
				uid = None
			if uid is None:
				uid = self.get_player_uuid(name)
				if uid is None:
					send_message(source, MSG_ID, tr_res('player.not_found', name))
					return
			else:
				name0 = self.get_player_name(uid)
				if name0 is None:
					send_message(source, MSG_ID, tr_res('player.id_not_found', uid))
					return
				name = name0
			names = f'{name}({uid})'
			namel = str(uid)
		if namel in self.lists.banned:
			send_message(source, MSG_ID, tr_res('player.already_banned', names))
			return
		self.lists.banned.append(namel)
		conn = get_proxy().get_conn(name)
		if conn is not None:
			conn.kick(self.config.messages['banned.name'], server=source.get_server())
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.banned', names))

	@Literal('banip')
	def banip(self, source: MCDR.CommandSource, ip: str):
		ip0 = parse_network_or_error(source, ip)
		if ip0 is None:
			return
		if ip0 in self.lists.bannedip:
			send_message(source, MSG_ID, tr_res('ip.already_banned', ip0))
			return
		self.lists.bannedip.append(ip0)
		server = source.get_server()
		msg = self.config.messages['banned.ip']
		conns = get_proxy().get_conns_by_ip(ip)
		for c in conns:
			c.kick(msg, server=server)
		self.lists.save()
		send_message(source, MSG_ID, tr_res('ip.banned', ip0))

	@Literal('pardon')
	def pardon(self, source: MCDR.CommandSource, name: str):
		names = name
		namel = name.lower()
		if self.config.online_mode and self.config.identify_by_online_uuid:
			try:
				uid = uuid.UUID(name)
			except ValueError:
				uid = None
			if uid is None:
				uid = self.get_player_uuid(name)
				if uid is None:
					send_message(source, MSG_ID, tr_res('player.not_found', name))
					return
			else:
				name0 = self.get_player_name(uid)
				if name0 is None:
					send_message(source, MSG_ID, tr_res('player.id_not_found', uid))
					return
				name = name0
			names = f'{name}({uid})'
			namel = str(uid)
		try:
			self.lists.banned.remove(namel)
		except ValueError:
			send_message(source, MSG_ID, tr_res('player.not_banned', names))
			return
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.unbanned', names))

	@Literal('pardonip')
	def pardonip(self, source: MCDR.CommandSource, ip: str):
		ip0 = parse_network_or_error(source, ip)
		if ip0 is None:
			return
		try:
			self.lists.bannedip.remove(ip0)
		except ValueError:
			send_message(source, MSG_ID, tr_res('ip.not_banned', ip0))
			return
		self.lists.save()
		send_message(source, MSG_ID, tr_res('ip.unbanned', ip0))

	@Literal(['whitelist', 'wh'])
	class whitelist(PermCommandSet):	
		@call_with_root
		def has_permission(self: Self, src: MCDR.CommandSource, literal: str) -> bool:
			if literal in ('enable', 'enableip'):
				return self.config.has_permission(src, 'enable')
			if literal in ('disable', 'disableip'):
				return self.config.has_permission(src, 'disable')
			return True

		@call_with_root
		def default(self: Self, source: MCDR.CommandSource):
			send_message(source, BIG_BLOCK_BEFOR)
			send_message(source, 'Whitelist Level:', self.config.whitelist_level)
			send_message(source, 'Allowed players',
				'({})'.format(tr('word.enabled' if self.config.enable_whitelist else 'word.disabled')),
				new_command('{0} whitelist disable'.format(Prefix), text='[{}]'.format(tr('button.disable')),
					color=MCDR.RColor.red).h(tr('message.button.whitelist.disable'))
				if self.config.enable_whitelist else
				new_command('{0} whitelist enable'.format(Prefix), text='[{}]'.format(tr('button.enable')),
					color=MCDR.RColor.green).h(tr('message.button.whitelist.enable')),
				':')
			gens = []
			if self.has_permission(source, 'query'):
				gens.append(lambda p: new_command('{0} query {1}'.format(Prefix, p),
					text='[Q]', color=MCDR.RColor.light_purple, styles=None))
			if self.has_permission(source, 'ban'):
				gens.append(lambda p: new_command('{0} ban {1}'.format(Prefix, p),
					text='[B]', color=MCDR.RColor.red, styles=None))
			if self.has_permission(source, 'remove'):
				gens.append(lambda p: new_command('{0} remove {1}'.format(Prefix, p),
					text='[R]', color=MCDR.RColor.red))
			for p in self.lists.allowed:
				send_message(source, '-',
					new_command(self._format_uuid(p), action=MCDR.RAction.suggest_command, styles=None),
					*[g(p) for g in gens])

			send_message(source, 'Allowed ips',
				'({})'.format(tr('word.enabled' if self.config.enable_ip_whitelist else 'word.disabled')),
				new_command('{0} whitelist disableip'.format(Prefix), text='[{}]'.format(tr('button.disable')),
					color=MCDR.RColor.red).h(tr('message.button.whitelist.disable_ip'))
				if self.config.enable_ip_whitelist else
				new_command('{0} whitelist enableip'.format(Prefix), text='[{}]'.format(tr('button.enable')),
					color=MCDR.RColor.green).h(tr('message.button.whitelist.enable_ip')),
				':')
			gens = []
			if self.has_permission(source, 'banip'):
				gens.append(lambda p: new_command('{0} banip {1}'.format(Prefix, p),
					text='[B]', color=MCDR.RColor.red, styles=None))
			if self.has_permission(source, 'removeip'):
				gens.append(lambda p: new_command('{0} removeip {1}'.format(Prefix, p),
					text='[R]', color=MCDR.RColor.red))
			for p in self.lists.allowedip:
				sp = str(p)
				send_message(source, '-',
					new_command(sp, action=MCDR.RAction.suggest_command),
					*[g(sp) for g in gens])
			send_message(source, BIG_BLOCK_AFTER)

		@Literal('enable')
		@call_with_root
		def enable(self: Self, source: MCDR.CommandSource):
			if self.config.enable_whitelist:
				send_message(source, MSG_ID,
					MCDR.RText(tr_res('whitelist.already_enabled'), color=MCDR.RColor.red))
				return
			self.config.enable_whitelist = True
			allows = self.lists.allowed
			for c in get_proxy().get_conns():
				if c.name not in allows and not self.config.check_player_level(c.name):
					c.kick(self.config.messages['whitelist.name'], server=source.get_server())
			send_message(source, MSG_ID, tr_res('whitelist.enabled'))

		@Literal('disable')
		@call_with_root
		def disable(self: Self, source: MCDR.CommandSource):
			if not self.config.enable_whitelist:
				send_message(source, MSG_ID,
					MCDR.RText(tr_res('whitelist.already_disabled'), color=MCDR.RColor.red))
				return
			self.config.enable_whitelist = False
			send_message(source, MSG_ID, tr_res('whitelist.disabled'))

		@Literal('enableip')
		@call_with_root
		def enableip(self: Self, source: MCDR.CommandSource):
			if self.config.enable_ip_whitelist:
				send_message(source, MSG_ID,
					MCDR.RText(tr_res('ipwhitelist.already_enabled'), color=MCDR.RColor.red))
				return
			self.config.enable_ip_whitelist = True
			for c in get_proxy().get_conns():
				if not self.lists.is_allowedip(c.ip) and not self.config.check_player_level(c.name):
					c.kick(self.config.messages['whitelist.ip'], server=source.get_server())
			send_message(source, MSG_ID, tr_res('ipwhitelist.enabled'))

		@Literal('disableip')
		@call_with_root
		def disableip(self: Self, source: MCDR.CommandSource):
			if not self.config.enable_ip_whitelist:
				send_message(source, MSG_ID,
					MCDR.RText(tr_res('ipwhitelist.already_disabled'), color=MCDR.RColor.red))
				return
			self.config.enable_ip_whitelist = False
			send_message(source, MSG_ID, tr_res('ipwhitelist.disabled'))

	@Literal('allow')
	def allow(self, source: MCDR.CommandSource, name: str):
		names = name
		namel = name.lower()
		if self.config.online_mode and self.config.identify_by_online_uuid:
			try:
				uid = uuid.UUID(name)
			except ValueError:
				uid = None
			if uid is None:
				uid = self.get_player_uuid(name)
				if uid is None:
					send_message(source, MSG_ID, tr_res('player.not_found', name))
					return
			else:
				name0 = self.get_player_name(uid)
				if name0 is None:
					send_message(source, MSG_ID, tr_res('player.id_not_found', uid))
					return
				name = name0
			names = f'{name}({uid})'
			namel = str(uid)
		if namel in self.lists.allowed:
			send_message(source, MSG_ID, tr_res('player.already_allowed', names))
			return
		self.lists.allowed.append(namel)
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.allowed', names))

	@Literal('allowip')
	def allowip(self, source: MCDR.CommandSource, ip: str):
		ip0 = parse_network_or_error(source, ip)
		if ip0 is None:
			return
		if ip0 in self.lists.allowedip:
			send_message(source, MSG_ID, tr_res('ip.already_allowed', ip))
			return
		self.lists.allowedip.append(ip0)
		self.lists.save()
		send_message(source, MSG_ID, tr_res('ip.allowed', ip0))

	@Literal(['remove', 'rm'])
	def remove(self, source: MCDR.CommandSource, name: str):
		names = name
		namel = name.lower()
		if self.config.online_mode and self.config.identify_by_online_uuid:
			try:
				uid = uuid.UUID(name)
			except ValueError:
				uid = None
			if uid is None:
				uid = self.get_player_uuid(name)
				if uid is None:
					send_message(source, MSG_ID, tr_res('player.not_found', name))
					return
			else:
				name0 = self.get_player_name(uid)
				if name0 is None:
					send_message(source, MSG_ID, tr_res('player.id_not_found', uid))
					return
				name = name0
			names = f'{name}({uid})'
			namel = str(uid)
		try:
			self.lists.allowed.remove(namel)
		except ValueError:
			send_message(source, MSG_ID, tr_res('player.not_exists', names))
			return
		if self.config.enable_whitelist and not self.config.check_player_level(name):
			conn = get_proxy().get_conn(name)
			if conn is not None:
				conn.kick(self.config.messages['whitelist.name'], server=source.get_server())
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.removed', names))

	@Literal(['removeip', 'rmip'])
	def removeip(self, source: MCDR.CommandSource, ip: str):
		ip0 = parse_network_or_error(source, ip)
		if ip0 is None:
			return
		try:
			self.lists.allowedip.remove(ip0)
		except ValueError:
			send_message(source, MSG_ID, tr_res('ip.not_exists', ip0))
			return
		if self.config.enable_ip_whitelist:
			server = source.get_server()
			msg = self.config.messages['whitelist.ip']
			conns = get_proxy().get_conns_by_network(ip0)
			for c in conns:
				if not self.config.check_player_level(c.ip):
					c.kick(msg, server=server)
		self.lists.save()
		send_message(source, MSG_ID, tr_res('ip.removed', ip0))

def is_uuid(s: str) -> bool:
	try:
		uuid.UUID(s)
	except ValueError:
		return False
	return True
