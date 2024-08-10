
from typing import TypeVar

import mcdreforged.api.all as MCDR

from kpi.command import *

from .configs import *
from .utils import *
from .api import *

Prefix = '!!lp'

def register(server: MCDR.PluginServerInterface):
	cfg = get_config()

	Commands(config=cfg, lists=ListConfig.instance()).register_to(server)

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

	def __init__(self, *args, config, lists, **kwargs):
		super().__init__(*args, **kwargs)
		self.__config = config
		self.__lists = lists

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
			send_message(source, '-', p, new_command(
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
		if name in self.lists.banned:
			send_message(source, MSG_ID, tr_res('player.already_banned', name))
			return
		self.lists.banned.append(name)
		conn = get_proxy().get_conn(name)
		if conn is not None:
			conn.kick(self.config.messages['banned.name'], server=source.get_server())
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.banned', name))

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
		try:
			self.lists.banned.remove(name)
		except ValueError:
			send_message(source, MSG_ID, tr_res('player.not_banned', name))
			return
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.unbanned', name))

	@Literal('pardonip')
	def pardonip(self, source: MCDR.CommandSource, ip: str):
		ip0 = parse_network_or_error(source, ip)
		if ip0 is None:
			return
		# print('ip0:', ip0, ip0 in self.lists.bannedip)
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
					new_command(p, action=MCDR.RAction.suggest_command, styles=None),
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
		if name in self.lists.allowed:
			send_message(source, MSG_ID, tr_res('player.already_allowed', name))
			return
		self.lists.allowed.append(name)
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.allowed', name))

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
		try:
			self.lists.allowed.remove(name)
		except ValueError:
			send_message(source, MSG_ID, tr_res('player.not_exists', name))
			return
		if self.config.enable_whitelist and not self.config.check_player_level(name):
			conn = get_proxy().get_conn(name)
			if conn is not None:
				conn.kick(self.config.messages['whitelist.name'], server=source.get_server())
		self.lists.save()
		send_message(source, MSG_ID, tr_res('player.removed', name))

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
