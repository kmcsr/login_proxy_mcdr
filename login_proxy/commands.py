
import mcdreforged.api.all as MCDR

from .globals import *
from .utils import *
from .api import *

Prefix = '!!lp'

def register(server: MCDR.PluginServerInterface):
	cfg = get_config()
	server.register_command(
		MCDR.Literal(Prefix).
		runs(command_help).
		then(cfg.literal('help').runs(command_help)).
		then(cfg.literal('list').runs(command_list)).
		then(cfg.literal('banned').runs(command_banned)).
		then(cfg.literal('ban').then(MCDR.Text('name').runs(lambda src, ctx: command_ban(src, ctx['name'])))).
		then(cfg.literal('banip').then(MCDR.Text('ip').runs(lambda src, ctx: command_banip(src, ctx['ip'])))).
		then(cfg.literal('pardon').then(MCDR.Text('name').runs(lambda src, ctx: command_pardon(src, ctx['name'])))).
		then(cfg.literal('pardonip').then(MCDR.Text('ip').runs(lambda src, ctx: command_pardonip(src, ctx['ip']))))
	)

def command_help(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR, tr('help_msg', Prefix), BIG_BLOCK_AFTER, sep='\n')

def command_list(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR)
	send_message(source, 'Connected players:')
	conns = get_server().get_conns()
	if source.has_permission(3):
		for c in conns:
			send_message(source, '-',
				new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
				new_command(c.ip, action=MCDR.RAction.suggest_command),
				new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None),
				new_command('{0} banip {1}'.format(Prefix, c.ip), text='[BANIP]', color=MCDR.RColor.red, styles=None)
			)
	elif source.has_permission(2):
		for c in conns:
			send_message(source, '-',
				new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
				new_command(c.ip, action=MCDR.RAction.suggest_command),
				new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None)
			)
	else:
		for c in conns:
			send_message(source, '-', new_command(c.name, action=MCDR.RAction.suggest_command, styles=None))
	send_message(source, BIG_BLOCK_AFTER)

def command_banned(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR)
	send_message(source, 'Banned players:')
	for p in ListConfig.instance().banned:
		send_message(source, '-', p, new_command(
			'{0} pardon {1}'.format(Prefix, p), text='[-]',
			action=MCDR.RAction.suggest_command, color=MCDR.RColor.red).h('Pardon player {}'.format(p)))
	send_message(source, 'Banned ips:')
	for p in ListConfig.instance().bannedip:
		send_message(source, '-', p, new_command(
			'{0} pardonip {1}'.format(Prefix, p), text='[-]',
			action=MCDR.RAction.suggest_command, color=MCDR.RColor.red).h('Pardon ip {}'.format(p)))
	send_message(source, BIG_BLOCK_AFTER)

def command_ban(source: MCDR.CommandSource, name: str):
	if name in ListConfig.instance().banned:
		send_message(source, 'Player {} already banned'.format(name))
		return
	ListConfig.instance().banned.append(name)
	send_message(source, 'Successful banned player {}'.format(name))

def command_banip(source: MCDR.CommandSource, ip: str):
	if ip in ListConfig.instance().bannedip:
		send_message(source, 'IP {} already banned'.format(ip))
		return
	ListConfig.instance().bannedip.append(ip)
	send_message(source, 'Successful banned ip {}'.format(ip))

def command_pardon(source: MCDR.CommandSource, name: str):
	if name not in ListConfig.instance().banned:
		send_message(source, 'Player {} has not been banned'.format(name))
		return
	ListConfig.instance().banned.remove(name)
	send_message(source, 'Successful unban player {}'.format(name))

def command_pardonip(source: MCDR.CommandSource, ip: str):
	if ip not in ListConfig.instance().bannedip:
		send_message(source, 'IP {} has not been banned'.format(ip))
		return
	ListConfig.instance().bannedip.remove(ip)
	send_message(source, 'Successful unban ip {}'.format(ip))
