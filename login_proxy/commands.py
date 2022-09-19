
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
		then(cfg.literal('query').then(MCDR.Text('name').runs(lambda src, ctx: command_query(src, ctx['name'])))).
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
	conns = get_proxy().get_conns()
	gens = []
	if source.has_permission(get_config().minimum_permission_level['query']):
		gens.append(lambda c: new_command(c.ip, action=MCDR.RAction.suggest_command))
	if source.has_permission(get_config().minimum_permission_level['ban']):
		gens.append(lambda c: new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None))
	if source.has_permission(get_config().minimum_permission_level['banip']):
		gens.append(lambda c: new_command('{0} banip {1}'.format(Prefix, c.ip), text='[BANIP]', color=MCDR.RColor.red, styles=None))
	for c in conns:
		send_message(source, '-',
			new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
			*[g(c) for g in gens]
		)
	send_message(source, BIG_BLOCK_AFTER)

def command_query(source: MCDR.CommandSource, name: str):
	c = get_proxy().get_conn(name)
	if c is None:
		send_message(source, MSG_ID, MCDR.RText('Connot find player {}'.format(name), color=MCDR.RColor.red))
		return
	args = []
	if source.has_permission(get_config().minimum_permission_level['ban']):
		args.append(new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None))
	if source.has_permission(get_config().minimum_permission_level['banip']):
		args.append(new_command('{0} banip {1}'.format(Prefix, c.ip), text='[BANIP]', color=MCDR.RColor.red, styles=None))
	send_message(source, '-',
		new_command(c.name, action=MCDR.RAction.suggest_command, styles=None),
		new_command(c.ip, action=MCDR.RAction.suggest_command),
		*args
	)

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
	conn = get_proxy().get_conn(name)
	if conn is not None:
		conn.kick(get_config().messages['banned.name'], server=source.get_server())
	send_message(source, 'Successful banned player {}'.format(name))

def command_banip(source: MCDR.CommandSource, ip: str):
	if ip in ListConfig.instance().bannedip:
		send_message(source, 'IP {} already banned'.format(ip))
		return
	ListConfig.instance().bannedip.append(ip)
	server = source.get_server()
	conns = get_proxy().get_conns_by_ip(ip)
	for c in conns:
		c.kick(get_config().messages['banned.ip'], server=server)
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
