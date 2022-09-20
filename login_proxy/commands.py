
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
		then(cfg.literal('pardonip').then(MCDR.Text('ip').runs(lambda src, ctx: command_pardonip(src, ctx['ip'])))).
		then(cfg.literal('whitelist').runs(command_whitelist)).
		then(cfg.literal('allow').then(MCDR.Text('name').runs(lambda src, ctx: command_allow(src, ctx['name'])))).
		then(cfg.literal('allowip').then(MCDR.Text('ip').runs(lambda src, ctx: command_allowip(src, ctx['ip'])))).
		then(cfg.literal('remove').then(MCDR.Text('name').runs(lambda src, ctx: command_remove(src, ctx['name'])))).
		then(cfg.literal('removeip').then(MCDR.Text('ip').runs(lambda src, ctx: command_removeip(src, ctx['ip']))))
	)

def command_help(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR, tr('help_msg', Prefix), BIG_BLOCK_AFTER, sep='\n')

def command_list(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR)
	send_message(source, 'Connected players:')
	conns = get_proxy().get_conns()
	cfg = get_config()
	gens = []
	if cfg.has_permission(source, 'query'):
		gens.append(lambda c: new_command(c.ip, action=MCDR.RAction.suggest_command))
	if cfg.has_permission(source, 'ban'):
		gens.append(lambda c: new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None))
	if cfg.has_permission(source, 'banip'):
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
	cfg = get_config()
	args = []
	if cfg.has_permission(source, 'ban'):
		args.append(new_command('{0} ban {1}'.format(Prefix, c.name), text='[BAN]', color=MCDR.RColor.red, styles=None))
	if cfg.has_permission(source, 'banip'):
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
	msg = get_config().messages['banned.ip']
	conns = get_proxy().get_conns_by_ip(ip)
	for c in conns:
		c.kick(msg, server=server)
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

def command_whitelist(source: MCDR.CommandSource):
	send_message(source, BIG_BLOCK_BEFOR)
	cfg = get_config()
	send_message(source, 'Allowed players', ':')
	gens = []
	if cfg.has_permission(source, 'query'):
		gens.append(lambda p: new_command('{0} query {1}'.format(Prefix, p), text='[Q]', color=MCDR.RColor.light_purple, styles=None))
	if cfg.has_permission(source, 'ban'):
		gens.append(lambda p: new_command('{0} ban {1}'.format(Prefix, p), text='[B]', color=MCDR.RColor.red, styles=None))
	if cfg.has_permission(source, 'remove'):
		gens.append(lambda p: new_command('{0} remove {1}'.format(Prefix, p), text='[R]', color=MCDR.RColor.red))
	for p in ListConfig.instance().allow:
		send_message(source, '-',
			new_command(p, action=MCDR.RAction.suggest_command, styles=None),
			*[g(p) for g in gens])

	send_message(source, 'Allowed ips', ':')
	gens = []
	if cfg.has_permission(source, 'banip'):
		gens.append(lambda p: new_command('{0} banip {1}'.format(Prefix, p), text='[B]', color=MCDR.RColor.red, styles=None))
	if cfg.has_permission(source, 'removeip'):
		gens.append(lambda p: new_command('{0} removeip {1}'.format(Prefix, p), text='[R]', color=MCDR.RColor.red))
	for p in ListConfig.instance().allowip:
		send_message(source, '-',
			new_command(p, action=MCDR.RAction.suggest_command),
			*[g(p) for g in gens])
	send_message(source, BIG_BLOCK_AFTER)

def command_allow(source: MCDR.CommandSource, name: str):
	if name in ListConfig.instance().allow:
		send_message(source, 'Player {} already in whitelist'.format(name))
		return
	ListConfig.instance().allow.append(name)
	send_message(source, 'Successful allow player {}'.format(name))

def command_allowip(source: MCDR.CommandSource, ip: str):
	if ip in ListConfig.instance().allowip:
		send_message(source, 'IP {} already whitelist'.format(ip))
		return
	ListConfig.instance().allowip.append(ip)
	send_message(source, 'Successful allow ip {}'.format(ip))

def command_remove(source: MCDR.CommandSource, name: str):
	if name not in ListConfig.instance().allow:
		send_message(source, 'Player {} has not in whitelist'.format(name))
		return
	ListConfig.instance().allow.remove(name)
	if get_config().enable_whitelist:
		conn = get_proxy().get_conn(name)
		if conn is not None:
			conn.kick(get_config().messages['whitelist.name'], server=source.get_server())
	send_message(source, 'Successful remove player {}'.format(name))

def command_removeip(source: MCDR.CommandSource, ip: str):
	if ip not in ListConfig.instance().allowip:
		send_message(source, 'IP {} has not in whitelist'.format(ip))
		return
	ListConfig.instance().allowip.remove(ip)
	if get_config().enable_ip_whitelist:
		server = source.get_server()
		msg = get_config().messages['whitelist.ip']
		conns = get_proxy().get_conns_by_ip(ip)
		for c in conns:
			c.kick(msg, server=server)
	send_message(source, 'Successful remove ip {}'.format(ip))
