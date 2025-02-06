
import mcdreforged.api.all as MCDR

from .protocols import Protocol

__all__ = [
	'Protocol',
	'ON_CONNECT', 'ON_PING', 'ON_LOGIN', 'ON_PRELOGIN', 'ON_POSTLOGIN', 'ON_LOGOFF',
	'ON_PACKET_C2S', 'ON_PACKET_S2C',
]

ON_CONNECT   = MCDR.LiteralEvent('login_proxy.on.connect')
ON_PING      = MCDR.LiteralEvent('login_proxy.on.ping')
ON_LOGIN     = MCDR.LiteralEvent('login_proxy.on.login')
ON_PRELOGIN  = MCDR.LiteralEvent('login_proxy.on.login.pre')
ON_POSTLOGIN = MCDR.LiteralEvent('login_proxy.on.login.post')
ON_LOGOFF    = MCDR.LiteralEvent('login_proxy.on.logoff')

ON_PACKET_C2S = MCDR.LiteralEvent('login_proxy.on.packet.c2s')
ON_PACKET_S2C = MCDR.LiteralEvent('login_proxy.on.packet.s2c')
