
import mcdreforged.api.all as MCDR

from .protocols import Protocol

__all__ = [
	'Protocol',
	'ON_CONNECT', 'ON_DISCONNECT',
	'ON_PING',
	'ON_LOGIN', 'ON_PRE_LOGIN', 'ON_POST_LOGIN', 'ON_LOGOFF',
]

ON_CONNECT    = MCDR.LiteralEvent('login_proxy.on.connect')
ON_DISCONNECT = MCDR.LiteralEvent('login_proxy.on.disconnect')
ON_PING       = MCDR.LiteralEvent('login_proxy.on.ping')
ON_LOGIN      = MCDR.LiteralEvent('login_proxy.on.login')
ON_PRE_LOGIN  = MCDR.LiteralEvent('login_proxy.on.login.pre')
ON_POST_LOGIN = MCDR.LiteralEvent('login_proxy.on.login.post')
ON_LOGOFF     = MCDR.LiteralEvent('login_proxy.on.logoff')
