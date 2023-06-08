
import mcdreforged.api.all as MCDR

from .protocols import Protocol

__all__ = [
	'ON_CONNECT', 'ON_LOGIN', 'ON_PING',
	'Protocol',
]

ON_CONNECT = MCDR.LiteralEvent('login_proxy.on.connect')
ON_PING    = MCDR.LiteralEvent('login_proxy.on.ping')
ON_LOGIN   = MCDR.LiteralEvent('login_proxy.on.login')
