
import mcdreforged.api.all as MCDR

from .utils import *
from .configs import *
from .server import *
from . import mojang

__all__ = [
	'get_proxy'
]

pxserver: ProxyServer | None = None

def get_proxy() -> ProxyServer:
	assert pxserver is not None
	return pxserver

def on_load(server: MCDR.PluginServerInterface, prev_module):
	global pxserver

	metadata = server.get_self_metadata()

	list_config = ListConfig.instance()
	assert list_config is not None

	mojang.USER_AGENT = 'loginproxy/{0} (https://github.com/kmcsr/login_proxy_mcdr)'.format(metadata.version)

	pxserver = ProxyServer(server, server.get_mcdr_config()['working_directory'],
		get_config(), list_config)
	pxserver.start()

def on_unload(server: MCDR.PluginServerInterface):
	global pxserver
	if pxserver is not None:
		pxserver.stop()
		pxserver = None

def on_server_start(server: MCDR.PluginServerInterface):
	pass

def on_server_stop(server: MCDR.PluginServerInterface, code: int):
	pass
