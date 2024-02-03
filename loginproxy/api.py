
import mcdreforged.api.all as MCDR

from .utils import *
from .configs import *
from .server import *

__all__ = [
	'get_proxy'
]

pxserver: ProxyServer | None = None

def get_proxy() -> ProxyServer:
	assert pxserver is not None
	return pxserver

def on_load(server: MCDR.PluginServerInterface, prev_module):
	global pxserver
	pxserver = ProxyServer(server, server.get_mcdr_config()['working_directory'],
		get_config(), ListConfig.instance())
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
