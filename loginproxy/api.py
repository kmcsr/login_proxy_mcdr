
import mcdreforged.api.all as MCDR

from .utils import *
from .server import *

__all__ = [
	'get_proxy'
]

pxserver: ProxyServer = None

def get_proxy() -> ProxyServer:
	return pxserver

def on_load(server: MCDR.PluginServerInterface, prev_module):
	global pxserver
	pxserver = ProxyServer(server, server.get_mcdr_config()['working_directory'])
	if prev_module is None:
		pxserver.start(reuse=True)
	else:
		pxserver.start(reuse=True)

def on_unload(server: MCDR.PluginServerInterface):
	global pxserver
	if pxserver is not None:
		pxserver.stop()
		pxserver = None

def on_server_start(server: MCDR.PluginServerInterface):
	pass

def on_server_stop(server: MCDR.PluginServerInterface, code: int):
	pass
