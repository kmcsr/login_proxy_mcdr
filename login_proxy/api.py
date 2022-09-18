
import mcdreforged.api.all as MCDR

from .server import *

__all__ = [
	'get_server'
]

pxserver: ProxyServer = None

def get_server() -> ProxyServer:
	return pxserver

def on_load(server: MCDR.PluginServerInterface):
	global pxserver
	pxserver = ProxyServer(server.get_mcdr_config()['working_directory'])
	pxserver.start()

def on_unload(server: MCDR.PluginServerInterface):
	global pxserver
	pxserver.stop()
	pxserver = None

def on_server_start(server: MCDR.PluginServerInterface):
	pass

def on_server_stop(server: MCDR.PluginServerInterface, code: int):
	pass
