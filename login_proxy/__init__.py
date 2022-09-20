
import mcdreforged.api.all as MCDR

globals_ = globals
from . import globals as GL
from .utils import *
from . import commands as CMD
from . import api

__all__ = []
export_pkg(globals_(), api)

def on_load(server: MCDR.PluginServerInterface, prev_module):
	if prev_module is None:
		log_info('Login proxy is on LOAD')
	else:
		log_info('Login proxy is on RELOAD')
	GL.init(server)
	api.on_load(server, prev_module)
	CMD.register(server)

def on_unload(server: MCDR.PluginServerInterface):
	log_info('Login proxy is on UNLOAD')
	api.on_unload(server)
	GL.destory(server)

def on_server_start(server: MCDR.PluginServerInterface):
	api.on_server_start(server)

def on_server_stop(server: MCDR.PluginServerInterface, code: int):
	api.on_server_stop(server, code)
