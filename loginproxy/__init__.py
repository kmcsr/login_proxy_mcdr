
import mcdreforged.api.all as MCDR

from . import constants
from .constants import *
from . import configs
from .utils import *
from . import commands as CMD
from .encoder import DecodeError, PacketReader, PacketBuffer, BitSet
from . import server
from .server import *
from . import api
from .api import *

__all__ = [
	'DecodeError', 'PacketReader', 'PacketBuffer', 'BitSet',
]

__all__.extend(api.__all__)
__all__.extend(server.__all__)
__all__.extend(constants.__all__)

def on_load(server: MCDR.PluginServerInterface, prev_module):
	if prev_module is None:
		log_info('Login proxy is on LOAD')
	else:
		log_info('Login proxy is on RELOAD')
	configs.init(server)
	api.on_load(server, prev_module)
	CMD.register(server)

def on_unload(server: MCDR.PluginServerInterface):
	log_info('Login proxy is on UNLOAD')
	api.on_unload(server)

def on_server_start(server: MCDR.PluginServerInterface):
	api.on_server_start(server)

def on_server_stop(server: MCDR.PluginServerInterface, code: int):
	api.on_server_stop(server, code)
