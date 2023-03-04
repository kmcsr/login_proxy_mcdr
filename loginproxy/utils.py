
import mcdreforged.api.all as MCDR

from kpi.utils import *

__all__ = [
	'new_thread', 'tr', 'debug', 'log_info', 'log_warn', 'log_error',
	'get_server_instance',
	'new_timer', 'new_command', 'join_rtext', 'send_message', 'broadcast_message',
	'assert_instanceof',
]

def new_thread(call):
	return MCDR.new_thread('login_proxy')(call)

def tr(key: str, *args, **kwargs):
	return get_server_instance().rtr(f'login_proxy.{key}', *args, **kwargs)
