
import mcdreforged.api.all as MCDR

import kpi.utils

__all__ = [
	'new_thread', 'tr', 'job_mnr'
]

kpi.utils.export_pkg(globals(), kpi.utils)

def new_thread(call):
	return MCDR.new_thread('login_proxy')(call)

def tr(key: str, *args, **kwargs):
	return MCDR.ServerInterface.get_instance().rtr(f'login_proxy.{key}', *args, **kwargs)

job_mnr = JobManager()
