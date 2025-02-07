
import json
import time

import http.client
import urllib.parse

__all__ = [
	'get_has_joined'
]

MOJANG_SERVER_HOST = 'sessionserver.mojang.com'

def get_has_joined(username: str, serverid: str, ip: str | None = None, retry: int = 3) -> dict | None:
	for i in range(retry):
		data = get_has_joined0(username, serverid, ip)
		if data is not None:
			return data
		time.sleep(0.5)
	return None

def get_has_joined0(username: str, serverid: str, ip: str | None = None) -> dict | None:
	url = f'/session/minecraft/hasJoined?username={urllib.parse.quote(username)}&serverId={urllib.parse.quote(serverid)}'
	if ip is not None:
		url += '&ip=' + urllib.parse.quote(ip)
	try:
		conn = http.client.HTTPSConnection(MOJANG_SERVER_HOST, timeout=10)
		conn.request('GET', url)
		resp = conn.getresponse()
		if resp.status != 200:
			return None
		data = json.load(resp)
		return data
	finally:
		conn.close()
