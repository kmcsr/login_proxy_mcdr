
import json
import time
import uuid

import http.client
import urllib.parse

__all__ = [
	'get_has_joined',
	'get_player_uuid',
	'get_player_name',
]

USER_AGENT = 'loginproxy/dev (https://github.com/kmcsr/login_proxy_mcdr)'
MOJANG_SESSIONSERVER_HOST = 'sessionserver.mojang.com'
MINECRAFTSERVICE_API_HOST = 'api.minecraftservices.com'

def get_has_joined(username: str, serverid: str, ip: str | None = None, retry: int = 3) -> dict | None:
	for i in range(retry):
		data = get_has_joined0(username, serverid, ip)
		if data is not None:
			return data
		time.sleep(0.2)
	return None

def get_has_joined0(username: str, serverid: str, ip: str | None = None) -> dict | None:
	url = f'/session/minecraft/hasJoined?username={urllib.parse.quote(username)}&serverId={urllib.parse.quote(serverid)}'
	if ip is not None:
		url += '&ip=' + urllib.parse.quote(ip)
	try:
		conn = http.client.HTTPSConnection(MOJANG_SESSIONSERVER_HOST, timeout=10)
		conn.request('GET', url, headers={
			'User-Agent': USER_AGENT,
		})
		resp = conn.getresponse()
		if resp.status != 200:
			return None
		data = json.load(resp)
		return data
	finally:
		conn.close()

def get_player_uuid(username: str) -> uuid.UUID | None:
	url = f'/minecraft/profile/lookup/name/{username}'
	try:
		conn = http.client.HTTPSConnection(MINECRAFTSERVICE_API_HOST, timeout=10)
		conn.request('GET', url, headers={
			'User-Agent': USER_AGENT,
		})
		resp = conn.getresponse()
		if resp.status != 200:
			return None
		data = json.load(resp)
		return uuid.UUID(data['id'])
	finally:
		conn.close()

def get_player_name(uid: uuid.UUID) -> str | None:
	url = f'/minecraft/profile/lookup/{str(uid)}'
	try:
		conn = http.client.HTTPSConnection(MINECRAFTSERVICE_API_HOST, timeout=10)
		conn.request('GET', url, headers={
			'User-Agent': USER_AGENT,
		})
		resp = conn.getresponse()
		if resp.status != 200:
			return None
		data = json.load(resp)
		return data['name']
	finally:
		conn.close()

if __name__ == '__main__':
	print('test get_player_uuid:', get_player_uuid('ckupen'))
	print('test get_player_name:', get_player_name(uuid.UUID('7a0ba4fe-e6ec-4bfe-99fc-56bf677a15a5')))
