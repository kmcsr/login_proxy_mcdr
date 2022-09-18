#!/bin/bash

cd $(dirname $0)
BASE_DIR=$(pwd)
mkdir -p test
cd test

function set_mcdr_config(){
	while IFS='' read line; do
		if [[ "${line}" == 'advanced_console:'* ]]; then
			echo 'advanced_console: false'
		elif [[ "${line}" == 'check_update:'* ]]; then
			echo 'check_update: false'
		elif [[ "${line}" == 'disable_console_color:'* ]]; then
			echo 'disable_console_color: true'
		elif [[ "${line}" == 'debug:'* ]]; then
			echo "${line}"
			IFS='' read line
			if [[ "${line}" == '  all:'* ]]; then
				echo '  all: true'
			fi
		else
			echo "${line}"
		fi
	done <config.yml >.tmp.config.yml
	cp .tmp.config.yml config.yml
	rm .tmp.config.yml
}

if ! python3 --version; then
	echo '[ERROR] Cannot find python3'
	exit 2
fi

if ! [ -f config.yml ]; then
	echo '==> Initing mcdreforged'
	python3 -m mcdreforged init || exit $?
	set_mcdr_config
fi

if ! [ -n "$SERVER_URL" ]; then
	SERVER_URL=https://piston-data.mojang.com/v1/objects/f69c284232d7c7580bd89a5a4931c3581eae1378/server.jar
fi
SERVER_DIR=server
SERVRE_JAR=$SERVER_DIR/minecraft_server.jar

if ! [ -f "$SERVRE_JAR" ]; then
	echo "==> Getting '$SERVER_URL'"
	if ! wget -O "$SERVRE_JAR" "$SERVER_URL" 2>/dev/null; then
		curl -L --output "$SERVRE_JAR" "$SERVER_URL" || exit $?
	fi
fi

echo '==> Packing plugin'

P=$(pwd)
cd ${BASE_DIR}
_id=($(python3 -c "import json
o = json.load(open('mcdreforged.plugin.json','r'))
print(o['id'])"))
if [ $? -ne 0 ]; then
	echo
	echo "[ERROR] Cannot parse 'mcdreforged.plugin.json'"
	exit 1
fi

python3 -m mcdreforged pack -o "${P}/plugins" -n "${_id}-dev" || exit $?
cd ${P}

exec python3 -m mcdreforged
