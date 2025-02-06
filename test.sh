#!/bin/bash

minecraft_version=1.19.2

cd $(dirname $0)
BASE_DIR=$(pwd)
mkdir -p _test
cd _test

function set_mcdr_config(){
	while IFS='' read line; do
		if [[ "${line}" == 'check_update:'* ]]; then
			echo 'check_update: false'
		# elif [[ "${line}" == 'advanced_console:'* ]]; then
		# 	echo 'advanced_console: false'
		# elif [[ "${line}" == 'disable_console_color:'* ]]; then
		# 	echo 'disable_console_color: true'
		elif [[ "${line}" == 'start_command:'* ]]; then
			echo "start_command: ['java', '-Xms1G', '-Xmx2G', '-jar', 'minecraft_server.jar', 'nogui']"
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

SERVER_DIR=server
SERVER_EXE_NAME=minecraft_server

if ! [ -f "$SERVER_DIR/$SERVER_EXE_NAME.jar" ]; then
	echo "==> Getting minecraft $minecraft_version"
	minecraft_installer -output "$SERVER_DIR" -name="$SERVER_EXE_NAME" -version "$minecraft_version" vanilla
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
