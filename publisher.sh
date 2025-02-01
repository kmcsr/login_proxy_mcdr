#!/bin/bash

DEV=
COMMIT=true
RELEASE=true

while [ -n "$1" ]; do
	case $1 in
		-p | --packet-only)
			COMMIT=''
			RELEASE=''
			;;
		-C | --no-commit)
			COMMIT=''
			;;
		-R | --no-release)
			RELEASE=''
			;;
		-d | --dev)
			DEV=true
			;;
	esac
	shift
done

cd $(dirname $0)

echo '==> Checking...'
echo

python3.11 -m mypy . || exit $?

echo '==> Reading plugin metadata...'
echo

_PARSER=`cat <<EOF
import json,sys
o = json.load(open(sys.argv[1],"r"))
n, d, v, m = o["name"], o["id"], o["version"], o.get("archive_name")
print((n.replace(" ", "") if n else d), v if not m else m.format(id=d, version=v), v)
EOF`

_TG='mcdreforged.plugin.json'
data=($(python3 -c "$_PARSER" "$_TG"))
if [ $? -ne 0 ]; then
	echo
	echo "[ERROR] Cannot parse '${_TG}'"
	exit 1
fi
name="${data[0]}"
namever="${data[1]}"
version="v${data[2]}"

if [ -n "$DEV" ]; then
	output="${name}-dev"
else
	output="${name}-v${namever}"
fi

echo '==> Packing source files...'
python3 -m mcdreforged pack -o ./output -n "$output" || exit $?

if ! [ -n "$DEV" ]; then
	if [ -n "$COMMIT" ]; then
		echo '==> Commiting git repo...'
		( git add . && git commit -m "$version" && git push ) || exit $?
	fi
	if [ -n "$RELEASE" ]; then
		echo '==> Creating github release...'
		gh release create "$version" "./output/${output}.mcdr" -t "$version" -n '' || exit $?
	fi
fi

echo '==> Done'
