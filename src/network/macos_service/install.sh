set -eu
umask 077
ulimit -f 131072

stage=$(/usr/bin/mktemp -d /private/tmp/array-connect-vpnd.XXXXXXXX)
trap '/bin/rm -f "$stage/array-connect-vpnd"; /bin/rmdir "$stage"' EXIT
helper="$stage/array-connect-vpnd"

# Treat the .app resource as untrusted until its private copy matches the
# digest compiled into the running desktop app.
[ -f "$1" ] && [ ! -L "$1" ] || exit 1
/bin/cp -P "$1" "$helper"
[ -f "$helper" ] && [ ! -L "$helper" ] || exit 1
digest=$(/usr/bin/shasum -a 256 "$helper")
[ "${digest%% *}" = "$2" ] || { echo "array-connect-vpnd checksum mismatch" >&2; exit 1; }
/bin/chmod 0700 "$helper"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "$helper" --install "$3"
