# Sinter fixed backup script (DESIGN §40.7). A constant: never built at run time and never extended; every
# varying value arrives as an argument. Run as root: sh -c <this text> sh <uid> <gid> <source> <dest> <max-bytes> <acl>
# Copies one regular file of account <uid>'s directory tree into a private backup run directory. Everything about
# the source runs as the account (setpriv); everything about the destination runs as root. What crosses from the
# account to root is hostile input: the content is bytes for one file, capped and never interpreted; metadata must
# match a strict grammar. Exit: 0 copied ("OK <size>"), 3 REJECT (nothing kept: a partial destination is removed).
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
reject() { printf 'REJECT: %s\n' "$1" >&2; exit 3; }
digits() { case $1 in ''|*[!0-9]*) return 1;; esac; [ "${#1}" -le 18 ]; }
[ $# = 6 ] || reject "bad arguments"
uid=$1 gid=$2 src=$3 dest=$4 max=$5 acl=$6
digits "$uid" && digits "$gid" && digits "$max" || reject "bad arguments"
case $src in /*) ;; *) reject "bad arguments";; esac
case $dest in /*) ;; *) reject "bad arguments";; esac
case $acl in 0|1) ;; *) reject "bad arguments";; esac
[ "$(id -u)" = 0 ] || reject "not running as root"
[ "$uid" != 0 ] || reject "the tree belongs to root"
cd /
# A new session and no terminal on stdin: the account's processes cannot reach a controlling terminal.
asuser() { setsid -w setpriv --reuid "$uid" --regid "$gid" --init-groups --no-new-privs -- "$@" </dev/null; }
snapshot() { asuser stat -c '%f %u %g %h %s %.9Y %.9Z %d %i %.9X' -- "$src" 2>/dev/null; }
made=0
cleanup() { if [ "$made" = 1 ]; then rm -f -- "$dest"; fi; }
trap cleanup EXIT
trap 'exit 3' HUP INT TERM
first=$(snapshot | head -c 512)
[ -n "$first" ] || reject "cannot observe the file as its account"
case $first in *[!0-9a-f\ .]*) reject "unexpected metadata";; esac
# shellcheck disable=SC2086 # the grammar above leaves only digits, a-f, dots and spaces to split
set -- $first
[ $# = 10 ] || reject "unexpected metadata"
raw=$1 fuid=$2 fgid=$3 links=$4 size=$5 mtime=$6 ctime=$7 dev=$8 ino=$9 atime=${10}
case $raw in ''|*[!0-9a-f]*) reject "unexpected metadata";; esac
[ "${#raw}" -le 8 ] || reject "unexpected metadata"
for n in "$fuid" "$fgid" "$links" "$size" "$dev" "$ino"; do digits "$n" || reject "unexpected metadata"; done
for t in "$mtime" "$ctime" "$atime"; do
  case $t in ''|*[!0-9.]*|*.*.*) reject "unexpected metadata";; esac
done
mode=$(( 0x$raw ))
[ $(( mode & 61440 )) = 32768 ] || reject "not a regular file"
[ "$fuid" = "$uid" ] || reject "the file is not owned by the account of its directory tree"
[ "$links" = 1 ] || reject "the file has more than one hard link"
[ $(( mode & 3072 )) = 0 ] || reject "the file is setuid or setgid"
[ "$size" -le "$max" ] || reject "the file is larger than the limit"
( set -C; : > "$dest" ) 2>/dev/null || reject "the destination exists or cannot be created"
made=1
limit=$(( max + 1 ))
rc=$( { { if asuser dd "if=$src" iflag=nofollow,nonblock bs=65536 status=none 2>/dev/null 3>&-; then printf 0 >&3; else printf 1 >&3; fi; } | head -c "$limit" > "$dest"; } 3>&1 ) || reject "cannot write the destination"
[ "$rc" = 0 ] || reject "cannot read the file as its account"
second=$(snapshot | head -c 512)
[ "${first% *}" = "${second% *}" ] || reject "the file changed while it was being read"
written=$(( $(wc -c < "$dest") ))
[ "$written" = "$size" ] || reject "the copy does not have the size of the file"
chown "$fuid:$fgid" -- "$dest" || reject "cannot set the owner of the copy"
chmod "$(printf '%o' $(( mode & 511 )))" -- "$dest" || reject "cannot set the mode of the copy"
if [ "$acl" = 1 ]; then
  text=$(asuser getfacl --omit-header --numeric --absolute-names -- "$src" 2>/dev/null | head -c 65537)
  [ -n "$text" ] || reject "cannot read the ACL as its account"
  [ "${#text}" -le 65536 ] || reject "unexpected ACL text"
  flat=$(printf '%s' "$text" | tr '\n\t' '  ')
  case $flat in *[!a-z0-9:#\ -]*) reject "unexpected ACL text";; esac
  printf '%s\n' "$text" | setfacl --set-file=- -- "$dest" 2>/dev/null || reject "cannot set the ACL of the copy"
fi
touch -m -d "@$mtime" -- "$dest" || reject "cannot set the times of the copy"
touch -a -d "@$atime" -- "$dest" || reject "cannot set the times of the copy"
made=0
printf 'OK %s\n' "$size"
