# Sinter fixed staging script (FS-2). A constant: it is never built at run time and never extended;
# every varying value arrives as an argument. Run as: sh -c <this text> sh <op> <args...>
#   stage     <dir> <dir-id|-> <mode> <uid> <gid> [xattr-name xattr-value ...]   (content on stdin)
#   stagelink <dir> <dir-id|-> <target>
#   publish   <new|replace> <file|link> <dir> <dir-id|-> <S> <G|-> <S-id> <payload-id> <base>
#   discard   <dir> <dir-id|-> <S> <G|-> <S-id>
# stage/stagelink print "<S> <G|-> <S-id> <payload-id>" when S is staged and left in place.
# Exit code = the primary outcome only: 0 done, 3 REJECT (identity not proven: no existing entry was
# changed or removed and, for publish and discard, nothing was published; a stage that is refused after
# its directory was made leaves that empty directory behind), 4 publication failed (nothing published;
# only this code and 3 prove that; an ln/mv killed by a signal ends with 1, not 4), 5 done but a second
# name of the payload remains or the cleanup state is unknown; any other code: a step failed and a
# publication cannot be ruled out. The cleanup result is the last stdout line:
# CLEANUP:clean | CLEANUP:left:<path> | CLEANUP:link-remains:<path> | CLEANUP:unknown.
# S is the private directory ".sinter-stage.XXXXXXXX" made in <dir>. As root its identity is the random
# group G it was created with (setpriv --regid G); unprivileged, <dir> must be one nobody else can
# rename entries in. <dir> is pinned as fd 4 and S as fd 5; whether S is gone is read from fd 5.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ $# -ge 1 ] || { printf 'REJECT: no operation\n' >&2; exit 3; }
op=$1; shift
me=$(id -u)
reject() { printf 'REJECT: %s\n' "$1" >&2; exit 3; }
case $op in
  stage) [ $# -ge 5 ] && [ $(( ($# - 5) % 2 )) = 0 ] || reject "bad arguments";;
  stagelink) [ $# = 3 ] || reject "bad arguments";;
  publish) [ $# = 9 ] || reject "bad arguments";;
  discard) [ $# = 5 ] || reject "bad arguments";;
  *) reject "unknown operation";;
esac

trusted_dir() {  # cwd = <dir>: nobody but root/us can rename or unlink entries here
  st=$(stat -c '%u %a' . 2>/dev/null) || return 1
  set -- $st
  [ $# = 2 ] || return 1
  [ "$1" = 0 ] || [ "$1" = "$me" ] || return 1
  case ${#2} in 1) m=000$2;; 2) m=00$2;; 3) m=0$2;; 4) m=$2;; *) return 1;; esac
  case $m in *[!0-7]*) return 1;; esac
  case ${m%???} in 1|3|5|7) return 0;; esac
  g=${m#??}; g=${g%?}; o=${m#???}
  case $g in 2|3|6|7) return 1;; esac
  case $o in 2|3|6|7) return 1;; esac
  return 0
}
no_setgid() {  # cwd = <dir>: the new directory would inherit the group, so G could not identify it
  m=$(stat -c %a .)
  case ${#m} in 4) case ${m%???} in 2|3|6|7) return 1;; esac;; esac
  return 0
}
valid() {  # <kind> <value>
  case $1 in
    id) case $2 in ''|*[!0-9]*) return 1;; esac;;
    optid) [ "$2" = - ] || valid id "$2";;
    devino) case $2 in ''|*[!0-9:]*|:*|*:|*:*:*) return 1;; *:*) ;; *) return 1;; esac;;
    optdevino) [ "$2" = - ] || valid devino "$2";;
    stage) case $2 in .sinter-stage.*[!A-Za-z0-9]*|.sinter-stage.|.sinter-stage.*/*) return 1;; .sinter-stage.*) ;; *) return 1;; esac;;
    base) case $2 in ''|.|..|*/*) return 1;; esac;;
  esac
}
pin_dir() {  # <dir> <dir-id|->  -> cwd = <dir>, fd 4 = <dir>
  valid optdevino "$2" || reject "bad directory identity"
  case $1 in /*) ;; *) reject "the directory must be an absolute path";; esac
  cd -P -- "$1" 2>/dev/null || reject "cannot enter the directory"
  [ "$2" = - ] || [ "$(stat -c '%d:%i' .)" = "$2" ] || reject "the directory is not the one that was checked"
  exec 4< .
}
check_s() {  # cwd = S ; <G|-> <S-id|-> ; proves that cwd is the staging directory
  [ "$(stat -c %u .)" = "$me" ] || return 1
  if [ "$1" != - ]; then [ "$(stat -c %g .)" = "$1" ] || return 1; fi
  if [ "$2" != - ]; then [ "$(stat -c '%d:%i' .)" = "$2" ] || return 1; fi
}
discard_here() {  # cwd = S (proven), fd 5 = S ; <s> <G|-> <S-id> ; prints the CLEANUP line; returns 0, or 5 for link-remains / unknown
  if rm -f -- payload && [ ! -e payload ] && [ ! -L payload ]; then :; else
    printf 'CLEANUP:link-remains:%s\n' "$(readlink /proc/self/fd/5 2>/dev/null || printf '%s' "$1")"; return 5
  fi
  if cd -P -- /proc/self/fd/4 2>/dev/null && trusted_dir; then
    if [ "$2" != - ]; then pred="-gid $2"; else pred="-inum ${3#*:}"; fi
    find -P . -maxdepth 1 -name "$1" -type d -user "$me" $pred -empty -delete 2>/dev/null || true
  fi
  n=$(stat -L -c %h /proc/self/fd/5 2>/dev/null) || n=
  case $n in
    0) printf 'CLEANUP:clean\n';;
    ''|*[!0-9]*) printf 'CLEANUP:unknown\n'; return 5;;
    *) printf 'CLEANUP:left:%s\n' "$(readlink /proc/self/fd/5 2>/dev/null || printf '%s' "$1")";;
  esac
  return 0
}
enter_s() {  # <dir> <dir-id|-> <S> <G|-> <S-id>  -> cwd = S (proven), fd 4 = <dir>, fd 5 = S
  valid stage "$3" && valid optid "$4" && valid devino "$5" || reject "bad staging identity"
  pin_dir "$1" "$2"
  cd -P -- "$3" 2>/dev/null || reject "the staging directory is gone or was replaced; a stray .sinter-stage.* may remain"
  check_s "$4" "$5" || reject "the staging directory is not the one made by stage"
  exec 5< .
}

case $op in
stage|stagelink)
  dir=$1; did=$2; shift 2
  if [ $op = stage ]; then
    valid id "$2" && valid id "$3" || reject "bad owner"
    case $1 in ''|*[!0-7]*) reject "bad mode";; esac
  fi
  pin_dir "$dir" "$did"
  no_setgid || reject "the directory has the setgid bit: a directory made in it inherits its group, so Sinter cannot prove the staging directory is its own"
  if [ "$me" = 0 ]; then
    command -v setpriv >/dev/null 2>&1 || reject "setpriv (util-linux) is required to stage as root"
    G=$(( $(od -An -N4 -tu4 /dev/urandom) % 1000000000 + 3000000000 ))
    s=$(setpriv --regid "$G" --clear-groups mktemp -d -p . .sinter-stage.XXXXXXXX)
  else
    G=-
    trusted_dir || reject "the parent directory could be changed by others: the staging directory cannot be proven to be Sinter's own"
    s=$(mktemp -d -p . .sinter-stage.XXXXXXXX)
  fi
  s=${s#./}
  valid stage "$s" || reject "unexpected staging directory name; a stray .sinter-stage.* may remain"
  cd -P -- "$s" 2>/dev/null || reject "the staging directory cannot be entered; a stray .sinter-stage.* may remain"
  if [ -L "../$s" ] || ! [ . -ef "../$s" ] || ! check_s "$G" - || [ "$(stat -c %a .)" != 700 ] || [ -n "$(ls -A)" ]; then
    reject "the staging directory is not the one just created; a stray .sinter-stage.* may remain"
  fi
  sid=$(stat -c '%d:%i' .)
  exec 5< .
  trap 'discard_here "$s" "$G" "$sid" || true' EXIT
  if [ $op = stage ]; then
    mode=$1; uid=$2; gid=$3; shift 3
    set -C; cat > payload; set +C
    chown "$uid:$gid" payload
    chmod "$mode" payload
    while [ $# -ge 2 ]; do setfattr -n "$1" -v "$2" payload; shift 2; done
  else
    ln -s -- "$1" payload
  fi
  pid=$(stat -c '%d:%i' payload)
  valid devino "$pid" || exit 1
  trap - EXIT
  printf '%s %s %s %s\n' "$s" "$G" "$sid" "$pid"
  ;;
publish)
  kind=$1; what=$2; dir=$3; did=$4; s=$5; G=$6; sid=$7; pid=$8; base=$9
  case $kind in new|replace) ;; *) reject "bad publication kind";; esac
  valid devino "$pid" && valid base "$base" || reject "bad publication arguments"
  enter_s "$dir" "$did" "$s" "$G" "$sid"
  [ "$(stat -c '%d:%i' payload)" = "$pid" ] || reject "the staged object is not the one made by stage"
  case $what in file) [ ! -L payload ] || reject "the staged object changed kind";; link) [ -L payload ] || reject "the staged object changed kind";; *) reject "bad object kind";; esac
  if [ $kind = new ]; then
    ln -T -- payload "/proc/self/fd/4/$base" || { r=$?; [ "$r" -le 128 ] || exit 1; discard_here "$s" "$G" "$sid" || true; exit 4; }
  else
    mv -T -f -- payload "/proc/self/fd/4/$base" || { r=$?; [ "$r" -le 128 ] || exit 1; discard_here "$s" "$G" "$sid" || true; exit 4; }
  fi
  rc=0; discard_here "$s" "$G" "$sid" || rc=$?
  exit $rc
  ;;
discard)
  enter_s "$1" "$2" "$3" "$4" "$5"
  rc=0; discard_here "$3" "$4" "$5" || rc=$?
  exit $rc
  ;;
*) reject "unknown operation";;
esac
