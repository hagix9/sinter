H_BUILD_KIND=@BUILD_KIND@
if [ "$H_BUILD_KIND" != test ]; then for _f in $(builtin compgen -A function); do builtin unset -f "$_f"; done; builtin unset _f; fi   # production: no function may be imported from the environment
