# Path C capture fixtures

Real command output preserved from the WP-P2 real-Linux research
(`sinter-wp-p2-dprime-linux-2026-10-05`, GCE acceptance hosts). Each `<host>_<chain>`
set is one batched capture of the same three-ancestor chain:

* `.dirs` - the operands, one per line, in the order they were passed
* `.stat.bin` - stdout of `stat --printf='%F|%a|%u|%g|%s|%d|%i|%y|%z|%n\0' -- <dirs>`
* `.getfattr.bin` - stdout of `getfattr -d -m - -e base64 --absolute-names -- <dirs>`

Hosts: `ubuntu24` (GNU coreutils 9.4, attr 2.5.2), `ubuntu26` (uutils coreutils 0.8.0,
attr 2.5.2), `rocky98` (GNU 8.32, attr 2.6.0, SELinux enforcing), `rocky102` (GNU 9.5,
attr 2.6.0). `rocky98_missing` is a failed batch (`stat` exit 1, partial stdout, the
diagnostic in `.stat.stderr`). The data is metadata of throw-away test trees only.
They are inputs to unit tests in `src/targetfs.rs`; nothing here is executed.
