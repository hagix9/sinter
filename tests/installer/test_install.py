"""Offline Linux installer contract tests; no release mutation or real downloads."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'install.sh'

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='sinter-installer-test-'))
        self.addCleanup(shutil.rmtree, self.root)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.dest = self.root / 'destination'; self.dest.mkdir(mode=0o700)
        self.temp = self.root / 'tmp'; self.temp.mkdir()
        self.fixture = self.root / 'fixture'; self.fixture.mkdir()
        self.version = 'v0.3.0'
        self.asset = 'sinter-v0.3.0-linux-x86_64.tar.gz'
        self.payload = b'#!/bin/sh\nprintf "sinter 0.3.0\\n"\n'
        self.make_archive()
        (self.bin / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo "${TEST_OS:-Linux}";; -m) echo "${TEST_ARCH:-x86_64}";; esac\n')
        (self.bin / 'curl').write_text('''#!/bin/sh
if [ "${TEST_NETWORK_FAIL:-0}" = 1 ]; then exit 22; fi
out=
while [ $# -gt 0 ]; do
 case "$1" in -o) out=$2; shift 2;; https://*) url=$1; shift;; *) shift;; esac
done
case "$url" in
 */releases/latest) printf 'https://github.com/hagix9/sinter/releases/tag/v0.3.0';;
 */v0.3.0/SHA256SUMS) cp "$TEST_FIXTURE/sums" "$out";;
 */v0.3.0/sinter-v0.3.0-linux-x86_64.tar.gz) cp "$TEST_FIXTURE/archive" "$out";;
 *) exit 22;;
esac
''')
        for p in self.bin.iterdir(): p.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'],
                        TEST_FIXTURE=str(self.fixture), TMPDIR=str(self.temp),
                        SINTER_INSTALL_DIR=str(self.dest), SINTER_VERSION=self.version)

    def make_archive(self, kind='normal'):
        name='sinter-v0.3.0-linux-x86_64'
        with tarfile.open(self.fixture/'archive','w:gz',format=tarfile.USTAR_FORMAT) as t:
            m=tarfile.TarInfo(name+'/'); m.type=tarfile.DIRTYPE; m.mode=0o755; t.addfile(m)
            for f in ['sinter','README.md','README.ja.md','LICENSE-MIT','LICENSE-APACHE']:
                m=tarfile.TarInfo(name+'/'+f); data=self.payload if f=='sinter' else b'fixture\n';m.mode=0o755 if f=='sinter' else 0o644
                if f=='sinter' and kind=='symlink':m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';t.addfile(m)
                elif f=='sinter' and kind=='hardlink':m.type=tarfile.LNKTYPE;m.linkname=name+'/README.md';t.addfile(m)
                else:m.size=len(data);t.addfile(m,io.BytesIO(data))
            if kind=='traversal':m=tarfile.TarInfo('../escape');m.size=1;t.addfile(m,io.BytesIO(b'x'))
            if kind=='duplicate':m=tarfile.TarInfo(name+'/sinter');m.size=len(self.payload);t.addfile(m,io.BytesIO(self.payload))
        h=hashlib.sha256((self.fixture/'archive').read_bytes()).hexdigest()
        (self.fixture/'sums').write_text(h+'  '+self.asset+'\n')

    def run_script(self, success=False, pipe=False):
        old=(self.dest/'sinter').read_bytes() if (self.dest/'sinter').is_file() else None
        r=subprocess.run(['/bin/sh'] if pipe else ['/bin/sh',str(SCRIPT)], input=SCRIPT.read_bytes() if pipe else None, env=self.env,capture_output=True)
        self.assertEqual(r.returncode==0,success,(r.returncode,r.stdout.decode(),r.stderr.decode()))
        self.assertEqual(list(self.temp.iterdir()),[])
        self.assertEqual(list(self.dest.glob('.sinter.*')),[])
        if not success and old is not None:self.assertEqual((self.dest/'sinter').read_bytes(),old)
        return r

    def test_explicit_and_reinstall(self):
        self.run_script(True);self.run_script(True)
        self.assertEqual((self.dest/'sinter').read_bytes(),self.payload)
        self.assertEqual((self.dest/'sinter').stat().st_mode & 0o777,0o755)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()),['sinter'])

    def test_default_user_destination(self):
        self.env.pop('SINTER_INSTALL_DIR');self.env['HOME']=str(self.root)
        self.dest=self.root/'.local/bin';self.run_script(True)
        self.assertEqual((self.dest/'sinter').read_bytes(),self.payload)

    def test_checksum_tool_unavailable(self):
        self.env['PATH']=str(self.bin);self.run_script()

    def test_wrong_embedded_version_preserves_install(self):
        self.run_script(True)
        self.payload=b'#!/bin/sh\nprintf "sinter 9.0.0\\n"\n'
        self.make_archive();self.run_script()

    def test_latest_and_pipe_stdin(self):
        self.env.pop('SINTER_VERSION');self.run_script(True,pipe=True)

    def test_unsupported_architecture(self):
        for arch in ['aarch64','arm64','i386','i686']:
            self.env['TEST_ARCH']=arch;self.run_script()

    def test_unsupported_os(self):
        self.env['TEST_OS']='Darwin';self.run_script()

    def test_invalid_versions(self):
        for v in ['../bad','v0.3.0;touch x','v0.3.0\nv1.0.0','v0.3.0-rc1']:
            self.env['SINTER_VERSION']=v;self.run_script()

    def test_missing_version(self):
        self.env['SINTER_VERSION']='v999.0.0';self.run_script()

    def test_checksum_failures_preserve_install(self):
        self.run_script(True)
        good=(self.fixture/'sums').read_text()
        for content in ['',good+good,'bad  '+self.asset+'\n','0'*64+'  '+self.asset+'\n']:
            (self.fixture/'sums').write_text(content);self.run_script()

    def test_truncated_download(self):
        self.run_script(True);p=self.fixture/'archive';p.write_bytes(p.read_bytes()[:100]);self.run_script()

    def test_unsafe_archives(self):
        self.run_script(True)
        for kind in ['symlink','hardlink','traversal','duplicate']:
            self.make_archive(kind);self.run_script()

    def test_destination_symlink(self):
        victim=self.root/'victim';victim.write_text('protected');(self.dest/'sinter').symlink_to(victim)
        self.run_script();self.assertEqual(victim.read_text(),'protected')

    def test_destination_directory(self):
        (self.dest/'sinter').mkdir();self.run_script()

    def test_untrusted_or_unwritable_destination(self):
        self.dest.chmod(0o777);self.run_script()
        self.dest.chmod(0o500);self.run_script();self.dest.chmod(0o700)

    def test_invalid_destination(self):
        for p in ['', '/', 'relative', str(self.dest)+'/../bad', str(self.dest)+'\n']:
            self.env['SINTER_INSTALL_DIR']=p;self.run_script()

    def test_network_failure_preserves_install(self):
        self.run_script(True);self.env['TEST_NETWORK_FAIL']='1';self.run_script()

    def test_published_script_matches_root(self):
        self.assertEqual(SCRIPT.read_bytes(),(SCRIPT.parent/'docs-site/public/install.sh').read_bytes())

if __name__=='__main__':unittest.main(verbosity=2)
