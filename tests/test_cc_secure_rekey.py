#!/usr/bin/env python3
"""`cc-secure rekey` must really change the passphrase of slot 0.

Run from the repo root: python3 -m unittest tests/test_cc_secure_rekey.py

Until this test existed `rekey` called `cryptsetup luksChangeKey --new-keyfile`, an option that
belongs to luksAddKey. cryptsetup 2.7.0 (Ubuntu 24.04, every box) refuses it, so a rekey failed
with "the old passphrase still works" on a real agent (12 October 2026) and nothing had ever
checked. `cmd_rekey` is cut out of the shipped script and run against a real LUKS2 header in a file.

With the call fixed, a rekey that is stopped half-way became possible, and the first version of
the fix could lose the new passphrase that way. `InterruptedRekey` kills a real rekey (argon2id, as
on a box, about nine seconds) at many moments and checks that what is on disk always opens slot 0.

Needs `cryptsetup`; skips without it.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC_SECURE = (ROOT / 'roles/controlclaw/files/cc-secure').read_text()


def shell_function(name):
    return re.search(r'^' + name + r'\(\) \{(?: [^\n]*\}\n|\n.*?^\}\n)', CC_SECURE, re.S | re.M).group(0)


@unittest.skipUnless(shutil.which('cryptsetup'), 'needs cryptsetup')
class Rekey(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='cc-rekey-'))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.img = self.dir / 'luks.img'
        self.key = self.dir / 'luks.key'
        self.key.write_text('the first passphrase')
        self.old = self.dir / 'old.key'
        shutil.copyfile(self.key, self.old)
        with open(self.img, 'wb') as f:
            f.truncate(32 * 1024 * 1024)
        subprocess.run(['cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000',
                        '--key-file', str(self.key), str(self.img)], check=True, capture_output=True)
        # A second slot, as a partner binding would be: a rekey must leave it alone.
        self.partner = self.dir / 'partner.key'
        self.partner.write_text('what a partner binding holds')
        subprocess.run(['cryptsetup', 'luksAddKey', '--batch-mode', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000',
                        '--key-file', str(self.key), str(self.img), str(self.partner)], check=True, capture_output=True)
        (self.dir / 'recovery.pub').write_text('pub')

    def opens(self, keyfile, slot=None):
        cmd = ['cryptsetup', 'open', '--test-passphrase', '--key-file', str(keyfile), str(self.img)]
        if slot is not None:
            cmd[2:2] = ['--key-slot', str(slot)]
        return subprocess.run(cmd, capture_output=True).returncode == 0

    def keyslots(self):
        meta = json.loads(subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', str(self.img)], capture_output=True, text=True, check=True).stdout)
        return meta['keyslots']

    def rekey(self, seal_ok=True):
        take_lock = 'take_lock() { :; }' if 'take_lock' in shell_function('cmd_rekey') else ''
        script = f'''
set -euo pipefail
SECURE={self.dir}; KEYFILE={self.key}; MAPPER=cc-test; RECOVERY_PUB={self.dir}/recovery.pub; RECOVERY_JWE={self.dir}/sealed
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
loopdev() {{ echo {self.img}; }}
{take_lock}
stop_leftover_bind() {{ :; }}
# Stands in for cc-seal: keeps a copy of what it was asked to seal.
seal_to_recovery() {{ {'cp "$1" "$RECOVERY_JWE"' if seal_ok else 'return 1'}; }}
{shell_function('opens_slot0')}
{shell_function('changekey_pids')}
{shell_function('finish_interrupted_rekey')}
{shell_function('cmd_rekey')}
cmd_rekey
'''
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True)

    def test_the_new_passphrase_opens_slot_0_and_the_old_one_no_longer_opens_anything(self):
        before = self.keyslots()
        r = self.rekey()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('rekeyed slot 0 and re-sealed the recovery blob', r.stderr)
        self.assertNotEqual(self.key.read_text(), self.old.read_text())
        self.assertTrue(self.opens(self.key, slot=0))
        self.assertFalse(self.opens(self.old))
        # What was sealed for the owner is the new passphrase, the one in the key file.
        self.assertEqual((self.dir / 'sealed').read_text(), self.key.read_text())
        # The partner's slot is the same bytes as before, and still opens.
        after = self.keyslots()
        self.assertEqual(sorted(after), ['0', '1'])
        self.assertEqual(after['1'], before['1'])
        self.assertNotEqual(after['0'], before['0'])
        self.assertTrue(self.opens(self.partner, slot=1))

    def test_twice_in_a_row_works(self):
        self.assertEqual(self.rekey().returncode, 0)
        first = self.key.read_text()
        self.assertEqual(self.rekey().returncode, 0)
        self.assertNotEqual(self.key.read_text(), first)
        self.assertTrue(self.opens(self.key, slot=0))
        self.assertEqual(sorted(self.keyslots()), ['0', '1'])

    def test_nothing_is_left_behind_by_a_rekey_that_finished(self):
        self.assertEqual(self.rekey().returncode, 0)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir() if p.name.startswith('luks.key')), ['luks.key'])

    def test_a_failed_seal_is_put_right_by_the_next_rekey(self):
        self.assertEqual(self.rekey(seal_ok=False).returncode, 1)
        self.assertTrue((self.dir / 'luks.key.reseal').exists())
        self.assertFalse((self.dir / 'sealed').exists())
        r = self.rekey()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('re-sealed the recovery blob after an interrupted rekey', r.stderr)
        self.assertEqual((self.dir / 'sealed').read_text(), self.key.read_text())
        self.assertFalse((self.dir / 'luks.key.reseal').exists())

    def test_when_the_new_passphrase_cannot_be_sealed_it_is_not_lost(self):
        # Slot 0 is already changed when the seal is tried. The key file has to hold the new
        # passphrase by then: before this was fixed it kept the old one and the new one was deleted,
        # so nothing could open slot 0 again.
        r = self.rekey(seal_ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn('could not be sealed: the recovery blob still holds the old one. Run reseal', r.stderr)
        self.assertNotEqual(self.key.read_text(), self.old.read_text())
        self.assertTrue(self.opens(self.key, slot=0))
        self.assertFalse(self.opens(self.old))
        self.assertTrue(self.opens(self.partner, slot=1))

    def test_the_call_is_one_cryptsetup_accepts(self):
        body = shell_function('cmd_rekey')
        self.assertNotIn('--new-keyfile', body.replace('`--new-keyfile`', '').replace('"Option --new-keyfile', ''))
        self.assertRegex(body, r'cryptsetup luksChangeKey --batch-mode --key-slot 0 --key-file "\$KEYFILE" "\$loop" "\$new"')

    def test_the_new_passphrase_is_on_disk_before_slot_0_is_changed_and_arrives_by_rename(self):
        body = shell_function('cmd_rekey')
        self.assertLess(body.index('> "$new"'), body.index('cryptsetup luksChangeKey'))
        self.assertLess(body.index('sync "$new"'), body.index('cryptsetup luksChangeKey'))
        self.assertLess(body.index('cryptsetup luksChangeKey --batch-mode'), body.index('mv -f "$new" "$KEYFILE"'))
        self.assertNotIn('/dev/shm', body.split('trap \'\' TERM INT HUP')[1])
        self.assertNotIn('rm -f "$KEYFILE"', body)
        self.assertLess(body.index("trap '' TERM INT HUP"), body.index('> "$new"'))
        self.assertLess(body.index('mv -f "$new" "$KEYFILE"'), body.index('trap - TERM INT HUP'))

    def test_the_box_user_can_no_longer_run_it(self):
        tasks = (ROOT / 'roles/controlclaw/tasks/disk-encryption.yml').read_text()
        lines = [l.strip() for l in tasks.split('\n') if 'NOPASSWD' in l and '/usr/local/bin/cc-secure' in l]
        self.assertFalse([l for l in lines if l.endswith('cc-secure rekey')], lines)
        self.assertTrue([l for l in lines if l.endswith('cc-secure reseal')])

    def test_bind_reseal_and_mount_put_an_interrupted_rekey_right_first(self):
        for name in ('cmd_bind', 'cmd_reseal', 'cmd_mount', 'cmd_rekey'):
            self.assertIn('finish_interrupted_rekey', shell_function(name), name)


@unittest.skipUnless(shutil.which('cryptsetup'), 'needs cryptsetup')
class InterruptedRekey(unittest.TestCase):
    """A real rekey on a container whose slot 0 is argon2id, as `cc-secure init` makes it, stopped
    at many moments in three ways. Slow on purpose (several minutes)."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='cc-rekey-kill-'))
        cls.first = 'the first passphrase'
        cls.pristine = cls.base / 'pristine.img'
        (cls.base / 'first.key').write_text(cls.first)
        with open(cls.pristine, 'wb') as f:
            f.truncate(32 * 1024 * 1024)
        subprocess.run(['cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--key-file', str(cls.base / 'first.key'), str(cls.pristine)], check=True, capture_output=True)
        # How long an undisturbed rekey takes here, to spread the kills over all of it.
        d = cls.fresh('measure')
        started = time.monotonic()
        r = subprocess.run(['bash', str(cls.script(d))], capture_output=True, text=True)
        cls.takes = time.monotonic() - started
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    @classmethod
    def fresh(cls, name):
        d = Path(tempfile.mkdtemp(prefix=f'{name}-', dir=cls.base))
        shutil.copyfile(cls.pristine, d / 'luks.img')
        (d / 'luks.key').write_text(cls.first)
        (d / 'recovery.pub').write_text('pub')
        return d

    @classmethod
    def script(cls, d):
        f = d / 'cc-secure-under-test'
        f.write_text(f'''
set -euo pipefail
SECURE={d}; KEYFILE={d}/luks.key; MAPPER=cc-test; RECOVERY_PUB={d}/recovery.pub; RECOVERY_JWE={d}/sealed
die() {{ echo "cc-secure: $*" >&2; exit 1; }}
log() {{ echo "cc-secure: $*" >&2; }}
is_mounted() {{ return 0; }}
loopdev() {{ echo {d}/luks.img; }}
{'take_lock() { :; }' if 'take_lock' in shell_function('cmd_rekey') else ''}
stop_leftover_bind() {{ :; }}
seal_to_recovery() {{ cp "$1" "$RECOVERY_JWE.tmp" && mv "$RECOVERY_JWE.tmp" "$RECOVERY_JWE"; }}
{shell_function('opens_slot0')}
{shell_function('changekey_pids')}
{shell_function('finish_interrupted_rekey')}
{shell_function('cmd_rekey')}
cmd_rekey
''')
        return f

    def opens(self, d, name):
        f = d / name
        return f.exists() and f.stat().st_size > 0 and subprocess.run(
            ['cryptsetup', 'open', '--test-passphrase', '--key-slot', '0', '--key-file', str(f), str(d / 'luks.img')], capture_output=True).returncode == 0

    def settle(self, d):
        # A cryptsetup that outlived its shell finishes what it was doing.
        for _ in range(300):
            if not subprocess.run(['pgrep', '-f', str(d / 'luks.img')], capture_output=True, text=True).stdout.split():
                return
            time.sleep(0.1)
        self.fail('a cryptsetup of the stopped rekey is still running after 30 s')

    def check_then_finish(self, d, label):
        self.settle(d)
        # What is on disk opens slot 0: the key file, or the new file next to it.
        self.assertTrue(self.opens(d, 'luks.key') or self.opens(d, 'luks.key.new'),
                        f'{label}: neither luks.key nor luks.key.new opens slot 0 ({sorted(p.name for p in d.iterdir())})')
        # The next run puts it right and ends with everything matching.
        r = subprocess.run(['bash', str(self.script(d))], capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, f'{label}: {r.stderr}')
        self.assertTrue(self.opens(d, 'luks.key'), label)
        self.assertEqual((d / 'sealed').read_text(), (d / 'luks.key').read_text(), f'{label}: the blob is not the passphrase in the key file')
        self.assertEqual(sorted(p.name for p in d.iterdir() if p.name.startswith('luks.key')), ['luks.key'], label)
        self.assertNotEqual((d / 'luks.key').read_text(), self.first, label)

    def moments(self, n):
        return [round(0.05 + i * (self.takes + 0.6) / n, 2) for i in range(n)]

    def test_kill_9_of_everything_at_any_moment(self):
        for at in self.moments(12):
            d = self.fresh(f'kill-all-{at}')
            p = subprocess.Popen(['bash', str(self.script(d))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, process_group=0)
            time.sleep(at)
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.communicate()
            self.check_then_finish(d, f'kill -9 of the group at {at} s')
            shutil.rmtree(d, ignore_errors=True)

    def test_kill_9_of_cc_secure_alone_while_its_cryptsetup_carries_on(self):
        for at in self.moments(8):
            d = self.fresh(f'kill-shell-{at}')
            p = subprocess.Popen(['bash', str(self.script(d))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, process_group=0)
            time.sleep(at)
            p.kill()
            p.communicate()
            # Straight away, while the orphaned luksChangeKey may still be deriving its key: the
            # next run has to wait for it instead of judging the two files too early.
            r = subprocess.run(['bash', str(self.script(d))], capture_output=True, text=True, timeout=240)
            self.assertEqual(r.returncode, 0, f'at {at} s: {r.stderr}')
            self.settle(d)
            self.assertTrue(self.opens(d, 'luks.key'), f'at {at} s: the key file does not open slot 0')
            self.assertEqual((d / 'sealed').read_text(), (d / 'luks.key').read_text(), f'at {at} s')
            self.assertEqual(sorted(x.name for x in d.iterdir() if x.name.startswith('luks.key')), ['luks.key'], f'at {at} s')
            shutil.rmtree(d, ignore_errors=True)

    def test_term_is_not_obeyed_half_way(self):
        # What `timeout 1.8 sudo cc-secure rekey` did, as the box user, before: slot 0 changed and
        # the only copy of its passphrase gone. TERM during the change is now ignored and the rekey
        # runs to its end.
        for at in self.moments(6):
            d = self.fresh(f'term-{at}')
            p = subprocess.Popen(['bash', str(self.script(d))], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, process_group=0)
            time.sleep(at)
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            _, err = p.communicate(timeout=120)
            self.settle(d)
            self.assertTrue(self.opens(d, 'luks.key') or self.opens(d, 'luks.key.new'), f'TERM at {at} s: {err}')
            if p.returncode == 0:
                self.assertTrue(self.opens(d, 'luks.key'), f'TERM at {at} s')
                self.assertEqual((d / 'sealed').read_text(), (d / 'luks.key').read_text(), f'TERM at {at} s')
            self.check_then_finish(d, f'TERM at {at} s')
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
