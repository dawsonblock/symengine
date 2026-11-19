"""private_directory / ensure_private_directory custody contracts."""
import ctypes
import os
import stat
import tempfile
import threading
import unittest
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis import vault_storage as vs
from sis.errors import InvalidInput
from sis.vault_storage import (
    assert_private_acl,
    create_private_file,
    ensure_private_directory,
    private_directory,
)


class _MockSecurityAttributes(ctypes.Structure):
    _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                ('inherit', wintypes.BOOL)]


class _MockFileAttributeTag(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]


def _mock_win_ctx(*, create_error=None, file_attrs=0x80, file_type=1,
                  write_error=None,
                  dacl_control=0x1000,
                  dacl_sddl='D:P(A;;FA;;;U)(A;;FA;;;SY)',
                  sid_aliases=None):
    """Recording stand-in for ``_windows_api()`` — no real Win32 needed.

    ``sid_aliases`` maps SDDL trustee spellings to the ``S-1-...`` SID
    ``ConvertStringSidToSidW`` would parse them as; a literal ``S-1-``
    string parses as itself and anything else fails to parse.
    """
    state = SimpleNamespace(
        create_calls=[], write_calls=[], deleted=[], closed=[],
        file_handle=0x5150, descriptor=0xD000, keep=[], last_error=0,
        sids={})
    aliases = {'SY': 'S-1-5-18', 'BA': 'S-1-5-32-544', 'CO': 'S-1-3-0',
               'WD': 'S-1-1-0', **(sid_aliases or {})}

    class Advapi:
        def ConvertStringSidToSidW(self, text, out):
            sid = aliases.get(text, text if text.startswith('S-1-') else None)
            if sid is None:
                return False
            handle = 0x51D0 + len(state.sids)
            state.sids[handle] = sid
            out._obj.value = handle
            return True

        def ConvertSidToStringSidW(self, binary, out):
            out._obj.value = state.sids[binary.value]
            return True

        def ConvertStringSecurityDescriptorToSecurityDescriptorW(
                self, sddl, rev, out, out_len):
            out._obj.value = state.descriptor
            return True

        def GetSecurityInfo(self, h, objtype, info, owner, group, dacl,
                            sacl, sd):
            sd._obj.value = state.descriptor
            return 0

        def GetSecurityDescriptorControl(self, sd, control, revision):
            control._obj.value = dacl_control
            revision._obj.value = 1
            return True

        def GetSecurityDescriptorDacl(self, sd, present, dacl, defaulted):
            present._obj.value = True
            dacl._obj.value = state.descriptor
            return True

        def ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self, sd, rev, info, out, out_len):
            buf = ctypes.create_unicode_buffer(dacl_sddl)
            state.keep.append(buf)
            out._obj.value = ctypes.addressof(buf)
            return True

    class Kernel:
        def GetCurrentProcess(self):
            return 1

        def CreateFileW(self, path, access, share, sa, disp, flags, tmpl):
            attrs = sa._obj if sa is not None else None
            state.create_calls.append(SimpleNamespace(
                path=path, access=access, share=share,
                descriptor=attrs.descriptor if attrs else None,
                inherit=attrs.inherit if attrs else None,
                disposition=disp, flags=flags))
            if create_error is not None:
                state.last_error = create_error
                return wintypes.HANDLE(-1).value
            return state.file_handle

        def GetFileInformationByHandleEx(self, h, cls, buf, size):
            buf._obj.attributes = file_attrs
            buf._obj.tag = 0
            return True

        def GetFileType(self, h):
            return file_type

        def WriteFile(self, h, data, n, written, ovl):
            if write_error is not None:
                state.last_error = write_error
                return False
            state.write_calls.append(
                SimpleNamespace(handle=h, data=bytes(data), n=n))
            written._obj.value = n
            return True

        def DeleteFileW(self, path):
            state.deleted.append(path)
            return True

        def CloseHandle(self, h):
            state.closed.append(h)
            return True

        def LocalFree(self, p):
            return None

    ctx = SimpleNamespace(
        advapi=Advapi(), kernel=Kernel(), wintypes=wintypes,
        token_user=None, security_attributes=_MockSecurityAttributes,
        file_attribute_tag=_MockFileAttributeTag)
    return ctx, state


class PrivateDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_creates_owner_only_directory(self):
        path = private_directory(self.root / 'vault')
        self.assertTrue(path.is_dir())
        assert_private_acl(path)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o700)

    def test_nested_leaf_created_private(self):
        path = private_directory(self.root / 'outer' / 'vault')
        self.assertTrue(path.is_dir())
        assert_private_acl(path)

    def test_existing_directory_rejected_untouched(self):
        existing = self.root / 'vault'
        existing.mkdir()
        marker = existing / 'keep.txt'
        marker.write_bytes(b'keep')
        before = existing.lstat().st_mode
        with self.assertRaises(InvalidInput):
            private_directory(existing)
        self.assertTrue(existing.is_dir())
        self.assertEqual(existing.lstat().st_mode, before)
        self.assertEqual(marker.read_bytes(), b'keep')

    def test_existing_file_rejected_untouched(self):
        existing = self.root / 'vault'
        existing.write_bytes(b'keep')
        with self.assertRaises(InvalidInput):
            private_directory(existing)
        self.assertTrue(existing.is_file())
        self.assertEqual(existing.read_bytes(), b'keep')

    def test_symlink_rejected_and_target_untouched(self):
        if os.name != 'posix':
            self.skipTest('POSIX symlink semantics')
        real = self.root / 'real'
        real.mkdir()
        before = real.lstat().st_mode
        link = self.root / 'vault'
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(InvalidInput):
            private_directory(link)
        self.assertTrue(link.is_symlink())
        self.assertEqual(real.lstat().st_mode, before)

    def test_ensure_creates_missing_private_directory(self):
        path = ensure_private_directory(self.root / 'vault')
        self.assertTrue(path.is_dir())
        assert_private_acl(path)

    def test_ensure_accepts_existing_private_dir(self):
        created = private_directory(self.root / 'vault')
        self.assertEqual(ensure_private_directory(created), created)

    def test_ensure_concurrent_creators_converge(self):
        # Two evaluators starting at once both create the key directory
        # in this helper: the loser must verify the winner's directory
        # instead of raising FileExistsError out of the constructor.
        target = self.root / 'vault'
        barrier = threading.Barrier(9)
        outcomes = []
        lock = threading.Lock()

        def create():
            barrier.wait(timeout=10)
            try:
                result = ensure_private_directory(target)
            except Exception as error:  # surfaced by the assertions below
                result = error
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual(len(outcomes), 8)
        for outcome in outcomes:
            self.assertIsInstance(outcome, Path, repr(outcome))
            self.assertEqual(outcome, target)
        assert_private_acl(target)

    def test_ensure_rejects_non_directory(self):
        existing = self.root / 'vault'
        existing.write_bytes(b'x')
        with self.assertRaises(InvalidInput):
            ensure_private_directory(existing)

    def test_ensure_rejects_public_directory_posix(self):
        if os.name != 'posix':
            self.skipTest('POSIX permission semantics')
        existing = self.root / 'vault'
        existing.mkdir()
        os.chmod(existing, 0o755)
        with self.assertRaises(InvalidInput):
            ensure_private_directory(existing)
        # Rejected, never repaired in place: permissions stay as found.
        self.assertEqual(stat.S_IMODE(existing.lstat().st_mode), 0o755)

    def test_assert_private_acl_rejects_symlink_posix(self):
        if os.name != 'posix':
            self.skipTest('POSIX symlink semantics')
        real = self.root / 'real'
        real.mkdir()
        link = self.root / 'link'
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(InvalidInput):
            assert_private_acl(link)

    def test_create_private_file_exclusive_and_verified(self):
        target = private_directory(self.root / 'vault') / 'seed.bin'
        create_private_file(target, b'payload', 'test file')
        self.assertEqual(target.read_bytes(), b'payload')
        assert_private_acl(target)
        with self.assertRaises(FileExistsError):
            create_private_file(target, b'other', 'test file')
        self.assertEqual(target.read_bytes(), b'payload')

    @unittest.skipUnless(os.name == 'nt', 'Windows DACL control checks')
    def test_unprotected_dacl_with_allowed_trustees_rejected(self):
        from ctypes import wintypes
        ctx = vs._windows_api()
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        # The parent is private: its ACEs are not inheritable, so once the
        # target's DACL is unprotected the only difference from a private
        # directory is the missing SE_DACL_PROTECTED bit. Creating with an
        # SDDL that merely omits ``P`` did not yield an unprotected DACL on
        # the Windows CI runner (the check accepted it), so the DACL is
        # unprotected explicitly afterwards and the precondition asserted.
        parent = private_directory(self.root / 'parent')
        target = private_directory(parent / 'unprotected')
        descriptor = ctypes.c_void_p()
        try:
            sddl, _ = vs._windows_user_sddl(ctx, lambda m: self.fail(m))
            self.assertTrue(
                ctx.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, ctypes.byref(descriptor), None))
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ctypes.c_void_p()
            self.assertTrue(advapi32.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl),
                ctypes.byref(defaulted)))
            # SE_FILE_OBJECT; DACL_SECURITY_INFORMATION |
            # UNPROTECTED_DACL_SECURITY_INFORMATION.
            self.assertEqual(advapi32.SetNamedSecurityInfoW(
                str(target), 1, 0x00000004 | 0x20000000,
                None, None, dacl, None), 0)
        finally:
            if descriptor:
                ctx.kernel.LocalFree(descriptor)
        # Precondition: the DACL really is unprotected now.
        observed = ctypes.c_void_p()
        self.assertEqual(advapi32.GetNamedSecurityInfoW(
            str(target), 1, 0x00000004, None, None, None, None,
            ctypes.byref(observed)), 0)
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            self.assertTrue(ctx.advapi.GetSecurityDescriptorControl(
                observed, ctypes.byref(control), ctypes.byref(revision)))
            self.assertFalse(control.value & 0x1000,
                             'precondition: DACL must be unprotected')
        finally:
            ctx.kernel.LocalFree(observed)
        with self.assertRaises(InvalidInput):
            assert_private_acl(target)
        with self.assertRaises(InvalidInput):
            ensure_private_directory(target)


class WindowsDaclMockTests(unittest.TestCase):
    """Mocked-Win32 DACL checks — runnable everywhere, NOT Windows
    integration coverage; the real check runs in the nt-only test."""

    SDDL = 'D:P(A;;FA;;;U)(A;;FA;;;SY)'

    def test_protected_bit_is_the_gate_not_trustees(self):
        allowed = {'U', 'SY', 'BA', 'CO'}
        # Identical allow-listed trustees; only the control bit differs.
        unprotected, _ = _mock_win_ctx(
            dacl_control=0, dacl_sddl='D:(A;;FA;;;U)(A;;FA;;;SY)')
        self.assertFalse(vs._windows_dacl_is_restricted(
            1, unprotected, allowed, self.fail))
        protected, _ = _mock_win_ctx(
            dacl_control=0x1000, dacl_sddl='D:(A;;FA;;;U)(A;;FA;;;SY)')
        self.assertTrue(vs._windows_dacl_is_restricted(
            1, protected, allowed, self.fail))
        # Protected, but a foreign trustee is still rejected.
        foreign, _ = _mock_win_ctx(
            dacl_control=0x1000, dacl_sddl='D:P(A;;FA;;;WD)')
        self.assertFalse(vs._windows_dacl_is_restricted(
            1, foreign, allowed, self.fail))

    # The GitHub windows-latest runner user (runneradmin) is the RID-500
    # built-in Administrator; the OS renders its SID as ``LA`` in SDDL
    # while ConvertSidToStringSidW spells it out in full.
    USER = 'S-1-5-21-1111-2222-3333-500'
    RUNNER_ALIASES = {'LA': USER}

    def _allowed(self):
        return vs._windows_allowed_sids(self.USER)

    def test_aliased_current_user_is_the_current_user(self):
        ctx, _ = _mock_win_ctx(dacl_sddl='D:PAI(A;;FA;;;LA)(A;;FA;;;SY)',
                               sid_aliases=self.RUNNER_ALIASES)
        self.assertTrue(vs._windows_dacl_is_restricted(
            1, ctx, self._allowed(), self.fail))

    def test_alias_of_another_principal_is_still_rejected(self):
        # ``LA`` naming someone other than the caller, Everyone, and
        # Owner Rights (Python's os.mkdir(mode=0o700) DACL) all fail.
        for sddl, aliases in (
                ('D:P(A;;FA;;;LA)(A;;FA;;;SY)',
                 {'LA': 'S-1-5-21-1111-2222-3333-501'}),
                ('D:P(A;;FA;;;LA)(A;;FA;;;WD)', self.RUNNER_ALIASES),
                ('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)',
                 {'OW': 'S-1-3-4'})):
            with self.subTest(sddl=sddl):
                ctx, _ = _mock_win_ctx(dacl_sddl=sddl, sid_aliases=aliases)
                self.assertFalse(vs._windows_dacl_is_restricted(
                    1, ctx, self._allowed(), self.fail))

    def test_unparseable_trustee_and_deny_ace_are_rejected(self):
        for sddl in ('D:P(A;;FA;;;??)', 'D:P(D;;FA;;;LA)(A;;FA;;;LA)',
                     'D:P(A;;FA;;LA)'):
            with self.subTest(sddl=sddl):
                ctx, _ = _mock_win_ctx(dacl_sddl=sddl,
                                       sid_aliases=self.RUNNER_ALIASES)
                self.assertFalse(vs._windows_dacl_is_restricted(
                    1, ctx, self._allowed(), self.fail))

    def test_canonical_aces_compare_principals_in_order(self):
        ctx, _ = _mock_win_ctx(sid_aliases=self.RUNNER_ALIASES)
        expected = f'D:P(A;;FA;;;{self.USER})(A;;FA;;;SY)'
        canonical = vs._windows_canonical_aces
        self.assertEqual(canonical(ctx, 'D:PAI(A;;FA;;;LA)(A;;FA;;;SY)'),
                         canonical(ctx, expected))
        self.assertEqual(canonical(ctx, expected),
                         [('A', '', 'FA', '', '', self.USER),
                          ('A', '', 'FA', '', '', 'S-1-5-18')])
        for observed in ('D:P(A;;FA;;;SY)(A;;FA;;;LA)',
                         'D:P(A;;FA;;;LA)',
                         'D:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FA;;;BA)',
                         'D:P(A;;FR;;;LA)(A;;FA;;;SY)'):
            with self.subTest(observed=observed):
                self.assertNotEqual(canonical(ctx, observed),
                                    canonical(ctx, expected))
        self.assertIsNone(canonical(ctx, 'D:P(A;;FA;;;??)'))

    @unittest.skipUnless(os.name == 'nt', 'real Win32 SID round trip')
    def test_real_private_directory_trustees_canonicalize(self):
        ctx = vs._windows_api()
        _, user_sid = vs._windows_user_sddl(ctx, self.fail)
        self.assertEqual(vs._windows_canonical_sid(ctx, user_sid), user_sid)
        self.assertEqual(vs._windows_canonical_sid(ctx, 'SY'), 'S-1-5-18')
        self.assertIsNone(vs._windows_canonical_sid(ctx, 'not-a-sid'))
        with tempfile.TemporaryDirectory() as temp:
            path = private_directory(Path(temp) / 'vault')
            assert_private_acl(path)


class WindowsFileCreateMockTests(unittest.TestCase):
    """Mocked-Win32 ``_windows_private_file_create`` — runnable on any
    platform; the nt-only tests above remain the real coverage."""

    SDDL = 'D:P(A;;FA;;;U)(A;;FA;;;SY)'

    def _create(self, ctx, state, payload=b'seed-bytes', path='C:/x/seed'):
        # ctypes.get_last_error only exists on Windows; inject the mock's
        # last-error channel the same way the real runtime provides it.
        with mock.patch.object(vs, '_windows_api', return_value=ctx), \
                mock.patch.object(vs, '_windows_user_sddl',
                                  return_value=(self.SDDL, 'U')), \
                mock.patch.object(ctypes, 'get_last_error',
                                  lambda: state.last_error, create=True):
            return vs._windows_private_file_create(
                Path(path), payload, 'evaluator seed')

    def test_create_new_secures_dacl_and_writes_same_handle(self):
        ctx, state = _mock_win_ctx()
        out = self._create(ctx, state)
        self.assertEqual(out, Path('C:/x/seed'))
        create = state.create_calls[0]
        self.assertEqual(create.disposition, 1)  # CREATE_NEW, exclusive
        self.assertEqual(create.share, 0)
        self.assertTrue(create.access & 0x40000000)  # GENERIC_WRITE
        # SECURITY_ATTRIBUTES carried the protected private DACL at
        # creation — no inherited-ACL window before the write.
        self.assertEqual(create.descriptor, state.descriptor)
        self.assertFalse(create.inherit)
        self.assertEqual(len(state.write_calls), 1)
        # Payload goes through the same validated handle, never a reopen.
        self.assertEqual(state.write_calls[0].handle, state.file_handle)
        self.assertEqual(state.write_calls[0].data, b'seed-bytes')
        self.assertEqual(state.deleted, [])
        self.assertIn(state.file_handle, state.closed)

    def test_existing_name_never_writes_or_deletes(self):
        ctx, state = _mock_win_ctx(create_error=80)  # ERROR_FILE_EXISTS
        with self.assertRaises(FileExistsError):
            self._create(ctx, state)
        self.assertEqual(state.write_calls, [])
        self.assertEqual(state.deleted, [])

    def test_failed_write_removes_only_own_creation(self):
        ctx, state = _mock_win_ctx(write_error=5)  # ERROR_ACCESS_DENIED
        with self.assertRaises(InvalidInput):
            self._create(ctx, state)
        self.assertEqual(state.deleted, [str(Path('C:/x/seed'))])


if __name__ == '__main__':
    unittest.main()
