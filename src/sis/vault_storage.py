"""Helpers for private, persistent evaluator SQLite files."""
import os
import re
import stat
import ctypes
from pathlib import Path
from types import SimpleNamespace

from .errors import InvalidInput

_WINDOWS_API = None


def _windows_api():
    """Return the process-wide Win32 bindings, loading them once."""
    global _WINDOWS_API
    if _WINDOWS_API is None:
        _WINDOWS_API = _load_windows_api()
    return _WINDOWS_API


def _load_windows_api():
    """Load advapi32/kernel32 with every used signature fully declared.

    Without ``argtypes``/``restype`` ctypes assumes 32-bit ``int``
    arguments and return values: on 64-bit Windows that silently
    truncates HANDLEs and pointers, corrupting both validity checks
    (``CreateFileW`` results) and cleanup (``CloseHandle`` targets).
    """
    from ctypes import wintypes

    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [('sid', ctypes.c_void_p), ('attributes', wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [('user', SidAndAttributes)]

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                    ('inherit', wintypes.BOOL)]

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]

    handle_type = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [handle_type, wintypes.DWORD,
                                      ctypes.POINTER(handle_type)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [handle_type, ctypes.c_int,
                                           ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.SetSecurityInfo.argtypes = [handle_type, ctypes.c_int, wintypes.DWORD,
                                       ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    advapi.GetSecurityInfo.argtypes = [handle_type, ctypes.c_int, wintypes.DWORD,
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = handle_type
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                   wintypes.DWORD,
                                   ctypes.POINTER(SecurityAttributes),
                                   wintypes.DWORD, wintypes.DWORD, handle_type]
    kernel.CreateFileW.restype = handle_type
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR,
                                        ctypes.POINTER(SecurityAttributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    kernel.WriteFile.argtypes = [handle_type, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.restype = wintypes.BOOL
    kernel.DeleteFileW.argtypes = [wintypes.LPCWSTR]
    kernel.DeleteFileW.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = [handle_type, ctypes.c_int,
                                                    ctypes.c_void_p,
                                                    wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [handle_type]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [handle_type]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return SimpleNamespace(
        advapi=advapi, kernel=kernel, wintypes=wintypes,
        token_user=TokenUser, security_attributes=SecurityAttributes,
        file_attribute_tag=FileAttributeTagInfo)


def _windows_user_sddl(ctx, fail):
    """Return ``(D:P(A;;FA;;;<caller>)(A;;FA;;;SY), <caller SID>)``."""
    advapi, kernel, wintypes = ctx.advapi, ctx.kernel, ctx.wintypes
    token = wintypes.HANDLE()
    user_sid = ctypes.c_wchar_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                       ctypes.byref(token)):
            fail('cannot open current user token '
                 f'(Windows error {ctypes.get_last_error()})')
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            fail('cannot determine current user SID')
        token_buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, token_buffer, needed,
                                          ctypes.byref(needed)):
            fail('cannot read current user SID')
        token_user = ctypes.cast(
            token_buffer, ctypes.POINTER(ctx.token_user)).contents
        if not advapi.ConvertSidToStringSidW(token_user.user.sid,
                                           ctypes.byref(user_sid)):
            fail('cannot encode current user SID')
        sid = user_sid.value
        if not sid:
            fail('cannot encode current user SID')
        return f'D:P(A;;FA;;;{sid})(A;;FA;;;SY)', sid
    finally:
        if user_sid.value is not None:
            kernel.LocalFree(ctypes.cast(user_sid, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def _windows_allowed_sids(user_sid):
    """ACE trustees accepted as private: the caller, SYSTEM, admin, owner."""
    return {user_sid, 'SY', 'BA', 'CO'}


def _windows_dacl_is_restricted(handle, ctx, allowed_sids, fail):
    """True when the object's DACL is protected and allow-lists only ``allowed_sids``.

    ``SE_DACL_PROTECTED`` is mandatory: an unprotected DACL still
    inherits ACEs from its parent, so allow-listed trustees alone do
    not prove the object is private.
    """
    advapi, kernel, wintypes = ctx.advapi, ctx.kernel, ctx.wintypes
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        result = advapi.GetSecurityInfo(handle, 1, 0x00000004,
                                        ctypes.byref(owner), ctypes.byref(group),
                                        ctypes.byref(dacl), ctypes.byref(sacl),
                                        ctypes.byref(descriptor))
        if result or not descriptor.value:
            fail(f'cannot inspect ACL (Windows error {result})')
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)):
            fail('cannot read ACL protection state')
        if not control.value & 0x1000:  # SE_DACL_PROTECTED
            return False
        sddl_buffer = ctypes.c_void_p()
        sddl_length = wintypes.DWORD()
        try:
            if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 0x00000004, ctypes.byref(sddl_buffer),
                    ctypes.byref(sddl_length)):
                fail('cannot read ACL')
            sddl = ctypes.wstring_at(sddl_buffer)
        finally:
            if sddl_buffer:
                kernel.LocalFree(sddl_buffer)
        aces = re.findall(r'\(([^()]*)\)', sddl)
        if not aces:
            return False
        return all(
            len(ace.split(';')) == 6
            and ace.split(';')[0] == 'A'
            and ace.split(';')[5] in allowed_sids
            for ace in aces)
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def _windows_private_sqlite_file(path, label):
    """Create or secure a vault file with a protected user-and-SYSTEM DACL."""
    ctx = _windows_api()
    advapi, kernel, wintypes = ctx.advapi, ctx.kernel, ctx.wintypes

    handle = wintypes.HANDLE()
    parent_handle = wintypes.HANDLE()
    descriptor = ctypes.c_void_p()
    queried_descriptor = ctypes.c_void_p()
    sddl_buffer = ctypes.c_void_p()

    def fail(message):
        raise InvalidInput(f'{label} Windows ACL validation failed: {message}')

    def wincheck(ok, message):
        if not ok:
            fail(f'{message} (Windows error {ctypes.get_last_error()})')

    try:
        expected_sddl, user_sid = _windows_user_sddl(ctx, fail)

        parent_handle = kernel.CreateFileW(
            str(path.parent), 0x00020080, 0x00000001 | 0x00000002 | 0x00000004,
            None, 3, 0x02000000 | 0x00200000, None)
        if parent_handle == wintypes.HANDLE(-1).value:
            fail(f'cannot inspect vault directory (Windows error {ctypes.get_last_error()})')
        parent_tag = ctx.file_attribute_tag()
        wincheck(kernel.GetFileInformationByHandleEx(parent_handle, 9,
                                                      ctypes.byref(parent_tag),
                                                      ctypes.sizeof(parent_tag)),
                 'cannot inspect vault directory')
        if not parent_tag.attributes & 0x10 or parent_tag.attributes & 0x400:
            fail('vault parent must be a directory and not a reparse point')
        if not _windows_dacl_is_restricted(
                parent_handle, ctx, _windows_allowed_sids(user_sid),
                fail):
            fail('vault directory ACL permits access outside the current user, SYSTEM, and Administrators')

        wincheck(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            expected_sddl, 1, ctypes.byref(descriptor), None), 'cannot create private ACL')
        attributes = ctx.security_attributes(
            ctypes.sizeof(ctx.security_attributes), descriptor, False)
        flags = 0x80 | 0x00200000  # normal file, open reparse points without following them
        access = 0x80000000 | 0x40000000 | 0x00020000 | 0x00040000
        share = 0x00000001 | 0x00000002 | 0x00000004
        handle = kernel.CreateFileW(str(path), access, share, ctypes.byref(attributes),
                                    1, flags, None)
        if handle == wintypes.HANDLE(-1).value:
            error = ctypes.get_last_error()
            if error not in (80, 183):
                fail(f'cannot create vault file (Windows error {error})')
            handle = kernel.CreateFileW(str(path), access, share, None, 3, flags, None)
            if handle == wintypes.HANDLE(-1).value:
                fail(f'cannot open vault file (Windows error {ctypes.get_last_error()})')

        tag = ctx.file_attribute_tag()
        wincheck(kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(tag),
                                                      ctypes.sizeof(tag)),
                 'cannot inspect vault file')
        if tag.attributes & (0x10 | 0x400) or kernel.GetFileType(handle) != 1:
            fail('vault path must be a regular file and not a reparse point')

        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        wincheck(advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                  ctypes.byref(dacl), ctypes.byref(defaulted)),
                 'cannot read private ACL')
        if not present.value or not dacl.value:
            fail('private ACL has no DACL')
        result = advapi.SetSecurityInfo(handle, 1, 0x00000004 | 0x80000000,
                                        None, None, dacl, None)
        if result:
            fail(f'cannot apply private ACL (Windows error {result})')

        owner = ctypes.c_void_p()
        group = ctypes.c_void_p()
        read_dacl = ctypes.c_void_p()
        sacl = ctypes.c_void_p()
        result = advapi.GetSecurityInfo(handle, 1, 0x00000004, ctypes.byref(owner),
                                        ctypes.byref(group), ctypes.byref(read_dacl),
                                        ctypes.byref(sacl), ctypes.byref(queried_descriptor))
        if result or not queried_descriptor.value:
            fail(f'cannot verify private ACL (Windows error {result})')
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        wincheck(advapi.GetSecurityDescriptorControl(queried_descriptor,
                                                      ctypes.byref(control), ctypes.byref(revision)),
                 'cannot verify protected ACL')
        length = wintypes.DWORD()
        wincheck(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            queried_descriptor, 1, 0x00000004, ctypes.byref(sddl_buffer), ctypes.byref(length)),
                 'cannot serialize vault ACL')
        observed_sddl = ctypes.wstring_at(sddl_buffer)
        if not (control.value & 0x1000) or observed_sddl != expected_sddl:
            fail('vault ACL is not limited to the current user and SYSTEM')
        return path
    except InvalidInput:
        raise
    except Exception as exc:
        raise InvalidInput(f'{label} Windows ACL validation failed') from exc
    finally:
        if handle and handle != wintypes.HANDLE(-1).value:
            kernel.CloseHandle(handle)
        if parent_handle and parent_handle != wintypes.HANDLE(-1).value:
            kernel.CloseHandle(parent_handle)
        if descriptor:
            kernel.LocalFree(descriptor)
        if queried_descriptor:
            kernel.LocalFree(queried_descriptor)
        if sddl_buffer:
            kernel.LocalFree(sddl_buffer)


def _windows_private_directory(target, label, fresh_only):
    """Create (or verify, when ``fresh_only`` is False) a private directory.

    Fresh directories are created atomically with the restricted DACL
    via ``CreateDirectoryW`` + ``SECURITY_ATTRIBUTES`` — there is no
    window where the directory carries a broad inherited ACL. An
    existing path is only ever inspected, never modified.
    """
    ctx = _windows_api()
    advapi, kernel, wintypes = ctx.advapi, ctx.kernel, ctx.wintypes
    handle = 0
    descriptor = ctypes.c_void_p()

    def fail(message):
        raise InvalidInput(f'{label} Windows ACL check failed: {message}')

    def wincheck(ok, message):
        if not ok:
            fail(f'{message} (Windows error {ctypes.get_last_error()})')

    try:
        sddl, user_sid = _windows_user_sddl(ctx, fail)
        wincheck(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None), 'cannot build private DACL')
        target.parent.mkdir(parents=True, exist_ok=True)
        attributes = ctx.security_attributes(
            ctypes.sizeof(ctx.security_attributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(target), ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            if error != 183:  # ERROR_ALREADY_EXISTS
                fail(f'cannot create private directory (Windows error {error})')
            if fresh_only:
                fail('path already exists')
        handle = kernel.CreateFileW(
            str(target), 0x00020080, 0x00000001 | 0x00000002 | 0x00000004,
            None, 3, 0x02000000 | 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            fail(f'cannot inspect private directory (Windows error {ctypes.get_last_error()})')
        tag = ctx.file_attribute_tag()
        wincheck(kernel.GetFileInformationByHandleEx(handle, 9,
                                                      ctypes.byref(tag),
                                                      ctypes.sizeof(tag)),
                 'cannot inspect private directory')
        if not tag.attributes & 0x10 or tag.attributes & 0x400:
            fail('path must be a directory and not a reparse point')
        if not _windows_dacl_is_restricted(
                handle, ctx, _windows_allowed_sids(user_sid), fail):
            fail('directory ACL permits access outside the current user, '
                 'SYSTEM, and Administrators')
        return target
    except InvalidInput:
        raise
    except Exception as exc:
        raise InvalidInput(f'{label} Windows ACL check failed') from exc
    finally:
        if handle and handle != wintypes.HANDLE(-1).value:
            kernel.CloseHandle(handle)
        if descriptor:
            kernel.LocalFree(descriptor)


def _windows_private_file_create(target, payload, label):
    """Atomically create ``target`` holding ``payload`` with a protected DACL.

    ``CREATE_NEW`` makes creation exclusive — a taken name raises
    :class:`FileExistsError`. The restricted DACL is applied at
    creation via ``SECURITY_ATTRIBUTES``, the object type and the
    resulting DACL are verified, and the payload is written through
    that same validated handle: secret bytes never sit in a file
    carrying a broad inherited ACL. On any failure after creation the
    file this call created is removed.
    """
    ctx = _windows_api()
    advapi, kernel, wintypes = ctx.advapi, ctx.kernel, ctx.wintypes
    handle = 0
    descriptor = ctypes.c_void_p()
    created = False
    complete = False

    def fail(message):
        raise InvalidInput(f'{label} Windows ACL check failed: {message}')

    def wincheck(ok, message):
        if not ok:
            fail(f'{message} (Windows error {ctypes.get_last_error()})')

    try:
        sddl, user_sid = _windows_user_sddl(ctx, fail)
        wincheck(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None), 'cannot build private DACL')
        attributes = ctx.security_attributes(
            ctypes.sizeof(ctx.security_attributes), descriptor, False)
        # GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES, no sharing,
        # CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT.
        handle = kernel.CreateFileW(
            str(target), 0x40000000 | 0x00020080, 0, ctypes.byref(attributes),
            1, 0x80 | 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            error = ctypes.get_last_error()
            if error in (80, 183):  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
                raise FileExistsError(str(target))
            fail(f'cannot create private file (Windows error {error})')
        created = True
        tag = ctx.file_attribute_tag()
        wincheck(kernel.GetFileInformationByHandleEx(handle, 9,
                                                      ctypes.byref(tag),
                                                      ctypes.sizeof(tag)),
                 'cannot inspect private file')
        if tag.attributes & (0x10 | 0x400) or kernel.GetFileType(handle) != 1:
            fail('path must be a regular file and not a reparse point')
        if not _windows_dacl_is_restricted(
                handle, ctx, _windows_allowed_sids(user_sid), fail):
            fail('private file ACL is not limited to the current user '
                 'and SYSTEM')
        written = wintypes.DWORD()
        wincheck(kernel.WriteFile(handle, payload, len(payload),
                                  ctypes.byref(written), None),
                 'cannot write private file')
        if written.value != len(payload):
            fail('private file write was incomplete')
        complete = True
        return target
    except (InvalidInput, FileExistsError):
        raise
    except Exception as exc:
        raise InvalidInput(f'{label} Windows ACL check failed') from exc
    finally:
        if handle and handle != wintypes.HANDLE(-1).value:
            kernel.CloseHandle(handle)
        if descriptor:
            kernel.LocalFree(descriptor)
        if created and not complete:
            # We exclusively created this file, so removing our own
            # partial result is safe — this can never delete another
            # creator's file.
            kernel.DeleteFileW(str(target))


def private_directory(path):
    """Create a fresh directory private to the current user (+ SYSTEM/Administrators).

    The path must not exist: an existing file, directory, symlink, or
    reparse point is rejected untouched — the helper never takes
    ownership of, or alters, a location the caller did not create.
    Creation is secure from the outset (``0o700`` on POSIX; on Windows
    an atomic protected DACL restricted to the current user and
    SYSTEM, so ``private_sqlite_path`` accepts it as a vault parent),
    and the resulting object type and permissions are verified.

    Use this when the caller owns the location outright (test fixtures,
    one-shot tooling). Code that may be handed an existing directory —
    an evaluator key directory, for example — uses
    :func:`ensure_private_directory`, which verifies instead of
    insisting on a fresh path.
    """
    target = Path(os.fspath(path)).expanduser()
    if os.name == 'nt':
        return _windows_private_directory(target, 'private directory',
                                          fresh_only=True)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.mkdir(target, 0o700)
    except FileExistsError:
        raise InvalidInput(
            f'private directory path already exists: {target}') from None
    info = target.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise InvalidInput(
            'private directory creation produced an unexpected object')
    return target


def ensure_private_directory(path, label='private directory'):
    """Return ``path`` as a private directory, creating it only if absent.

    A pre-existing path is verified, never modified: it must be a real
    directory — not a file, symlink, or reparse point — whose
    permissions already deny everyone but the current user, SYSTEM,
    and Administrators. Anything else fails closed. Creation tolerates
    losing the name race to a concurrent creator: the winner's
    directory is then verified exactly like a pre-existing one, so two
    evaluators starting at once converge instead of one of them
    crashing on ``FileExistsError``.
    """
    target = Path(os.fspath(path)).expanduser()
    if os.name == 'nt':
        return _windows_private_directory(target, label, fresh_only=False)
    try:
        info = target.lstat()
    except FileNotFoundError:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.mkdir(target, 0o700)
        except FileExistsError:
            pass
        info = target.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise InvalidInput(
            f'{label} must be a real directory, not a file or link')
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise InvalidInput(
            f'{label} permissions must deny all group and other access')
    return target


def assert_private_acl(path, label='private path'):
    """Read-only check that ``path`` denies everyone but the owner and SYSTEM.

    POSIX: not a symlink, and no group/other permission bits. Windows:
    a real file or directory — never followed through a reparse point —
    whose DACL permits only the current user, SYSTEM, and
    Administrators. Returns ``path`` or raises :class:`InvalidInput`.
    """
    target = Path(os.fspath(path))
    if os.name != 'nt':
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise InvalidInput(
                f'{label} permissions must deny all group and other access')
        return target
    ctx = _windows_api()
    kernel, wintypes = ctx.kernel, ctx.wintypes
    handle = 0

    def fail(message):
        raise InvalidInput(f'{label} Windows ACL check failed: {message}')

    try:
        _, user_sid = _windows_user_sddl(ctx, fail)
        handle = kernel.CreateFileW(
            str(target), 0x00020080, 0x00000001 | 0x00000002 | 0x00000004,
            None, 3, 0x02000000 | 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            fail(f'cannot open path (Windows error {ctypes.get_last_error()})')
        tag = ctx.file_attribute_tag()
        if not kernel.GetFileInformationByHandleEx(
                handle, 9, ctypes.byref(tag), ctypes.sizeof(tag)):
            fail('cannot inspect path')
        if tag.attributes & 0x400:
            fail('path must not be a reparse point')
        if not _windows_dacl_is_restricted(
                handle, ctx, _windows_allowed_sids(user_sid), fail):
            fail('ACL permits access outside the current user, SYSTEM, '
                 'and Administrators')
        return target
    except InvalidInput:
        raise
    except Exception as exc:
        raise InvalidInput(f'{label} Windows ACL check failed') from exc
    finally:
        if handle and handle != wintypes.HANDLE(-1).value:
            kernel.CloseHandle(handle)


def create_private_file(path, payload, label='private file'):
    """Exclusively create ``path`` containing ``payload`` with owner-only access.

    ``O_EXCL``/``CREATE_NEW`` semantics: if the name exists — as
    anything — :class:`FileExistsError` is raised and the existing
    object is left completely untouched, so a losing creator can never
    replace or delete another creator's material. On POSIX the file is
    created ``0o600`` inside an already-private parent. On Windows it
    is created with a protected DACL restricted to the current user
    and SYSTEM, verified, and the payload is written through the same
    secured handle — private from the first byte. On partial-write
    failure the file this call created is removed.
    """
    target = Path(os.fspath(path)).expanduser()
    payload = bytes(payload)
    if os.name == 'nt':
        return _windows_private_file_create(target, payload, label)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = target.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise InvalidInput(f'{label} parent must be a real directory')
    if os.name == 'posix' and stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise InvalidInput(
            f'{label} parent permissions must deny all group and other access')
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    complete = False
    try:
        try:
            written = 0
            while written < len(payload):
                written += os.write(fd, payload[written:])
        finally:
            os.close(fd)
        complete = True
    finally:
        if not complete:
            # Only our own O_EXCL-created file can be here; removing it
            # cannot delete another creator's work.
            target.unlink(missing_ok=True)
    return target


def private_sqlite_path(path, label):
    raw = os.fspath(path)
    if raw == ':memory:':
        raise InvalidInput(f'{label} must be a persistent file')
    target = Path(raw).expanduser()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'nt':
        return _windows_private_sqlite_file(target, label)
    parent_info = target.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise InvalidInput(f'{label} parent must be a real directory')
    if os.name == 'posix' and stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise InvalidInput(f'{label} parent permissions must deny all group and other access')
    if target.is_symlink():
        raise InvalidInput(f'{label} must not be a symlink')
    try:
        fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise InvalidInput(f'{label} must be a regular file')
    if os.name == 'posix' and stat.S_IMODE(info.st_mode) & 0o077:
        raise InvalidInput(f'{label} permissions must deny all group and other access')
    return target
