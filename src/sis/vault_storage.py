"""Helpers for private, persistent evaluator SQLite files."""
import os
import re
import stat
import ctypes
from pathlib import Path

from .errors import InvalidInput


def _windows_private_sqlite_file(path, label):
    """Create or secure a vault file with a protected user-and-SYSTEM DACL."""
    from ctypes import wintypes

    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    handle = wintypes.HANDLE()
    parent_handle = wintypes.HANDLE()
    token = wintypes.HANDLE()
    descriptor = ctypes.c_void_p()
    parent_descriptor = ctypes.c_void_p()
    parent_sddl_buffer = ctypes.c_void_p()
    queried_descriptor = ctypes.c_void_p()
    sddl_buffer = ctypes.c_void_p()

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
    advapi.OpenProcessToken.argtypes = [handle_type, wintypes.DWORD, ctypes.POINTER(handle_type)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(wintypes.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.SetSecurityInfo.argtypes = [handle_type, ctypes.c_int, wintypes.DWORD,
                                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    advapi.GetSecurityInfo.argtypes = [handle_type, ctypes.c_int, wintypes.DWORD,
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
                                                    ctypes.POINTER(wintypes.WORD),
                                                    ctypes.POINTER(wintypes.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = handle_type
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.POINTER(SecurityAttributes), wintypes.DWORD,
                                   wintypes.DWORD, handle_type]
    kernel.CreateFileW.restype = handle_type
    kernel.GetFileInformationByHandleEx.argtypes = [handle_type, ctypes.c_int, ctypes.c_void_p,
                                                    wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [handle_type]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [handle_type]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p

    def fail(message):
        raise InvalidInput(f'{label} Windows ACL validation failed: {message}')

    def wincheck(ok, message):
        if not ok:
            fail(f'{message} (Windows error {ctypes.get_last_error()})')

    try:
        wincheck(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                          ctypes.byref(token)), 'cannot open current user token')
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            fail('cannot determine current user SID')
        token_buffer = ctypes.create_string_buffer(needed.value)
        wincheck(advapi.GetTokenInformation(token, 1, token_buffer, needed,
                                            ctypes.byref(needed)), 'cannot read current user SID')
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents
        user_sid = ctypes.c_wchar_p()
        wincheck(advapi.ConvertSidToStringSidW(token_user.user.sid, ctypes.byref(user_sid)),
                 'cannot encode current user SID')
        try:
            expected_sddl = f'D:P(A;;FA;;;{user_sid.value})(A;;FA;;;SY)'
        finally:
            kernel.LocalFree(ctypes.cast(user_sid, ctypes.c_void_p))

        parent_handle = kernel.CreateFileW(
            str(path.parent), 0x00020080, 0x00000001 | 0x00000002 | 0x00000004,
            None, 3, 0x02000000 | 0x00200000, None)
        if parent_handle == wintypes.HANDLE(-1).value:
            fail(f'cannot inspect vault directory (Windows error {ctypes.get_last_error()})')
        parent_tag = FileAttributeTagInfo()
        wincheck(kernel.GetFileInformationByHandleEx(parent_handle, 9,
                                                      ctypes.byref(parent_tag),
                                                      ctypes.sizeof(parent_tag)),
                 'cannot inspect vault directory')
        if not parent_tag.attributes & 0x10 or parent_tag.attributes & 0x400:
            fail('vault parent must be a directory and not a reparse point')
        parent_owner = ctypes.c_void_p()
        parent_group = ctypes.c_void_p()
        parent_dacl = ctypes.c_void_p()
        parent_sacl = ctypes.c_void_p()
        result = advapi.GetSecurityInfo(parent_handle, 1, 0x00000004,
                                        ctypes.byref(parent_owner),
                                        ctypes.byref(parent_group),
                                        ctypes.byref(parent_dacl),
                                        ctypes.byref(parent_sacl),
                                        ctypes.byref(parent_descriptor))
        if result or not parent_descriptor.value:
            fail(f'cannot inspect vault directory ACL (Windows error {result})')
        parent_sddl_length = wintypes.DWORD()
        wincheck(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            parent_descriptor, 1, 0x00000004, ctypes.byref(parent_sddl_buffer),
            ctypes.byref(parent_sddl_length)), 'cannot read vault directory ACL')
        parent_sddl = ctypes.wstring_at(parent_sddl_buffer)
        kernel.LocalFree(parent_sddl_buffer)
        parent_sddl_buffer = ctypes.c_void_p()
        allowed_sids = {expected_sddl.split(';;;')[1].split(')')[0], 'SY', 'BA', 'CO'}
        parent_aces = re.findall(r'\(([^()]*)\)', parent_sddl)
        if not parent_aces or any(
                len(ace.split(';')) != 6
                or ace.split(';')[0] != 'A'
                or ace.split(';')[5] not in allowed_sids
                for ace in parent_aces):
            fail('vault directory ACL permits access outside the current user, SYSTEM, and Administrators')

        wincheck(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            expected_sddl, 1, ctypes.byref(descriptor), None), 'cannot create private ACL')
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
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

        tag = FileAttributeTagInfo()
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
        if token:
            kernel.CloseHandle(token)
        if descriptor:
            kernel.LocalFree(descriptor)
        if parent_descriptor:
            kernel.LocalFree(parent_descriptor)
        if parent_sddl_buffer:
            kernel.LocalFree(parent_sddl_buffer)
        if queried_descriptor:
            kernel.LocalFree(queried_descriptor)
        if sddl_buffer:
            kernel.LocalFree(sddl_buffer)


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
