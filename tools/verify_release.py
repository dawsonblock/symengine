#!/usr/bin/env python3
"""Read-only release verification, ZIP-native and extracted-tree modes.

``verify(path)`` streams a release ZIP without extracting members: it
requires exactly one project directory, exactly one manifest
(``RELEASE_SHA256.json`` preferred, historical ``SOURCE_SHA256.json``
accepted), safe member paths, no symlinks, no duplicates, bounded sizes, and
an exact content-hash match between manifest and archive contents.

``verify_tree(root)`` performs the same fail-closed inventory+hash check on
an already-extracted release tree using ``RELEASE_SHA256.json`` at its root.
"""
import argparse
import compileall
import hashlib
import json
import os
import stat
import sys
import zipfile
import zlib
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_source_manifest import _included, _valid_manifest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
CHUNK = 1024 * 1024

MANIFEST_NAMES = ("RELEASE_SHA256.json", "SOURCE_SHA256.json")


def _hash_member(z, info, *, limit):
    if info.file_size > limit:
        raise ValueError('archive member exceeds size limit: ' + info.filename)
    digest = hashlib.sha256()
    total = 0
    with z.open(info, 'r') as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError('archive member exceeds size limit: ' + info.filename)
            digest.update(block)
    if total != info.file_size:
        raise ValueError('archive member size mismatch: ' + info.filename)
    return digest.hexdigest(), total


def verify(path):
    """Verify a release ZIP in streaming fashion; never extracts members."""
    if os.path.getsize(path) > MAX_ARCHIVE:
        raise ValueError('archive exceeds compressed size limit')
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError('archive contains too many members')
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError('archive has duplicate paths')
        total = 0
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0xffff
            if (name.startswith('/') or '\\' in name
                    or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))
                    or not name or (mode and stat.S_ISLNK(mode))):
                raise ValueError('archive has unsafe path or symlink: ' + name)
            if info.file_size < 0 or info.file_size > MAX_MEMBER:
                raise ValueError('archive member exceeds size limit: ' + name)
            total += info.file_size
        if total > MAX_TOTAL:
            raise ValueError('archive exceeds total uncompressed size limit')
        files = [info for info in infos if not info.is_dir()]
        prefixes = {info.filename.split('/', 1)[0] for info in files}
        if len(prefixes) != 1 or any('/' not in info.filename for info in files):
            raise ValueError('expected one project directory')
        prefix = next(iter(prefixes)) + '/'
        manifests = [i for i in files if i.filename in
                     {prefix + name for name in MANIFEST_NAMES}]
        if len(manifests) != 1:
            raise ValueError('missing exactly-one manifest')
        manifest_info = manifests[0]
        manifest_name = manifest_info.filename[len(prefix):]
        if manifest_info.file_size > MAX_MANIFEST:
            raise ValueError('manifest exceeds size limit')
        with z.open(manifest_info, 'r') as stream:
            manifest_bytes = stream.read(MAX_MANIFEST + 1)
        if len(manifest_bytes) > MAX_MANIFEST or len(manifest_bytes) != manifest_info.file_size:
            raise ValueError('manifest size mismatch or limit exceeded')
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict) or set(manifest) != {'schema', 'files'} \
                or manifest['schema'] != 1 or not isinstance(manifest['files'], dict):
            raise ValueError('invalid manifest schema')
        recorded = manifest['files']
        payload = [i for i in files if i.filename != manifest_info.filename]
        actual = {}
        streamed_total = manifest_info.file_size
        for info in payload:
            relative = info.filename[len(prefix):]
            pure = PurePosixPath(relative)
            if (not relative or pure.is_absolute() or '\\' in relative
                    or any(part in ('', '.', '..') for part in relative.split('/'))):
                raise ValueError('unsafe source path: ' + relative)
            if relative.startswith('release/') or relative.endswith('.zip'):
                raise ValueError('archive embeds out-of-band provenance: ' + relative)
            limit = min(MAX_MEMBER, MAX_TOTAL - streamed_total)
            if limit < 0:
                raise ValueError('archive exceeds total uncompressed size limit')
            actual[relative], size = _hash_member(z, info, limit=limit)
            streamed_total += size
        if actual != recorded:
            bad = sorted(set(actual) ^ set(recorded)
                         | {k for k in set(actual) & set(recorded) if actual[k] != recorded[k]})
            raise ValueError(manifest_name[:-5] + ' mismatch: ' + ', '.join(bad[:8]))
    archive_hash = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            archive_hash.update(block)
    return {'valid': True, 'source_files': len(actual), 'project': prefix[:-1],
            'manifest': manifest_name, 'zip_sha256': archive_hash.hexdigest()}


def verify_tree(root: Path) -> dict:
    """Fail-closed inventory+hash check on an extracted release tree."""
    try:
        document = json.loads((root / "RELEASE_SHA256.json").read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError("RELEASE_SHA256.json is missing") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("RELEASE_SHA256.json is not valid JSON") from exc
    manifest = _valid_manifest(document)
    if any(rel.startswith("release/") or rel.endswith(".zip") for rel in manifest):
        raise ValueError("release manifest covers out-of-band provenance")

    actual: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("release tree contains unexpected symlink: " + str(path))
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _included(relative):
            actual[relative] = path
    if set(actual) != set(manifest):
        extra = sorted(set(actual) - set(manifest))
        missing = sorted(set(manifest) - set(actual))
        raise ValueError(f"release inventory mismatch; extra={extra[:8]!r} missing={missing[:8]!r}")
    for relative, expected in manifest.items():
        if hashlib.sha256(actual[relative].read_bytes()).hexdigest() != expected:
            raise ValueError("release hash mismatch: " + relative)
    return {"files": len(manifest)}


def verify_against_tree(path: Path, root: Path) -> dict:
    """Bind an archive to the source tree it was built from.

    Internal manifest/archive agreement (``verify``) proves only that the
    archive is self-consistent. This check proves the archive contains
    exactly the manifest-covered files currently on disk, so a stale ZIP
    cannot pass just because it still matches its own embedded manifest.
    """
    root = Path(root).resolve()
    with zipfile.ZipFile(path) as z:
        infos = [info for info in z.infolist() if not info.is_dir()]
        prefixes = {info.filename.split("/", 1)[0] for info in infos}
        if len(prefixes) != 1:
            raise ValueError("expected one project directory")
        prefix = next(iter(prefixes)) + "/"
        archived: dict[str, str] = {}
        for info in infos:
            relative = info.filename[len(prefix):]
            if relative in MANIFEST_NAMES:
                continue
            if relative.startswith("release/") or relative.endswith(".zip"):
                raise ValueError("archive embeds out-of-band provenance: " + relative)
            archived[relative] = _hash_member(z, info, limit=MAX_MEMBER)[0]

    current: dict[str, str] = {}
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise ValueError("source tree contains symlink: " + str(candidate))
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(root).as_posix()
        if _included(relative):
            current[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()

    if set(archived) != set(current):
        extra = sorted(set(archived) - set(current))
        missing = sorted(set(current) - set(archived))
        raise ValueError(f"source binding inventory mismatch; stale={extra[:8]!r} unshipped={missing[:8]!r}")
    stale = sorted(rel for rel in archived if archived[rel] != current[rel])
    if stale:
        raise ValueError("source binding hash mismatch: " + ", ".join(stale[:8]))
    return {"files": len(archived), "project": prefix[:-1], "source_bound": True}


def build_zip(root: Path, target: Path) -> Path:
    """Package ``root`` into ``target`` as ``<name>/<files>`` for verify()."""
    manifest = json.loads((root / "RELEASE_SHA256.json").read_text(encoding="utf-8"))
    _valid_manifest(manifest)
    prefix = root.name + "/"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in sorted(manifest["files"]):
            archive.write(root / relative, prefix + relative)
        archive.writestr(prefix + "RELEASE_SHA256.json",
                         json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")) + "\n")
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=str(ROOT),
                        help="release ZIP or extracted tree root")
    parser.add_argument("--compile", action="store_true",
                        help="tree mode: also byte-compile the source")
    args = parser.parse_args(argv)
    path = Path(args.path).resolve()
    try:
        if path.is_file():
            print(json.dumps(verify(path), indent=2))
        else:
            report = verify_tree(path)
            print(f"release verified: {report['files']} files, all SHA-256 matched")
            if args.compile:
                ok = compileall.compile_dir(str(path / "src"), quiet=1, force=True)
                if not ok:
                    raise ValueError("compile check failed")
                print("compile check passed")
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError,
            EOFError, json.JSONDecodeError, zlib.error) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
