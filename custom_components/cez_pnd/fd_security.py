"""Small, fail-closed helpers for immutable file-descriptor snapshots."""

import fcntl
import hashlib
import os
import stat
from typing import Iterable, Optional, Tuple


SNAPSHOT_SEALS = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)


class SnapshotError(OSError):
    """The requested immutable bounded snapshot could not be made safely."""


class SealedReport:
    """Owned immutable report descriptor transferred from browser to parser."""

    __slots__ = ("_fd", "logical_name", "size", "digest", "_used")

    def __init__(self, fd: int, logical_name: str, size: int, digest: str) -> None:
        if not isinstance(fd, int) or fd < 0 or not isinstance(logical_name, str) or not logical_name:
            raise SnapshotError("Invalid sealed report ownership")
        self._fd = fd
        self.logical_name = logical_name
        self.size = size
        self.digest = digest
        self._used = False

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise SnapshotError("Sealed report descriptor is closed")
        return self._fd

    def duplicate_for_read(self) -> int:
        """Consume this ownership once and return a separate read descriptor."""
        if self._used or self._fd < 0:
            raise SnapshotError("Sealed report descriptor was already consumed")
        verify_sealed_fd(self._fd, self.size, self.digest)
        try:
            duplicate = os.dup(self._fd)
        except OSError as err:
            raise SnapshotError("Sealed report descriptor cannot be duplicated") from err
        self._used = True
        return duplicate

    def close(self) -> None:
        fd, self._fd = self._fd, -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> "SealedReport":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __getstate__(self) -> None:
        raise TypeError("SealedReport is process-local and not serializable")


def verify_sealed_fd(fd: int, expected_size: Optional[int] = None, expected_digest: Optional[str] = None) -> None:
    """Fail closed unless fd is an exact sealed memfd with expected metadata."""
    required = ("F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
    if not all(hasattr(fcntl, name) for name in required):
        raise SnapshotError("Sealed report verification is unavailable")
    try:
        file_stat = os.fstat(fd)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        proc_target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as err:
        raise SnapshotError("Sealed report descriptor cannot be verified") from err
    if not stat.S_ISREG(file_stat.st_mode):
        raise SnapshotError("Sealed report descriptor is not regular")
    if not proc_target.startswith("/memfd:") or seals != SNAPSHOT_SEALS:
        raise SnapshotError("Sealed report descriptor is not an exact memfd snapshot")
    if expected_size is not None and file_stat.st_size != expected_size:
        raise SnapshotError("Sealed report size changed")
    if expected_digest is not None:
        # The snapshot is sealed, so the producer's digest is authoritative;
        # callers that need a content check use the bounded readback digest.
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            raise SnapshotError("Sealed report digest metadata is invalid")


def close_sealed_reports(values: Optional[Iterable[object]]) -> None:
    """Close all owned SealedReport values, safely and idempotently."""
    if values is None:
        return
    seen = set()
    for value in values:
        if isinstance(value, SealedReport) and id(value) not in seen:
            seen.add(id(value))
            value.close()


def _new_sealed_memfd(label: str) -> int:
    """Create a memfd with sealing explicitly enabled, or fail closed."""
    required = ("memfd_create", "MFD_ALLOW_SEALING", "MFD_CLOEXEC")
    if not all(hasattr(os, name) for name in required):
        raise SnapshotError("Immutable file snapshot is unavailable")
    try:
        return os.memfd_create(label, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    except OSError as err:
        raise SnapshotError("Immutable file snapshot is unavailable") from err


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as err:
            raise SnapshotError("Immutable file snapshot write failed") from err
        if written <= 0:
            raise SnapshotError("Immutable file snapshot write failed")
        view = view[written:]


def _read_digest(descriptor: int, max_size: int) -> Tuple[int, str]:
    """Read from offset zero, bounded by max_size+1, and return size plus SHA-256."""
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as err:
        raise SnapshotError("Immutable file snapshot read failed") from err
    digest = hashlib.sha256()
    total = 0
    while total <= max_size:
        try:
            chunk = os.read(descriptor, min(64 * 1024, max_size + 1 - total))
        except OSError as err:
            raise SnapshotError("Immutable file snapshot read failed") from err
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if total > max_size:
            raise SnapshotError("Immutable file snapshot exceeds its size limit")
    return total, digest.hexdigest()


def _seal(descriptor: int) -> None:
    try:
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SNAPSHOT_SEALS)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as err:
        raise SnapshotError("Immutable file snapshot sealing is unavailable") from err
    if seals != SNAPSHOT_SEALS:
        raise SnapshotError("Immutable file snapshot sealing is incomplete")


def bounded_sealed_snapshot(
    source_fd: int, max_size: int, label: str, logical_name: str = "report.csv"
) -> SealedReport:
    """Copy a regular source FD into a bounded, sealed memfd.

    The source is read twice and hashed both times.  The first pass populates the
    snapshot; the second pass detects same-size content changes during copying.
    Metadata is checked around both passes as an additional fail-closed guard.
    The returned descriptor is positioned at offset zero and belongs to caller.
    """
    snapshot_fd = _new_sealed_memfd(label)
    try:
        try:
            initial = os.fstat(source_fd)
        except OSError as err:
            raise SnapshotError("Source file cannot be inspected") from err

        try:
            os.lseek(source_fd, 0, os.SEEK_SET)
        except OSError as err:
            raise SnapshotError("Source file cannot be read") from err
        first_digest_obj = hashlib.sha256()
        first_size = 0
        while first_size <= max_size:
            try:
                chunk = os.read(source_fd, min(64 * 1024, max_size + 1 - first_size))
            except OSError as err:
                raise SnapshotError("Source file cannot be read") from err
            if not chunk:
                break
            _write_all(snapshot_fd, chunk)
            first_digest_obj.update(chunk)
            first_size += len(chunk)
            if first_size > max_size:
                raise SnapshotError("Source file exceeds its size limit")
        first_digest = first_digest_obj.hexdigest()
        try:
            after_first = os.fstat(source_fd)
        except OSError as err:
            raise SnapshotError("Source file cannot be inspected") from err
        if (
            first_size <= 0
            or first_size > max_size
            or after_first.st_size != first_size
            or (after_first.st_dev, after_first.st_ino) != (initial.st_dev, initial.st_ino)
            or getattr(after_first, "st_mtime_ns", None) != getattr(initial, "st_mtime_ns", None)
            or getattr(after_first, "st_ctime_ns", None) != getattr(initial, "st_ctime_ns", None)
        ):
            raise SnapshotError("Source file changed during snapshot")

        # Re-read the source and compare a digest before sealing the copy.
        second_size, second_digest = _read_digest(source_fd, max_size)
        try:
            after_second = os.fstat(source_fd)
        except OSError as err:
            raise SnapshotError("Source file cannot be inspected") from err
        if (
            second_size != first_size
            or second_digest != first_digest
            or after_second.st_size != first_size
            or (after_second.st_dev, after_second.st_ino) != (initial.st_dev, initial.st_ino)
            or getattr(after_second, "st_mtime_ns", None) != getattr(initial, "st_mtime_ns", None)
            or getattr(after_second, "st_ctime_ns", None) != getattr(initial, "st_ctime_ns", None)
        ):
            raise SnapshotError("Source file changed during snapshot")

        _seal(snapshot_fd)
        os.lseek(snapshot_fd, 0, os.SEEK_SET)
        report = SealedReport(snapshot_fd, logical_name, first_size, first_digest)
        snapshot_fd = -1
        return report
    except Exception:
        try:
            os.close(snapshot_fd)
        except OSError:
            pass
        raise
