"""Tkinter-based asynchronous proxy scanner.

This module provides :class:`ProxyScannerApp` which coordinates asynchronous
SOCKS5 port scanning and weak credential probing while integrating with a
Tkinter GUI.  The implementation focuses on robustness for concurrent async
operations, providing thread-safe progress accounting and safe interaction with
Tkinter's single-threaded event loop.

The design of this module follows several key goals:

* Use locks to guard shared state that is mutated from async tasks running in a
  thread separate from Tkinter's main loop.
* Check a cooperative ``stop_flag`` frequently to allow users to interrupt
  long-running scans.
* Ensure network resources are released even when exceptions are raised.
* Validate and de-duplicate inputs loaded from user-provided files.
* Restrict scanning to SOCKS5 since other SOCKS variants share the same TCP
  signature and previously caused duplicate work.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

try:  # pragma: no cover - Tk may be unavailable in headless environments
    import tkinter as tk
    from tkinter import messagebox
except Exception:  # pragma: no cover - do not fail when Tk is missing entirely
    tk = None  # type: ignore
    messagebox = None  # type: ignore


@dataclass(frozen=True)
class ProxyCredential:
    """Simple value object for SOCKS5 credentials."""

    username: str
    password: str

    @property
    def as_tuple(self) -> Tuple[str, str]:
        return self.username, self.password


def _dedupe(sequence: Iterable[str]) -> List[str]:
    """Return items from *sequence* preserving order while removing duplicates."""

    seen = OrderedDict()  # type: ignore[var-annotated]
    for item in sequence:
        if item not in seen:
            seen[item] = None
    return list(seen.keys())


class ProxyScannerApp:
    """Coordinate asynchronous SOCKS5 proxy scanning with a Tkinter UI."""

    def __init__(self, root: Optional[tk.Misc] = None, *, timeout: float = 3.0) -> None:
        self.root = root
        self.timeout = timeout

        # Thread-safe primitives -------------------------------------------------
        self.result_lock = threading.Lock()
        self.completed_lock = threading.Lock()
        self.after_lock = threading.Lock()
        self.stop_flag = threading.Event()

        # Progress tracking ------------------------------------------------------
        self.completed = 0
        self.total_tasks = 0

        # Scanner configuration --------------------------------------------------
        self.protocols: List[str] = ["socks5"]
        self.ip_targets: List[str] = []
        self.ports: List[int] = []
        self.credentials: List[ProxyCredential] = []

        # Async runtime state ----------------------------------------------------
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.loop_thread: Optional[threading.Thread] = None
        self.tasks: List[asyncio.Task[None]] = []

        # Tkinter integration ----------------------------------------------------
        if self.root is not None:
            self.after_callable = self.root.after
        else:
            self.after_callable = self._fallback_after

    # ------------------------------------------------------------------ UI tools
    def _fallback_after(self, delay: int, callback, *args):
        """Fallback ``after`` implementation when Tkinter isn't available."""

        if delay <= 0:
            callback(*args)
            return None

        timer = threading.Timer(delay / 1000.0, callback, args=args)
        timer.daemon = True
        timer.start()
        return timer

    def safe_after(self, delay: int, callback, *args) -> object:
        """Thread-safe wrapper around Tk's ``after`` method."""

        with self.after_lock:
            return self.after_callable(delay, callback, *args)

    def _warn_user(self, message: str) -> None:
        if self.root is not None and messagebox is not None:
            self.safe_after(0, messagebox.showwarning, "提示", message)

    # -------------------------------------------------------------- Load helpers
    def load_ip_list(self, path: os.PathLike[str] | str) -> List[str]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)

        with file_path.open("r", encoding="utf-8") as infile:
            ips = [line.strip() for line in infile if line.strip()]

        ips = _dedupe(ips)
        if not ips:
            self._warn_user("IP 列表为空")
            raise ValueError("IP 列表为空")

        self.ip_targets = ips
        return ips

    def load_ports(self, path: os.PathLike[str] | str) -> List[int]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)

        raw_values: List[str] = []
        with file_path.open("r", encoding="utf-8") as infile:
            for line in infile:
                tokenized = [token.strip() for token in line.replace(",", " ").split() if token.strip()]
                raw_values.extend(tokenized)

        ports: List[int] = []
        for value in raw_values:
            if "-" in value:
                try:
                    start_s, end_s = value.split("-", 1)
                    start, end = int(start_s), int(end_s)
                except ValueError as exc:
                    raise ValueError(f"无效端口范围: {value}") from exc
                if start > end or not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValueError(f"端口范围越界: {value}")
                ports.extend(range(start, end + 1))
            else:
                try:
                    port = int(value)
                except ValueError as exc:
                    raise ValueError(f"无效端口: {value}") from exc
                if not (1 <= port <= 65535):
                    raise ValueError(f"端口越界: {port}")
                ports.append(port)

        ports = [int(p) for p in _dedupe([str(p) for p in ports])]
        if not ports:
            self._warn_user("端口列表为空")
            raise ValueError("端口列表为空")

        self.ports = ports
        return ports

    def load_creds(self, path: os.PathLike[str] | str) -> List[ProxyCredential]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)

        creds: List[ProxyCredential] = []
        seen = set()
        with file_path.open("r", encoding="utf-8") as infile:
            for raw_line in infile:
                line = raw_line.strip()
                if not line:
                    continue
                if ":" not in line:
                    continue
                username, password = line.split(":", 1)
                key = (username.strip(), password.strip())
                if not key[0] and not key[1]:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                creds.append(ProxyCredential(*key))

        if not creds:
            self._warn_user("凭证列表为空")
            raise ValueError("凭证列表为空")

        self.credentials = creds
        return creds

    # --------------------------------------------------------------- Scan control
    def _compute_total_tasks(self) -> None:
        self.total_tasks = len(self.ip_targets) * len(self.ports)

    def start_scan(self) -> None:
        if not self.ip_targets or not self.ports:
            raise RuntimeError("未加载 IP 或端口列表")

        self.stop_flag.clear()
        self.completed = 0
        self._compute_total_tasks()
        self.tasks.clear()

        loop = asyncio.new_event_loop()
        self.loop = loop

        def runner() -> None:
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._run_scan())
            finally:
                with contextlib.suppress(RuntimeError):
                    loop.stop()
                try:
                    loop.close()
                except RuntimeError:
                    # Windows sometimes raises if close is called after stop but
                    # loop is already closing. Swallow to keep shutdown smooth.
                    pass
                self.loop = None

        self.loop_thread = threading.Thread(target=runner, daemon=True)
        self.loop_thread.start()

    def stop_scan(self) -> None:
        self.stop_flag.set()
        loop = self.loop
        if loop and loop.is_running():
            for task in list(self.tasks):
                task.cancel()
            loop.call_soon_threadsafe(loop.stop)
        if self.loop_thread and self.loop_thread.is_alive():
            self.loop_thread.join(timeout=1.0)

    async def _run_scan(self) -> None:
        tasks = []
        for ip in self.ip_targets:
            for port in self.ports:
                if self.stop_flag.is_set():
                    break
                tasks.append(asyncio.create_task(self.async_port_scan(ip, port)))
            if self.stop_flag.is_set():
                break

        self.tasks = tasks
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*tasks, return_exceptions=False)

    # ------------------------------------------------------------ Async routines
    async def async_port_scan(self, ip: str, port: int) -> None:
        if self.stop_flag.is_set():
            self._increment_completed()
            return

        writer: Optional[asyncio.StreamWriter] = None
        try:
            writer = await self.async_check_port(ip, port)
            if writer is None:
                return

            with self.result_lock:
                self.safe_after(0, self.on_port_open, ip, port)
            if self.credentials and not self.stop_flag.is_set():
                self._increment_total(1)
                await self.async_weak_pass_scan(ip, port)
        except asyncio.CancelledError:
            raise
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            self._increment_completed()

    async def async_check_port(self, ip: str, port: int) -> Optional[asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, OSError, ConnectionError):
            return None
        except asyncio.CancelledError:
            raise
        else:
            return writer

    async def async_weak_pass_scan(self, ip: str, port: int) -> None:
        try:
            for credential in self.credentials:
                if self.stop_flag.is_set():
                    break

                writer: Optional[asyncio.StreamWriter] = None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout,
                    )
                    authenticated = await self.async_authenticate(reader, writer, credential)
                    if authenticated:
                        with self.result_lock:
                            self.safe_after(0, self.on_weak_credential_found, ip, port, credential)
                        break
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    continue
                except asyncio.CancelledError:
                    raise
                finally:
                    if writer is not None:
                        writer.close()
                        with contextlib.suppress(Exception):
                            await writer.wait_closed()
        finally:
            self._increment_completed()

    async def async_authenticate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        credential: ProxyCredential,
    ) -> bool:
        """Attempt SOCKS5 authentication using *credential*.

        The base implementation simply returns ``False``.  Tests can monkeypatch
        or subclasses can override this method to perform protocol-specific
        authentication.
        """

        return False

    # ------------------------------------------------------------- Event hooks
    def on_port_open(self, ip: str, port: int) -> None:
        """Hook executed when a port is confirmed open."""

    def on_weak_credential_found(self, ip: str, port: int, credential: ProxyCredential) -> None:
        """Hook executed when weak credentials have been discovered."""

    def on_progress(self, completed: int, total: int) -> None:
        """Hook executed when progress counters advance."""

    # ------------------------------------------------------------ Misc helpers
    def _increment_total(self, delta: int) -> None:
        if not delta:
            return
        with self.completed_lock:
            self.total_tasks += delta
            completed_snapshot = self.completed
            total_snapshot = self.total_tasks
        self.safe_after(0, self.on_progress, completed_snapshot, total_snapshot)

    def _increment_completed(self) -> None:
        with self.completed_lock:
            self.completed += 1
            completed_snapshot = self.completed
            total_snapshot = self.total_tasks
        self.safe_after(0, self.on_progress, completed_snapshot, total_snapshot)


__all__ = ["ProxyScannerApp", "ProxyCredential"]
