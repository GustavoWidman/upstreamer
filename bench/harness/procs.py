"""Processes pinned to CPUs and accounted in their own cgroup.

Each role (origin, proxy, load generator) runs in a transient systemd user
scope so its CPU time and peak memory come from the cgroup, covering every
process and thread it spawns. Pinning uses taskset because the user manager
is not delegated the cpuset controller.
"""

import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .topology import cpulist

CGROUP_ROOT = Path("/sys/fs/cgroup")


def _systemctl(*args: str) -> str:
    return subprocess.run(
        ["systemctl", "--user", *args], capture_output=True, text=True, check=False
    ).stdout.strip()


class Scope:
    def __init__(
        self,
        role: str,
        argv: list[str],
        cpus: tuple[int, ...],
        log: Path,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ):
        self.role = role
        self.cpus = cpus
        self.unit = f"bench-{role}-{uuid.uuid4().hex[:8]}.scope"
        self.log = log
        self._log_file = log.open("ab")
        cmd = [
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            f"--unit={self.unit}",
            "-p",
            "CPUAccounting=yes",
            "-p",
            "MemoryAccounting=yes",
            "--",
            "taskset",
            "-c",
            cpulist(cpus),
            *argv,
        ]
        self.argv = argv
        self.proc = subprocess.Popen(
            cmd,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            start_new_session=True,
        )
        self.started = time.monotonic()
        self.cgroup = self._find_cgroup()

    def _find_cgroup(self) -> Path:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            cg = _systemctl("show", "-P", "ControlGroup", self.unit)
            if cg:
                path = CGROUP_ROOT / cg.lstrip("/")
                if (path / "cpu.stat").exists():
                    return path
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.role} exited early: see {self.log}")
            time.sleep(0.02)
        raise RuntimeError(f"no cgroup for {self.unit}")

    def alive(self) -> bool:
        return self.proc.poll() is None or bool(self.pids())

    def pids(self) -> list[int]:
        try:
            return [int(p) for p in (self.cgroup / "cgroup.procs").read_text().split()]
        except FileNotFoundError:
            return []

    def cpu_seconds(self) -> float:
        try:
            for line in (self.cgroup / "cpu.stat").read_text().splitlines():
                key, value = line.split()
                if key == "usage_usec":
                    return int(value) / 1e6
        except FileNotFoundError:
            pass
        return float("nan")

    def _read_int(self, name: str) -> int | None:
        try:
            return int((self.cgroup / name).read_text())
        except (FileNotFoundError, ValueError):
            return None

    def memory_current(self) -> int | None:
        return self._read_int("memory.current")

    def memory_peak(self) -> int | None:
        return self._read_int("memory.peak")

    def memory_anon(self) -> int | None:
        try:
            for line in (self.cgroup / "memory.stat").read_text().splitlines():
                key, value = line.split()
                if key == "anon":
                    return int(value)
        except FileNotFoundError:
            pass
        return None

    def pss(self) -> int:
        """Sum of proportional set size over the scope's processes, in bytes."""
        total = 0
        for pid in self.pids():
            try:
                for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
                    if line.startswith("Pss:"):
                        total += int(line.split()[1]) * 1024
                        break
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        return total

    def stop(self, timeout: float = 10) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        _systemctl("stop", self.unit)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            _systemctl("kill", "--signal=SIGKILL", self.unit)
            self.proc.wait(timeout)
        self._log_file.close()


FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


@dataclass
class CpuSnapshot:
    """Per-CPU jiffies from /proc/stat by field, plus a timestamp.

    Steal is time a vCPU was runnable but the hypervisor ran something else;
    on a VM it is the main source of run-to-run noise, so it is kept apart.
    Softirq time (loopback packet processing) is not charged to any cgroup,
    so a role's saturation is read from its CPUs' idle time instead."""

    at: float
    cpus: dict[int, tuple[int, ...]]

    @classmethod
    def take(cls) -> "CpuSnapshot":
        cpus = {}
        with open("/proc/stat") as f:
            for line in f:
                if not line.startswith("cpu") or line.startswith("cpu "):
                    continue
                parts = line.split()
                cpus[int(parts[0][3:])] = tuple(map(int, parts[1:9]))
        return cls(time.monotonic(), cpus)


HZ = os.sysconf("SC_CLK_TCK")


def breakdown(a: CpuSnapshot, b: CpuSnapshot, cpus) -> dict[str, float]:
    """Seconds spent per /proc/stat field over `cpus` between two snapshots."""
    total = dict.fromkeys(FIELDS, 0.0)
    for c in cpus:
        for name, x, y in zip(FIELDS, a.cpus[c], b.cpus[c]):
            total[name] += (y - x) / HZ
    return total


@dataclass
class MemorySampler:
    """Samples a scope's PSS and cgroup memory in a background thread."""

    scope: Scope
    interval: float = 1.0
    pss_peak: int = 0
    current_peak: int = 0
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def sample(self) -> None:
        self.pss_peak = max(self.pss_peak, self.scope.pss())
        self.current_peak = max(self.current_peak, self.scope.memory_current() or 0)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.sample()

    def __enter__(self) -> "MemorySampler":
        self.sample()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
        self.sample()


def loadavg() -> list[float]:
    return [float(x) for x in Path("/proc/loadavg").read_text().split()[:3]]


def raise_nofile() -> int:
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = min(hard, 1 << 20)
    if soft < target:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    return target


@dataclass
class Finished:
    returncode: int
    cpu_seconds: float
    wall_seconds: float
    max_rss_bytes: int


def run_pinned(
    argv: list[str], cpus: tuple[int, ...], log: Path, cwd: Path | None = None
) -> Finished:
    """Run a short-lived process (a load generator) pinned to `cpus`.

    CPU time comes from wait4's rusage, which covers every thread of the
    process, so no cgroup is needed for a single-process tool.
    """
    with log.open("ab") as out:
        start = time.monotonic()
        proc = subprocess.Popen(
            ["taskset", "-c", cpulist(cpus), *argv],
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
        )
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        return Finished(
            proc.returncode,
            usage.ru_utime + usage.ru_stime,
            time.monotonic() - start,
            usage.ru_maxrss * 1024,
        )
