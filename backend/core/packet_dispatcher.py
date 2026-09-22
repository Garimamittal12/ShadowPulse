"""
PacketDispatcher
================
The SINGLE packet capture point for ShadowPulse.

One shared Scapy AsyncSniffer captures packets from the network interface
and fans them out to every registered detector. No detector may call
``scapy.sniff()`` on its own — that would capture the same traffic multiple
times and waste resources.

Design:
    - Owns a single ``scapy.AsyncSniffer`` (or blocking sniff in a daemon thread
      depending on availability).
    - Maintains a registry of detectors that implement ``handle_packet(packet)``.
    - Tracks runtime counters (packets seen, packets/sec, dropped packets).
    - Thread-safe: registration/removal of detectors and counter reads can
      happen concurrently with packet capture.
    - Uses a worker thread pool so a slow detector never blocks packet capture.
    - Monitors the capture interface and auto-recovers if the adapter
      disconnects / changes (hot-swap support on Windows).
    - Attaches capture timestamps to every packet before fan-out.
"""

from __future__ import annotations

import platform
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Deque, Dict, List, Optional

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - environment without scapy
    scapy = None
    SCAPY_AVAILABLE = False

from utils.logger import get_logger
from utils.network_scanner import NetworkScanner

logger = get_logger()

# Log a capture summary every N packets (avoid log spam).
_LOG_EVERY_N_PACKETS = 500

# Max number of worker threads for parallel detector processing.
_MAX_WORKER_THREADS = 4

# How often (seconds) to check capture health / interface validity.
_CAPTURE_MONITOR_INTERVAL = 5.0


def _configure_scapy() -> None:
    """Ensure Scapy uses Npcap/libpcap on Windows."""
    if not SCAPY_AVAILABLE:
        return
    try:
        # Force Npcap usage on Windows (preferred over WinPcap).
        scapy.conf.use_pcap = True
        if platform.system() == "Windows":
            try:
                from scapy.arch import pcapdnet
            except Exception:
                pass
            scapy.conf.use_pcap = True
            # Set a larger default buffer for high-throughput capture.
            try:
                scapy.conf.bufsize = 65536
            except Exception:
                pass
    except Exception as exc:
        logger.warning(f"Dispatcher: Scapy pcap configuration warning: {exc}")


_configure_scapy()


class PacketDispatcher:
    """Single sniffer + fan-out dispatcher for all detectors."""

    def __init__(
        self,
        interface: Optional[str] = None,
        filter_str: Optional[str] = None,
        buffer_size: int = 65536,
        store: bool = False,
    ):
        self.interface = interface
        self.filter = filter_str
        self.buffer_size = buffer_size
        self.store = store

        # Detector registry: name -> callable(packet)
        self._detectors: Dict[str, Callable] = {}
        self._lock = threading.RLock()
        # Detectors keep small state tables (ARP mappings, DNS transactions,
        # DHCP offers).  A detector must see packets in a serialised order even
        # though unrelated detectors may run in parallel.
        self._detector_locks: Dict[str, threading.Lock] = {}

        # Capture state
        self._sniffer: Optional[object] = None
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._capture_error: Optional[str] = None
        self._using_filter: Optional[str] = None
        self._last_log_count = 0

        # Worker thread pool for parallel detector processing.
        # A slow detector must not block packet capture.
        # NOTE: The pool is recreated on every start() because stop()
        # permanently shuts it down (ThreadPoolExecutor cannot be restarted).
        self._worker_pool: Optional[ThreadPoolExecutor] = None
        self._pending_tasks = 0
        self._tasks_lock = threading.Lock()
        self._ensure_worker_pool()

        # Interface hot-swap / recovery monitor thread.
        self._monitor_thread: Optional[threading.Thread] = None

        # Runtime counters (thread-safe)
        self._counters_lock = threading.Lock()
        self._packet_count = 0
        self._dropped_count = 0
        self._detector_error_count = 0
        self._started_at: Optional[datetime] = None
        self._rate_samples: Deque[tuple] = deque(maxlen=60)  # (ts, count)
        self._last_rate = 0.0
        self._last_sample_ts = time.time()
        self._last_sample_count = 0

    # ------------------------------------------------------------------
    # Detector registry
    # ------------------------------------------------------------------
    def register(self, name: str, callback: Callable) -> None:
        """Register a detector callback. The callback receives each packet."""
        with self._lock:
            self._detectors[name] = callback
            self._detector_locks[name] = threading.Lock()
            logger.info(f"Dispatcher: registered detector '{name}'")

    def unregister(self, name: str) -> None:
        """Remove a detector callback from the fan-out."""
        with self._lock:
            self._detectors.pop(name, None)
            self._detector_locks.pop(name, None)
            logger.info(f"Dispatcher: unregistered detector '{name}'")

    def registered_names(self) -> List[str]:
        with self._lock:
            return list(self._detectors.keys())

    @property
    def detector_count(self) -> int:
        with self._lock:
            return len(self._detectors)

    # ------------------------------------------------------------------
    # Worker pool lifecycle
    # ------------------------------------------------------------------
    def _ensure_worker_pool(self) -> None:
        """Create the worker pool if it does not exist or was shut down.

        ThreadPoolExecutor cannot be restarted once shutdown() is called,
        so start()/restart() must always ensure a fresh pool.
        """
        if self._worker_pool is None or self._worker_pool._shutdown:
            self._worker_pool = ThreadPoolExecutor(
                max_workers=_MAX_WORKER_THREADS,
                thread_name_prefix="detector-worker",
            )

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------
    def _resolve_interface(self) -> Optional[str]:
        """Resolve configured interface to a Scapy/Npcap device name."""
        info = NetworkScanner.resolve_capture_interface(self.interface)
        resolved = info.get("scapy_iface")
        if resolved:
            if resolved != self.interface:
                logger.info(
                    f"Dispatcher: resolved interface '{self.interface}' -> '{resolved}' "
                    f"(psutil={info.get('psutil_name')}, ip={info.get('local_ip')})"
                )
            self.interface = resolved
            return resolved

        logger.error(
            f"Dispatcher: could not resolve capture interface (configured={self.interface})"
        )
        return None

    def start(self) -> bool:
        """Start the single packet sniffer. Returns True if capture is active."""
        if self._running:
            logger.warning("Dispatcher: sniffer already running")
            return True

        if not SCAPY_AVAILABLE:
            self._capture_error = "scapy is not available"
            logger.error("Dispatcher: scapy is not available; cannot start sniffer")
            return False

        iface = self._resolve_interface()
        if not iface:
            self._capture_error = "no valid network interface"
            return False

        self._stop_event.clear()
        self._running = True
        self._capture_error = None
        self._started_at = datetime.utcnow()
        self._packet_count = 0
        self._dropped_count = 0
        self._last_log_count = 0

        # Ensure the worker pool exists (recreate after stop()/restart()).
        self._ensure_worker_pool()

        # Try with BPF filter first, then without (Npcap BPF can be restrictive).
        for attempt_filter in (self.filter, None):
            if self._try_start_sniffer(iface, attempt_filter):
                self._using_filter = attempt_filter
                filter_label = attempt_filter or "(no filter — all protocols)"
                logger.info(
                    f"Dispatcher: packet capture started on '{iface}' filter={filter_label}"
                )
                self._schedule_capture_health_check()
                self._start_capture_monitor()
                return True

        self._running = False
        self._capture_error = self._capture_error or "sniffer failed to start"
        logger.error(f"Dispatcher: failed to start capture on '{iface}': {self._capture_error}")
        return False

    def _try_start_sniffer(self, iface: str, bpf_filter: Optional[str]) -> bool:
        """Attempt AsyncSniffer then blocking sniff fallback."""
        label = bpf_filter or "none"
        try:
            self._sniffer = scapy.AsyncSniffer(
                iface=iface,
                prn=self._on_packet,
                filter=bpf_filter,
                store=self.store,
                started_callback=lambda: logger.info(
                    f"Dispatcher: AsyncSniffer active on {iface} (filter={label})"
                ),
            )
            self._sniffer.start()
            time.sleep(0.3)
            if hasattr(self._sniffer, "running") and not self._sniffer.running:
                raise RuntimeError("AsyncSniffer exited immediately")
            return True
        except Exception as exc:
            logger.warning(
                f"Dispatcher: AsyncSniffer failed on '{iface}' filter={label}: {exc}"
            )
            self._sniffer = None

        try:
            self._sniffer_thread = threading.Thread(
                target=self._sniff_blocking,
                kwargs={"iface": iface, "bpf_filter": bpf_filter},
                daemon=True,
                name="sniffer-thread",
            )
            self._sniffer_thread.start()
            time.sleep(0.3)
            if self._sniffer_thread.is_alive():
                logger.info(
                    f"Dispatcher: blocking sniff thread active on {iface} (filter={label})"
                )
                return True
        except Exception as exc:
            self._capture_error = str(exc)
            logger.error(f"Dispatcher: blocking sniff failed: {exc}")

        return False

    def _schedule_capture_health_check(self) -> None:
        """Warn if no packets arrive shortly after startup (admin/Npcap issues)."""
        def _check() -> None:
            time.sleep(8)
            if not self._running:
                return
            count = self.packet_count
            if count == 0:
                logger.warning(
                    "Dispatcher: no packets captured after 8s — "
                    "run ShadowPulse as Administrator, confirm Npcap is installed, "
                    "and verify the selected adapter has live traffic"
                )
            else:
                logger.info(
                    f"Dispatcher: capture healthy — {count} packets, "
                    f"{round(self.packet_rate(), 1)} pkt/s"
                )

        threading.Thread(target=_check, daemon=True, name="capture-health").start()

    def _sniff_blocking(self, iface: str, bpf_filter: Optional[str] = None) -> None:
        """Fallback: run blocking sniff in a daemon thread."""
        try:
            scapy.sniff(
                iface=iface,
                prn=self._on_packet,
                filter=bpf_filter,
                store=self.store,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            self._capture_error = str(exc)
            logger.error(f"Dispatcher: blocking sniff error: {exc}")
            self._running = False

    # ------------------------------------------------------------------
    # Capture monitoring / interface hot-swap recovery
    # ------------------------------------------------------------------
    def _start_capture_monitor(self) -> None:
        """Start the background thread that watches capture health."""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self._monitor_thread = threading.Thread(
            target=self._capture_monitor_loop,
            daemon=True,
            name="capture-monitor",
        )
        self._monitor_thread.start()

    def _capture_monitor_loop(self) -> None:
        """Periodically verify the sniffer is still alive and the interface
        is still valid. If the adapter disconnects / changes, restart capture
        on the new active adapter (hot-swap recovery)."""
        last_packet_count = self.packet_count
        last_packet_change_ts = time.time()

        while self._running and not self._stop_event.is_set():
            time.sleep(_CAPTURE_MONITOR_INTERVAL)

            if not self._running:
                break

            # 1. If the sniffer thread died, attempt recovery.
            if not self.is_running:
                logger.warning(
                    "Dispatcher: capture thread died; attempting recovery "
                    f"(error={self._capture_error})"
                )
                self._recover_capture()
                continue

            # 2. Detect a dead/stalled capture (no packets for >30s).
            current_count = self.packet_count
            now = time.time()
            if current_count != last_packet_count:
                last_packet_count = current_count
                last_packet_change_ts = now
            elif now - last_packet_change_ts > 30:
                logger.warning(
                    "Dispatcher: no packets for 30s; interface may be "
                    "disconnected — attempting recovery"
                )
                self._recover_capture()
                last_packet_count = self.packet_count
                last_packet_change_ts = time.time()

    def _recover_capture(self) -> None:
        """Stop the current sniffer and restart on the best available adapter."""
        logger.info("Dispatcher: attempting capture recovery...")
        try:
            self._stop_sniffer_only()
        except Exception as exc:
            logger.warning(f"Dispatcher: recovery stop error: {exc}")

        time.sleep(1.0)

        # Re-resolve the interface (may have changed on hot-swap).
        new_iface = self._resolve_interface()
        if not new_iface:
            self._capture_error = "recovery: no valid interface"
            logger.error(self._capture_error)
            return

        self._stop_event.clear()
        self._running = True
        self._capture_error = None

        for attempt_filter in (self.filter, None):
            if self._try_start_sniffer(new_iface, attempt_filter):
                self._using_filter = attempt_filter
                logger.info(
                    f"Dispatcher: capture recovered on '{new_iface}' "
                    f"filter={attempt_filter or 'none'}"
                )
                return

        self._running = False
        self._capture_error = self._capture_error or "recovery failed"
        logger.error(f"Dispatcher: capture recovery failed: {self._capture_error}")

    def _stop_sniffer_only(self) -> None:
        """Stop just the sniffer (used during recovery)."""
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.warning(f"Dispatcher: error stopping AsyncSniffer: {exc}")
            self._sniffer = None

        if self._sniffer_thread is not None and self._sniffer_thread.is_alive():
            try:
                self._sniffer_thread.join(timeout=3)
            except Exception:
                pass
            self._sniffer_thread = None

    def stop(self) -> None:
        """Stop the sniffer cleanly and shut down the worker pool."""
        self._stop_event.set()
        self._running = False

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.warning(f"Dispatcher: error stopping AsyncSniffer: {exc}")
            self._sniffer = None

        if self._sniffer_thread is not None and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=3)
            self._sniffer_thread = None

        # Stop the capture monitor thread.
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2)
            self._monitor_thread = None

        # Shut down the worker pool (waits briefly for in-flight tasks).
        try:
            self._worker_pool.shutdown(wait=False, cancel_futures=True)
        except Exception as exc:
            logger.warning(f"Dispatcher: worker pool shutdown error: {exc}")

        logger.info(
            f"Dispatcher: packet capture stopped (total_packets={self.packet_count})"
        )

    @property
    def is_running(self) -> bool:
        if self._sniffer is not None and hasattr(self._sniffer, "running"):
            return bool(self._sniffer.running)
        if self._sniffer_thread is not None and self._sniffer_thread.is_alive():
            return True
        return self._running

    # ------------------------------------------------------------------
    # Packet handling
    # ------------------------------------------------------------------
    def _packet_summary(self, packet) -> str:
        """Build a short log line for a captured packet."""
        proto = "unknown"
        src = dst = "-"
        try:
            if packet.haslayer("ARP"):
                proto = "ARP"
                src = packet["ARP"].psrc
                dst = packet["ARP"].pdst
            elif packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst
                if packet.haslayer("UDP"):
                    dport = packet["UDP"].dport
                    sport = packet["UDP"].sport
                    proto = f"UDP/{dport}" if dport in (53, 67, 68) else f"UDP {sport}->{dport}"
                elif packet.haslayer("TCP"):
                    dport = packet["TCP"].dport
                    proto = f"TCP/{dport}"
                elif packet.haslayer("ICMP"):
                    proto = "ICMP"
                else:
                    proto = "IP"
        except Exception:
            pass
        return f"{proto} {src} -> {dst}"

    def _on_packet(self, packet) -> None:
        """Called for every captured packet. Fan out to all detectors.

        Detectors are invoked through a worker thread pool so a slow
        detector never blocks packet capture. A capture timestamp is
        attached to the packet before fan-out.
        """
        if not self._running:
            return

        with self._counters_lock:
            self._packet_count += 1
            count = self._packet_count

        if count == 1:
            logger.info(f"Dispatcher: first packet captured — {self._packet_summary(packet)}")
        elif count - self._last_log_count >= _LOG_EVERY_N_PACKETS:
            self._last_log_count = count
            logger.info(
                f"Dispatcher: {count} packets captured "
                f"({round(self.packet_rate(), 1)} pkt/s) — "
                f"latest: {self._packet_summary(packet)}"
            )

        # Attach capture timestamp so detectors use real capture time.
        try:
            packet.capture_time = datetime.utcnow()
        except Exception:
            pass

        # Snapshot detector list under lock so unregister mid-iteration is safe.
        with self._lock:
            callbacks = list(self._detectors.items())

        # Route only relevant packets to each detector.  Sending every packet
        # through every detector made the IDS slower and let unrelated traffic
        # influence detector state.
        # NOTE: Increment _pending_tasks BEFORE submit to avoid a race where a
        # fast worker finishes (and decrements) before we increment. If submit
        # fails, we decrement and fall back to inline processing.
        for name, callback in callbacks:
            if not self._is_relevant_packet(name, packet):
                continue
            with self._tasks_lock:
                self._pending_tasks += 1
            try:
                self._worker_pool.submit(self._dispatch_to_detector, name, callback, packet)
            except Exception as exc:
                # Thread pool exhausted or shut down — fall back to inline.
                with self._tasks_lock:
                    self._pending_tasks = max(0, self._pending_tasks - 1)
                logger.warning(f"Dispatcher: worker pool submit failed for '{name}': {exc}")
                try:
                    callback(packet)
                except Exception as exc2:
                    logger.error(f"Dispatcher: detector '{name}' error: {exc2}")
                    with self._counters_lock:
                        self._dropped_count += 1
                        self._detector_error_count += 1

    def _dispatch_to_detector(self, name: str, callback: Callable, packet) -> None:
        """Run a single detector callback in a worker thread."""
        try:
            with self._lock:
                detector_lock = self._detector_locks.get(name)
            if detector_lock is None:
                return
            with detector_lock:
                callback(packet)
        except Exception as exc:
            # A crashing detector must never stop the sniffer.
            logger.error(f"Dispatcher: detector '{name}' error: {exc}")
            with self._counters_lock:
                self._dropped_count += 1
                self._detector_error_count += 1
        finally:
            with self._tasks_lock:
                self._pending_tasks = max(0, self._pending_tasks - 1)

    @staticmethod
    def _is_relevant_packet(detector_name: str, packet) -> bool:
        """Protocol gate for detector callbacks.

        The network monitor observes all packets.  Every attack detector only
        receives the protocol families it can actually analyse.
        """
        try:
            if detector_name == "network_monitor":
                return True
            if detector_name == "arp_spoof":
                return packet.haslayer("ARP")
            if detector_name == "dhcp_spoofing":
                return packet.haslayer("DHCP")
            if detector_name == "dns_spoof":
                return packet.haslayer("DNS")
            if detector_name == "icmp_redirect":
                return packet.haslayer("ICMP")
            if detector_name in {"http_injection", "ssl_strip"}:
                return packet.haslayer("TCP") and packet.haslayer("Raw")
            if detector_name == "rogue_access":
                return packet.haslayer("Dot11") or packet.haslayer("ARP") or packet.haslayer("DHCP")
        except Exception:
            return False
        return False

    # ------------------------------------------------------------------
    # Runtime metrics
    # ------------------------------------------------------------------
    @property
    def packet_count(self) -> int:
        with self._counters_lock:
            return self._packet_count

    @property
    def dropped_count(self) -> int:
        with self._counters_lock:
            return self._dropped_count

    @property
    def started_at(self) -> Optional[datetime]:
        return self._started_at

    def packet_rate(self, window_seconds: int = 10) -> float:
        """Return average packets per second over the sliding window."""
        now = time.time()
        with self._counters_lock:
            self._rate_samples.append((now, self._packet_count))
            # Prune samples outside the window.
            cutoff = now - window_seconds
            while self._rate_samples and self._rate_samples[0][0] < cutoff:
                self._rate_samples.popleft()

            if len(self._rate_samples) >= 2:
                t0, c0 = self._rate_samples[0]
                t1, c1 = self._rate_samples[-1]
                dt = t1 - t0
                if dt > 0:
                    return (c1 - c0) / dt
            return 0.0

    def status_dict(self) -> dict:
        """Snapshot of dispatcher runtime state (for /api/status)."""
        with self._tasks_lock:
            pending = self._pending_tasks
        with self._counters_lock:
            detector_errors = self._detector_error_count
        return {
            "interface": self.interface,
            "running": self.is_running,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "packet_count": self.packet_count,
            "packets_per_second": round(self.packet_rate(), 2),
            "dropped_packets": self.dropped_count,
            "detector_errors": detector_errors,
            "pending_tasks": pending,
            "detector_count": self.detector_count,
            "registered_detectors": self.registered_names(),
            "bpf_filter": self._using_filter,
            "capture_error": self._capture_error,
            "worker_threads": _MAX_WORKER_THREADS,
            "queue_depth": pending,  # worker-pool backlog
        }
