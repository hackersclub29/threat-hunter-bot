"""
packet_listener.py — Async Scapy packet sniffer.
Extracts external IPs and DNS queries → pushes to asyncio.Queue.
Requires root / CAP_NET_RAW.
"""
import asyncio
import ipaddress
import logging

logger = logging.getLogger(__name__)

# ── Private range set for fast O(1) exclusion ─────────────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(n) for n in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",    # CGNAT
        "0.0.0.0/8",
        "224.0.0.0/4",      # Multicast
        "240.0.0.0/4",      # Reserved
        "255.255.255.255/32",
    ]
]


def _is_routable(ip_str: str) -> bool:
    """Returns True only for globally routable unicast IPs."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


class PacketListener:
    """
    Wraps Scapy's AsyncSniffer. Pushes dicts to queue:
        {"type": "ip",     "ip": "x.x.x.x"}
        {"type": "domain", "domain": "example.com"}
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        interface=None,
        bpf_filter: str = "ip",
    ):
        self.queue     = queue
        self.loop      = loop
        self.interface = interface
        self.bpf       = bpf_filter
        self._sniffer  = None
        self._seen_ips: set     = set()
        self._seen_domains: set = set()
        self.pkt_count: int     = 0

    # ── Scapy callback (runs in sniffer thread) ───────────────────────────────

    def _handle(self, pkt) -> None:
        self.pkt_count += 1
        try:
            from scapy.layers.inet import IP
            from scapy.layers.dns  import DNS, DNSQR

            # ── IP extraction ─────────────────────────────────────────────────
            if IP in pkt:
                for candidate in (pkt[IP].src, pkt[IP].dst):
                    if _is_routable(candidate) and candidate not in self._seen_ips:
                        self._seen_ips.add(candidate)
                        self._enqueue({"type": "ip", "ip": candidate})

            # ── DNS query extraction ──────────────────────────────────────────
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                raw = pkt[DNSQR].qname
                domain = (
                    raw.decode("utf-8", errors="ignore").rstrip(".")
                    if isinstance(raw, bytes)
                    else str(raw).rstrip(".")
                )
                if domain and domain not in self._seen_domains and "." in domain:
                    self._seen_domains.add(domain)
                    self._enqueue({"type": "domain", "domain": domain})

        except Exception as e:
            logger.debug(f"Packet parse error: {e}")

    def _enqueue(self, item: dict) -> None:
        """Thread-safe queue push back to the asyncio event loop."""
        asyncio.run_coroutine_threadsafe(self.queue.put(item), self.loop)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            raise RuntimeError("scapy not installed: pip install scapy")

        iface_label = self.interface or "auto"
        logger.info(f"Starting packet capture  iface={iface_label}  filter='{self.bpf}'")

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf,
            prn=self._handle,
            store=False,
        )
        self._sniffer.start()
        logger.info("Packet sniffer running — pipeline will process external IPs & DNS")

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        logger.info(f"Sniffer stopped. Total packets handled: {self.pkt_count}")
