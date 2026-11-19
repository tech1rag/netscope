"""All terminal output lives here (built with the `rich` library)."""
from __future__ import annotations

import time
from datetime import datetime

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .capture import PacketRecord
from .geo import GeoLocator
from .resolver import TargetInfo
from .stats import Stats
from .utils import fmt_duration, human_bytes, remote_ip

PROTO_STYLE = {"TCP": "cyan", "UDP": "magenta", "ICMP": "yellow", "ICMPv6": "yellow", "ARP": "blue"}
FLAG_STYLE = {"SYN": "bold green", "FIN": "yellow", "RST": "bold red", "PSH": "cyan", "URG": "magenta"}
FLAG_MEANING = {
    "SYN": "connection request",
    "SYN+ACK": "request accepted",
    "ACK": "acknowledgement",
    "PSH+ACK": "data being sent",
    "FIN+ACK": "closing the connection",
    "FIN+PSH+ACK": "last data + closing",
    "RST": "connection aborted",
    "RST+ACK": "connection refused / reset",
}


def endpoint(ip: str, port) -> str:
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def flags_text(flags: str) -> Text:
    text = Text()
    for i, name in enumerate(flags.split("+") if flags else []):
        if i:
            text.append("+", style="dim")
        text.append(name, style=FLAG_STYLE.get(name, "white"))
    return text


def bar(share: float, width: int = 18) -> Text:
    return Text("█" * max(1, round(share * width)), style="cyan")


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def banner(console: Console) -> None:
    console.print(Panel(
        Text.from_markup(
            "[bold cyan]netscope[/]  passive network traffic viewer\n"
            "[dim]It only listens to traffic. It never scans or probes the target.[/]"),
        border_style="cyan", box=box.ROUNDED))


def show_interfaces(console: Console, interfaces) -> None:
    table = Table(title="Network interfaces (use the Name with -i)", box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("Name", style="bold cyan")
    table.add_column("IP address")
    table.add_column("Description", style="dim")
    for name, ip, desc in interfaces:
        table.add_row(name, ip, desc)
    console.print(table)


def show_target(console: Console, info: TargetInfo, geo: GeoLocator) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row("Target", info.host)
    grid.add_row("Type", "IP address" if info.kind == "ip" else "Domain name")
    grid.add_row("IP addresses", ", ".join(info.ips) or "none found")
    for ip, name in info.reverse.items():
        grid.add_row("Reverse DNS", f"{ip}  →  {name}")
    console.print(Panel(grid, title="Target", border_style="green"))

    if info.records:
        table = Table(title="DNS records", box=box.SIMPLE_HEAD, title_justify="left")
        table.add_column("Type", style="bold cyan", no_wrap=True)
        table.add_column("Value", overflow="fold")
        table.add_column("TTL", justify="right", style="dim")
        for rtype, value, ttl in info.records:
            table.add_row(rtype, value, "" if ttl is None else f"{ttl}s")
        console.print(table)

    if geo.enabled and info.ips:
        with console.status("[cyan]Looking up locations..."):
            places = [(ip, geo.lookup(ip)) for ip in info.ips[:6]]
        table = Table(title="Location (approximate)", box=box.SIMPLE_HEAD, title_justify="left")
        table.add_column("IP", style="bold")
        table.add_column("Location")
        table.add_column("Network")
        table.add_column("ASN", style="dim")
        for ip, g in places:
            if g is None:
                table.add_row(ip, "[dim]lookup failed[/]", "", "")
            else:
                where = g.label if g.note else ", ".join(p for p in (g.city, g.region, g.country) if p) or "Unknown"
                table.add_row(ip, where, g.org, g.asn)
        console.print(table)

    for err in info.errors:
        console.print(f"[yellow]! {err}[/]")


class LiveView:
    """Re-drawn several times a second while capturing."""

    def __init__(self, console: Console, stats: Stats, geo: GeoLocator, *, subtitle: str, show_geo: bool):
        self.console = console
        self.stats = stats
        self.geo = geo
        self.subtitle = subtitle
        self.show_geo = show_geo
        self.started = time.time()
        self.finished = False

    def _details(self, rec: PacketRecord) -> Text:
        if rec.info:
            return Text(rec.info)
        if not self.show_geo:
            return Text("")
        g = self.geo.get(remote_ip(rec.src, rec.dst))
        if g is None:
            return Text("...", style="dim")
        label = g.label if g.note or not g.org else f"{g.label} · {g.org}"
        return Text(label, style="dim")

    def render(self):
        rows = max(5, self.console.size.height - 8)
        with self.stats.lock:
            recent = list(self.stats.recent)[-rows:]
            packets, nbytes = self.stats.packets, self.stats.bytes

        table = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold", pad_edge=False)
        table.add_column("Time", no_wrap=True, style="dim")
        table.add_column("Proto", no_wrap=True)
        table.add_column("Source", no_wrap=True, overflow="ellipsis")
        table.add_column("Destination", no_wrap=True, overflow="ellipsis")
        table.add_column("Service", no_wrap=True)
        table.add_column("Flags", no_wrap=True)
        table.add_column("Size", justify="right", no_wrap=True)
        table.add_column("Details", no_wrap=True, overflow="ellipsis", ratio=1)
        for rec in recent:
            table.add_row(
                fmt_time(rec.time),
                Text(rec.proto, style=PROTO_STYLE.get(rec.proto, "white")),
                endpoint(rec.src, rec.sport),
                endpoint(rec.dst, rec.dport),
                Text(rec.service, style="green"),
                flags_text(rec.flags),
                f"{rec.size} B",
                self._details(rec),
            )

        state = "Stopped" if self.finished else "Capturing, press Ctrl+C to stop"
        status = Text(
            f" {state}   |   packets: {packets:,}   data: {human_bytes(nbytes)}   "
            f"elapsed: {fmt_duration(time.time() - self.started)}", style="dim")
        panel = Panel(table, title="[bold]Live traffic[/]", subtitle=f"[dim]{self.subtitle}[/]",
                      border_style="cyan")
        return Group(panel, status)


def _share_table(title: str) -> Table:
    t = Table(title=title, box=box.SIMPLE_HEAD, title_justify="left")
    return t


def show_summary(console: Console, stats: Stats, geo: GeoLocator, show_geo: bool = True) -> None:
    with stats.lock:
        packets, nbytes, duration = stats.packets, stats.bytes, stats.duration
        protocols = stats.protocols.most_common()
        ports = stats.ports.most_common(10)
        flags = stats.flags.most_common(8)
        talkers = sorted(stats.talkers.items(), key=lambda kv: kv[1][0], reverse=True)[:5]
        dns_names = stats.dns_names.most_common(10)

    if packets == 0:
        console.print(Panel(
            "No packets matched. Generate some traffic (open the site, run ping) "
            "or loosen the filters (-p / --proto).", title="Summary", border_style="yellow"))
        return

    overview = Table.grid(padding=(0, 3))
    overview.add_column(style="bold")
    overview.add_column()
    overview.add_row("Packets", f"{packets:,}")
    overview.add_row("Data", human_bytes(nbytes))
    overview.add_row("Time span", fmt_duration(duration))
    if duration > 0:
        overview.add_row("Average rate", f"{packets / duration:.1f} packets/s")
    console.print(Panel(overview, title="Summary", border_style="green"))

    t = _share_table("Protocols")
    t.add_column("Protocol", style="bold")
    t.add_column("Packets", justify="right")
    t.add_column("Share", justify="right")
    t.add_column("")
    for proto, n in protocols:
        t.add_row(Text(proto, style=PROTO_STYLE.get(proto, "white")), f"{n:,}", f"{n / packets:.0%}", bar(n / packets))
    console.print(t)

    if ports:
        t = _share_table("Ports and services")
        t.add_column("Port", style="bold", justify="right")
        t.add_column("Proto")
        t.add_column("Service", style="green")
        t.add_column("Packets", justify="right")
        t.add_column("Share", justify="right")
        t.add_column("")
        for (proto, port, service), n in ports:
            t.add_row(str(port), proto, service or "-", f"{n:,}", f"{n / packets:.0%}", bar(n / packets))
        console.print(t)

    if flags:
        t = _share_table("TCP flags")
        t.add_column("Flags")
        t.add_column("Packets", justify="right")
        t.add_column("Meaning", style="dim")
        for combo, n in flags:
            t.add_row(flags_text(combo), f"{n:,}", FLAG_MEANING.get(combo, ""))
        console.print(t)
        console.print("[dim]A normal connection opens with SYN, then SYN+ACK, then ACK. "
                      "RST means it was refused or aborted.[/]\n")

    locs = {}
    if show_geo and geo.enabled:
        with console.status("[cyan]Looking up locations..."):
            locs = {ip: geo.lookup(ip) for ip, _ in talkers}
    t = _share_table("Top remote addresses")
    t.add_column("IP", style="bold")
    t.add_column("Packets", justify="right")
    t.add_column("Data", justify="right")
    if locs:
        t.add_column("Location")
        t.add_column("Network", style="dim")
    for ip, (n, b) in talkers:
        row = [ip, f"{n:,}", human_bytes(b)]
        if locs:
            g = locs.get(ip)
            row += [g.label if g else "-", (g.org if g else "")]
        t.add_row(*row)
    console.print(t)

    if dns_names:
        t = _share_table("Names seen in DNS traffic")
        t.add_column("Name", style="bold")
        t.add_column("Messages", justify="right")
        for name, n in dns_names:
            t.add_row(name, str(n))
        console.print(t)
