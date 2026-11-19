"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import time

from rich.console import Console
from rich.live import Live

from . import __version__
from .capture import CaptureSession, PacketFilter, list_interfaces
from .display import LiveView, banner, show_interfaces, show_summary, show_target
from .geo import GeoLocator
from .resolver import resolve_target
from .stats import Stats
from .utils import has_capture_privileges

EXAMPLES = """\
examples:
  netscope example.com                 watch live traffic to/from a domain
  netscope 8.8.8.8 -t 30               watch one IP address for 30 seconds
  netscope example.com -p 443          only show traffic on port 443
  netscope --proto dns -c 20           capture 20 DNS packets from anywhere
  netscope example.com --info-only     DNS + location details only (no admin rights needed)
  netscope -r examples/sample.pcap     replay a saved capture (no admin rights needed)
  netscope --list-interfaces           show interface names to use with -i

Tip: put the target first, then the options.
Live capture needs admin rights: sudo on Linux/macOS, an Administrator terminal on Windows.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscope",
        description="Passive network traffic viewer: live packets, DNS details, ports, TCP flags and IP locations.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="domain or IP address to focus on (leave out to watch all traffic)")

    g = p.add_argument_group("what to capture")
    g.add_argument("-i", "--interface", metavar="NAME", help="network interface to listen on (default: automatic)")
    g.add_argument("-p", "--port", type=int, nargs="+", metavar="PORT", help="only show these ports, e.g. -p 80 443")
    g.add_argument("--proto", choices=["tcp", "udp", "icmp", "dns", "arp"], help="only show one protocol")

    g = p.add_argument_group("when to stop (default: press Ctrl+C)")
    g.add_argument("-c", "--count", type=int, metavar="N", help="stop after N matching packets")
    g.add_argument("-t", "--time", type=int, metavar="SECONDS", help="stop after this many seconds")

    g = p.add_argument_group("output")
    g.add_argument("--no-geo", action="store_true", help="skip IP location lookups (nothing is sent to ipwho.is)")
    g.add_argument("-w", "--write", metavar="FILE.pcap", help="save captured packets to a file (open it in Wireshark)")
    g.add_argument("--info-only", action="store_true", help="show DNS + location details for the target and exit")

    g = p.add_argument_group("other")
    g.add_argument("-r", "--read", metavar="FILE.pcap", help="analyse a saved capture instead of listening live")
    g.add_argument("--list-interfaces", action="store_true", help="list network interfaces and exit")
    g.add_argument("-V", "--version", action="version", version=f"netscope {__version__}")
    return p


def run_capture(console: Console, args, flt: PacketFilter, stats: Stats, geo: GeoLocator) -> bool:
    session = CaptureSession(
        flt, iface=args.interface, offline=args.read, write=args.write,
        on_record=stats.add, max_packets=args.count or 0,
    )
    where = f"reading {args.read}" if args.read else f"interface: {args.interface or 'auto'}"
    view = LiveView(console, stats, geo, subtitle=f"{where} | filter: {flt.describe()}", show_geo=not args.no_geo)

    started = time.time()
    session.start()
    with Live(get_renderable=view.render, console=console, refresh_per_second=6, vertical_overflow="crop"):
        try:
            while not session.finished:
                if args.time and time.time() - started >= args.time:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        view.finished = True
        session.stop()
    console.print()

    if stats.packets == 0 and not args.read and session.finished:
        console.print(
            "[red]Capture stopped before any packet arrived.[/] Most likely you need admin rights "
            "(sudo on Linux/macOS, an Administrator terminal on Windows), the interface name is wrong "
            "(see --list-interfaces), or Npcap is missing on Windows."
            + (f"\n[dim]{session.error}[/]" if session.error else ""))
        return False
    return True


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    if args.list_interfaces:
        show_interfaces(console, list_interfaces())
        return 0

    banner(console)

    if args.info_only and not args.target:
        console.print("[red]--info-only needs a target, for example:[/] netscope example.com --info-only")
        return 2
    if args.read and not os.path.isfile(args.read):
        console.print(f"[red]File not found:[/] {args.read}")
        return 2

    geo = GeoLocator(enabled=not args.no_geo)
    target = None
    if args.target:
        with console.status("[cyan]Resolving target..."):
            target = resolve_target(args.target)
        show_target(console, target, geo)
        if not target.ips and not args.read:
            return 1
        if args.info_only:
            geo.close()
            return 0
    else:
        console.print("[dim]No target given: showing all traffic on the interface.[/]\n")

    flt = PacketFilter(
        ips=frozenset(target.ips) if target else frozenset(),
        domain=target.host if target and target.kind == "domain" else None,
        ports=tuple(args.port or ()),
        proto=args.proto,
    )

    if not args.read and not has_capture_privileges():
        console.print("[yellow]Not running as admin/root, so live capture may fail.[/]")

    stats = Stats()
    ok = run_capture(console, args, flt, stats, geo)
    if ok:
        show_summary(console, stats, geo, show_geo=not args.no_geo)
        if args.write and stats.packets:
            console.print(f"[green]Saved {stats.packets} packets to {args.write}[/]")
    geo.close()
    return 0 if ok else 1
