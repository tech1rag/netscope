# netscope

A passive network traffic viewer for the terminal. Give it a domain or an IP address and it shows
live packets, protocols, ports, TCP flags, DNS details and where the IP addresses are located,
with colourful, readable output.

It is **look, don't touch**: netscope only listens to traffic. It never scans or probes the target.
Think of it as a read-only cousin of nmap and Wireshark, built for learning.

## Features

- Live packet capture with timestamps, source and destination IP + port
- Protocol and service detection (TCP, UDP, ICMP, ARP, DNS, HTTPS, QUIC, SSH ...)
- TCP flags in colour (SYN, ACK, FIN, RST ...) with plain-English meanings in the summary
- DNS details: A, AAAA, CNAME, NS, MX, TXT records with TTLs, reverse DNS, and DNS queries seen on the wire
- IP geolocation (city, country, network owner)
- Summary at the end: protocol share, top ports/services, TCP flags, top remote addresses
- Save captures to `.pcap` (open in Wireshark) or replay one with `-r`

## Install for Linux:
On Windows, see the [Windows](#windows) section below.
```bash
git clone https://github.com/<your-username>/netscope.git
cd netscope
python3 -m venv .venv
source .venv/bin/activate          
pip install -e .
```

## Quick start

On Windows, see the [Windows](#windows) section below.
Try it without any admin rights using the bundled demo capture:
```bash
netscope -r examples/sample.pcap --no-geo
netscope example.com --info-only
```

Live capture needs admin rights because the operating system protects raw network access:

```bash
# Linux / macOS (keep the venv: use the full path to the command)
sudo .venv/bin/netscope example.com

# Windows: open the terminal as Administrator, then
netscope example.com
```

While it runs, open the site in your browser (or `ping` it) from another window to generate traffic.
Press **Ctrl+C** to stop and see the summary.


## Windows:

netscope should also work on Windows. These steps have not been tested on Windows yet, so please
[open an issue](../../issues) if something goes wrong.

**1. Install once**

- [Python 3.9+](https://www.python.org/downloads/) (tick **Add python.exe to PATH**)
- [Git](https://git-scm.com/downloads)
- [Npcap](https://npcap.com) (tick **Install Npcap in WinPcap API-compatible Mode**). This lets Python capture packets.
- Windows Terminal is recommended, because the old `cmd.exe` window can draw tables badly.

**2. Clone and install (PowerShell)**

```powershell
git clone https://github.com/tech1rag/netscope.git
cd netscope
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

If activation says "running scripts is disabled", run this once and try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

In `cmd.exe`, activate with `.venv\Scripts\activate.bat` instead.

**3. Try it (no admin rights needed)**

```powershell
netscope --version
netscope -r examples\sample.pcap --no-geo
netscope example.com --info-only
```

**4. Live capture (needs an Administrator terminal)**

Windows has no `sudo`. Right-click Windows Terminal or PowerShell, choose **Run as administrator**, then:

```powershell
cd path\to\netscope
.venv\Scripts\Activate.ps1
netscope --list-interfaces
netscope example.com -t 30
```

While it runs, generate traffic from a second, normal PowerShell window:

```powershell
curl.exe -sI https://example.com
```

If the table stays empty, choose your connection from `--list-interfaces` and pass it with `-i`, for example `netscope example.com -i "Wi-Fi"`.

**Troubleshooting**

- *"libpcap provider" warning:* Npcap is missing or was not installed in WinPcap-compatible mode. Reinstall it with that option ticked.
- *Nothing is captured:* make sure the terminal is running as Administrator and you picked the right interface.



## Usage

```
netscope [target] [options]
```

Put the target first, then the options.

| Option | What it does |
|---|---|
| `target` | Domain or IP to focus on. Leave out to watch all traffic |
| `-i`, `--interface NAME` | Interface to listen on (see `--list-interfaces`) |
| `-p`, `--port 80 443` | Only show these ports |
| `--proto tcp\|udp\|icmp\|dns\|arp` | Only show one protocol |
| `-c`, `--count N` | Stop after N matching packets |
| `-t`, `--time SECONDS` | Stop after this many seconds |
| `--no-geo` | Skip location lookups |
| `-w`, `--write FILE.pcap` | Save packets to a file |
| `--info-only` | Show DNS + location for the target and exit (no admin rights) |
| `-r`, `--read FILE.pcap` | Analyse a saved capture instead of listening live |
| `--list-interfaces` | Show interface names and exit |

### Examples

```bash
sudo .venv/bin/netscope example.com                 # live view of a domain
sudo .venv/bin/netscope 8.8.8.8 -t 30               # one IP for 30 seconds
sudo .venv/bin/netscope example.com -p 443          # HTTPS traffic only
sudo .venv/bin/netscope --proto dns -c 20           # 20 DNS packets from anywhere
sudo .venv/bin/netscope example.com -w capture.pcap # save for Wireshark
```

## How it works

1. **Resolve:** the target is resolved with DNS (`dnspython`) to get its IP addresses and records.
2. **Capture:** `scapy` listens on the network interface with a BPF filter built from those IPs.
3. **Decode:** each packet is peeled layer by layer (Ethernet, IP, TCP/UDP/ICMP, DNS) into a simple record.
4. **Enrich:** ports are mapped to services, and IPs are looked up for location in background threads.
5. **Display:** `rich` draws the live table and the final summary.

```
netscope/
  cli.py        command-line flags and main flow
  capture.py    packet parsing, filters, capture thread
  resolver.py   DNS lookups for the target
  geo.py        cached, non-blocking IP geolocation
  stats.py      counters for the summary
  display.py    all terminal output
tests/          unit tests (python -m unittest discover -s tests)
examples/       sample.pcap and the script that generated it
```

## Privacy and responsible use

- Only capture traffic on networks you own or have permission to monitor.
- Location lookups send the IP addresses you view to [ipwho.is](https://ipwho.is). Use `--no-geo` to avoid that.
- DNS lookups for the target go to your normal DNS resolver.
- Locations are approximate (often the provider's hub, not the physical machine).
- HTTPS content is encrypted. netscope shows who talks to whom, on which ports, and when, never the page content.

## Limitations

- A domain behind a CDN can resolve to different IPs over time, so browser traffic may use an address that
  differs from the one netscope resolved. Use `--info-only` to see the current answers, or watch without a target.
- Only IPv4/IPv6, ARP and ICMP are decoded.

## License

MIT, see [LICENSE](LICENSE).
