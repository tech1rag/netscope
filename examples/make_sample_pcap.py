"""Creates examples/sample.pcap: a small, made-up capture for demos (no network needed).

Run:  python examples/make_sample_pcap.py
"""
import os

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, wrpcap

ME, DNS_SRV, SITE, QUIC_SRV, PING = "192.168.1.23", "8.8.8.8", "93.184.216.34", "142.250.77.14", "1.1.1.1"
t0 = 1_760_000_000.0
packets = []


def add(pkt, dt):
    pkt.time = t0 + dt
    packets.append(pkt)


add(Ether() / ARP(op=1, psrc=ME, pdst="192.168.1.1"), 0.00)
add(Ether() / IP(src=ME, dst=DNS_SRV) / UDP(sport=53011, dport=53) / DNS(id=7, rd=1, qd=DNSQR(qname="example.com")), 0.20)
add(Ether() / IP(src=DNS_SRV, dst=ME) / UDP(sport=53, dport=53011) /
    DNS(id=7, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", type="A", ttl=300, rdata=SITE)), 0.24)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="S", seq=100), 0.30)
add(Ether() / IP(src=SITE, dst=ME) / TCP(sport=443, dport=51234, flags="SA", seq=500, ack=101), 0.35)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="A", seq=101, ack=501), 0.35)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="PA", seq=101, ack=501) / (b"x" * 280), 0.40)
add(Ether() / IP(src=SITE, dst=ME) / TCP(sport=443, dport=51234, flags="PA", seq=501, ack=381) / (b"y" * 1200), 0.52)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="A", seq=381, ack=1701), 0.52)
add(Ether() / IP(src=ME, dst=QUIC_SRV) / UDP(sport=60100, dport=443) / (b"q" * 900), 0.70)
add(Ether() / IP(src=QUIC_SRV, dst=ME) / UDP(sport=443, dport=60100) / (b"q" * 1100), 0.78)
add(Ether() / IP(src=ME, dst=PING) / ICMP(type=8), 1.00)
add(Ether() / IP(src=PING, dst=ME) / ICMP(type=0), 1.02)
add(Ether() / IP(src=ME, dst="203.0.113.50") / TCP(sport=51300, dport=22, flags="S"), 1.30)
add(Ether() / IP(src="203.0.113.50", dst=ME) / TCP(sport=22, dport=51300, flags="RA"), 1.33)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="FA", seq=381, ack=1701), 1.60)
add(Ether() / IP(src=SITE, dst=ME) / TCP(sport=443, dport=51234, flags="FA", seq=1701, ack=382), 1.64)
add(Ether() / IP(src=ME, dst=SITE) / TCP(sport=51234, dport=443, flags="A", seq=382, ack=1702), 1.64)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")
wrpcap(out, packets)
print(f"wrote {len(packets)} packets to {out}")
