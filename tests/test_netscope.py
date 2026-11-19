import unittest

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether

from netscope.capture import PacketFilter, parse_packet
from netscope.resolver import clean_target
from netscope.utils import format_flags


class ParseTests(unittest.TestCase):
    def test_tcp_syn(self):
        r = parse_packet(Ether() / IP(src="10.0.0.2", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="S"))
        self.assertEqual((r.proto, r.flags, r.service, r.svc_port), ("TCP", "SYN", "HTTPS", 443))

    def test_syn_ack(self):
        r = parse_packet(Ether() / IP() / TCP(sport=443, dport=51000, flags="SA"))
        self.assertEqual(r.flags, "SYN+ACK")

    def test_quic(self):
        r = parse_packet(Ether() / IP() / UDP(sport=60000, dport=443))
        self.assertEqual(r.service, "QUIC")

    def test_dns_query_and_answer(self):
        q = parse_packet(Ether() / IP() / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
        self.assertEqual(q.dns_name, "example.com")
        self.assertIn("Query A example.com", q.info)
        a = parse_packet(Ether() / IP() / UDP(sport=53, dport=5000) /
                         DNS(qr=1, qd=DNSQR(qname="example.com"),
                             an=DNSRR(rrname="example.com", type="A", rdata="1.2.3.4")))
        self.assertIn("1.2.3.4", a.info)

    def test_icmp(self):
        r = parse_packet(Ether() / IP() / ICMP(type=8))
        self.assertEqual((r.proto, r.info), ("ICMP", "Echo request"))


class FilterTests(unittest.TestCase):
    def test_bpf(self):
        f = PacketFilter(ips=frozenset({"1.2.3.4"}), domain="example.com", ports=(443,), proto="tcp")
        self.assertEqual(f.bpf(), "(host 1.2.3.4 or port 53) and tcp and (port 443)")

    def test_empty_filter(self):
        self.assertEqual(PacketFilter().describe(), "all traffic")

    def test_matches_target_ip_and_domain_dns(self):
        f = PacketFilter(ips=frozenset({"1.2.3.4"}), domain="example.com")
        hit = parse_packet(Ether() / IP(src="10.0.0.2", dst="1.2.3.4") / TCP(dport=443))
        miss = parse_packet(Ether() / IP(src="10.0.0.2", dst="9.9.9.9") / TCP(dport=443))
        dns_hit = parse_packet(Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="www.example.com")))
        dns_miss = parse_packet(Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="other.org")))
        self.assertTrue(f.matches(hit))
        self.assertFalse(f.matches(miss))
        self.assertTrue(f.matches(dns_hit))
        self.assertFalse(f.matches(dns_miss))


class HelperTests(unittest.TestCase):
    def test_clean_target(self):
        self.assertEqual(clean_target("https://Example.com:8080/a/b"), "example.com")
        self.assertEqual(clean_target(" example.com "), "example.com")
        self.assertEqual(clean_target("8.8.8.8"), "8.8.8.8")

    def test_flags(self):
        self.assertEqual(format_flags(0x18), "PSH+ACK")
        self.assertEqual(format_flags(0), "NONE")


if __name__ == "__main__":
    unittest.main()
