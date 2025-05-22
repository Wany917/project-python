"""
Tests pour le module analyzer.
"""

import unittest
from unittest.mock import MagicMock, patch

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet

from module_1_scapy.core.analyzer import ProtocolAnalyzer, analyze_packet_protocols


class TestProtocolAnalyzer(unittest.TestCase):
    """Tests pour la classe ProtocolAnalyzer."""

    def setUp(self):
        """Initialisation avant chaque test."""
        self.analyzer = ProtocolAnalyzer()
        
        self.tcp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        self.udp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=1234, dport=53)
        self.icmp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        self.arp_packet = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.2")

    def test_identify_protocols_tcp(self):
        """Test de l'identification des protocoles pour un paquet TCP."""
        # Given
        packet = self.tcp_packet
        
        # When
        protocols = self.analyzer._identify_protocols(packet)
        
        # Then
        self.assertIn("Ethernet", protocols)
        self.assertIn("IP", protocols)
        self.assertIn("TCP", protocols)
        self.assertIn("HTTP", protocols)  # 80

    def test_identify_protocols_udp(self):
        """Test de l'identification des protocoles pour un paquet UDP."""
        # Given
        packet = self.udp_packet
        
        # When
        protocols = self.analyzer._identify_protocols(packet)
        
        # Then
        self.assertIn("Ethernet", protocols)
        self.assertIn("IP", protocols)
        self.assertIn("UDP", protocols)
        self.assertIn("DNS", protocols)  # Car le port de destination est 53

    def test_get_protocol_stats(self):
        """Test de l'obtention des statistiques de protocoles."""
        # Given
        self.analyzer.packets = [self.tcp_packet, self.udp_packet, self.icmp_packet, self.arp_packet]
        
        # When
        stats = self.analyzer.get_protocol_stats()
        
        # Then
        self.assertEqual(stats["Ethernet"], 4)
        self.assertEqual(stats["IP"], 3)  # TCP, UDP, ICMP
        self.assertEqual(stats["TCP"], 1)
        self.assertEqual(stats["UDP"], 1)
        self.assertEqual(stats["ICMP"], 1)
        self.assertEqual(stats["ARP"], 1)
        self.assertEqual(stats["HTTP"], 1)
        self.assertEqual(stats["DNS"], 1)

    def test_analyze_ip_communication(self):
        """Test de l'analyse des communications IP."""
        # Given
        self.analyzer.packets = [self.tcp_packet, self.udp_packet, self.icmp_packet]
        
        # When
        comm_stats = self.analyzer.analyze_ip_communication()
        
        # Then
        self.assertEqual(comm_stats[("192.168.1.1", "192.168.1.2")], 3)

    def test_analyze_packet_protocols_function(self):
        """Test de la fonction utilitaire analyze_packet_protocols."""
        # Given
        packets = [self.tcp_packet, self.udp_packet]
        
        # When
        stats = analyze_packet_protocols(packets)
        
        # Then
        self.assertEqual(stats["Ethernet"], 2)
        self.assertEqual(stats["IP"], 2)
        self.assertEqual(stats["TCP"], 1)
        self.assertEqual(stats["UDP"], 1)
        self.assertEqual(stats["HTTP"], 1)
        self.assertEqual(stats["DNS"], 1)


if __name__ == "__main__":
    unittest.main() 