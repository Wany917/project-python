"""
Tests pour le module de détection d'attaques.
"""

import unittest
from unittest.mock import MagicMock, patch

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether

from module_1_scapy.core.detection import AttackDetector


class TestAttackDetector(unittest.TestCase):
    """Tests pour la classe AttackDetector."""

    def setUp(self):
        """Initialisation avant chaque test."""
        self.detector = AttackDetector()
        
        # Création de paquets fictifs pour les tests
        self.normal_tcp = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        
        # Paquet avec injection SQL
        sql_payload = b"GET /login.php?username=admin' OR 1=1--&password=test HTTP/1.1"
        self.sql_injection = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80) / Raw(load=sql_payload)
        
        # Paquet ARP pour ARP spoofing
        self.arp_packet = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55", pdst="192.168.1.2", hwdst="aa:bb:cc:dd:ee:ff")
        
        # Paquet TCP SYN pour SYN flood
        self.syn_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S")
        
        # Paquet ICMP pour ICMP flood
        self.icmp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP() / Raw(load=b"X" * 1500)  # Gros paquet ICMP

    def test_detect_sql_injection(self):
        """Test de détection d'injection SQL."""
        # Given
        packet = self.sql_injection
        
        # When
        attack_info = self.detector._check_sql_injection(packet)
        
        # Then
        self.assertIsNotNone(attack_info)
        self.assertEqual(attack_info["type"], "SQL Injection")
        self.assertEqual(attack_info["source_ip"], "192.168.1.1")
        self.assertEqual(attack_info["destination_ip"], "192.168.1.2")

    def test_detect_arp_spoofing(self):
        """Test de détection d'ARP spoofing."""
        # Given
        # Pré-remplissage du cache ARP avec une autre MAC
        self.detector.arp_cache["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"
        packet = self.arp_packet
        
        # When
        attack_info = self.detector._check_arp_spoofing(packet)
        
        # Then
        self.assertIsNotNone(attack_info)
        self.assertEqual(attack_info["type"], "ARP Spoofing")
        self.assertEqual(attack_info["ip_address"], "192.168.1.1")
        self.assertEqual(attack_info["original_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(attack_info["spoofed_mac"], "00:11:22:33:44:55")

    def test_detect_syn_flood(self):
        """Test de détection de SYN flood."""
        # Given
        packet = self.syn_packet
        
        # Simuler plusieurs paquets SYN
        for _ in range(15):
            self.detector._check_syn_flood(packet)
        
        # When
        attack_info = self.detector._check_syn_flood(packet)
        
        # Then
        self.assertIsNotNone(attack_info)
        self.assertEqual(attack_info["type"], "SYN Flood")
        self.assertEqual(attack_info["source_ip"], "192.168.1.1")
        self.assertEqual(attack_info["target_ip"], "192.168.1.2")
        self.assertEqual(attack_info["target_port"], 80)

    def test_detect_icmp_flood(self):
        """Test de détection d'ICMP flood."""
        # Given
        packet = self.icmp_packet
        
        # When
        attack_info = self.detector._check_icmp_flood(packet)
        
        # Then
        self.assertIsNotNone(attack_info)
        self.assertEqual(attack_info["type"], "ICMP Flood")
        self.assertEqual(attack_info["source_ip"], "192.168.1.1")
        self.assertEqual(attack_info["target_ip"], "192.168.1.2")
        self.assertGreater(attack_info["packet_size"], 1000)

    def test_analyze_packet_normal(self):
        """Test d'analyse d'un paquet normal."""
        # Given
        packet = self.normal_tcp
        
        # When
        attack_info = self.detector.analyze_packet(packet)
        
        # Then
        self.assertIsNone(attack_info)


if __name__ == "__main__":
    unittest.main() 