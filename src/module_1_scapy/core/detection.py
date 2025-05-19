"""
Module de détection d'attaques réseau.
"""

import logging
import re
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether

logger = logging.getLogger(__name__)


class AttackDetector:
    """Classe de détection d'attaques réseau."""

    def __init__(self):
        """Initialise le détecteur d'attaques."""
        self.detected_attacks = []
        self.arp_cache = {}  # Pour détecter l'ARP spoofing
        self.syn_flood_counter = defaultdict(int)  # Pour détecter le SYN flood
        self.port_scan_counter = defaultdict(set)  # Pour détecter le scan de ports
        logger.info("Détecteur d'attaques initialisé")

    def analyze_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Analyse un paquet pour détecter des attaques.

        Args:
            packet: Paquet à analyser

        Returns:
            Dictionnaire contenant les informations sur l'attaque détectée ou None
        """
        attack_info = None

        # Vérification SQL Injection
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            attack_info = self._check_sql_injection(packet)
            if attack_info:
                return attack_info

        # Vérification ARP Spoofing
        if packet.haslayer(ARP):
            attack_info = self._check_arp_spoofing(packet)
            if attack_info:
                return attack_info

        # Vérification SYN Flood
        if packet.haslayer(TCP) and packet.haslayer(IP):
            attack_info = self._check_syn_flood(packet)
            if attack_info:
                return attack_info

        # Vérification Port Scanning
        if packet.haslayer(TCP) and packet.haslayer(IP):
            attack_info = self._check_port_scanning(packet)
            if attack_info:
                return attack_info

        # Vérification ICMP Flood (Ping of Death)
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            attack_info = self._check_icmp_flood(packet)
            if attack_info:
                return attack_info

        return None

    def _check_sql_injection(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Vérifie si le paquet contient une tentative d'injection SQL.

        Args:
            packet: Paquet à analyser

        Returns:
            Informations sur l'attaque si détectée, sinon None
        """
        payload = packet[Raw].load.decode('latin-1', errors='ignore')
        sql_patterns = [
            r"['\"].*OR.*1\s*=\s*1",
            r"OR\s+1\s*=\s*1",
            r"--\s",
            r";\s*DROP",
            r"UNION\s+SELECT",
            r"INSERT\s+INTO",
            r"DELETE\s+FROM",
            r";\s*EXEC",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                logger.warning(f"Injection SQL détectée: {pattern}")
                return {
                    "type": "SQL Injection",
                    "source_ip": packet[IP].src,
                    "destination_ip": packet[IP].dst,
                    "pattern_detected": pattern,
                    "packet": packet,
                }
        return None

    def _check_arp_spoofing(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Détecte les tentatives d'ARP spoofing.

        Args:
            packet: Paquet à analyser

        Returns:
            Informations sur l'attaque si détectée, sinon None
        """
        if packet[ARP].op == 2:  # ARP Reply
            ip_addr = packet[ARP].psrc
            mac_addr = packet[ARP].hwsrc

            # Si l'IP est déjà dans le cache mais avec une adresse MAC différente
            if ip_addr in self.arp_cache and self.arp_cache[ip_addr] != mac_addr:
                logger.warning(
                    f"Possible ARP Spoofing détecté: {ip_addr} a changé de MAC de "
                    f"{self.arp_cache[ip_addr]} à {mac_addr}"
                )
                return {
                    "type": "ARP Spoofing",
                    "ip_address": ip_addr,
                    "original_mac": self.arp_cache[ip_addr],
                    "spoofed_mac": mac_addr,
                    "packet": packet,
                }
            else:
                self.arp_cache[ip_addr] = mac_addr
        return None

    def _check_syn_flood(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Détecte les attaques SYN flood.

        Args:
            packet: Paquet à analyser

        Returns:
            Informations sur l'attaque si détectée, sinon None
        """
        if packet[TCP].flags == 'S':  # SYN flag
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            key = f"{dst_ip}:{dst_port}"
            self.syn_flood_counter[key] += 1

            # Seuil arbitraire pour la détection de SYN flood
            if self.syn_flood_counter[key] > 10:
                logger.warning(f"Possible SYN Flood détecté vers {key}")
                return {
                    "type": "SYN Flood",
                    "source_ip": packet[IP].src,
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "syn_count": self.syn_flood_counter[key],
                    "packet": packet,
                }
        return None

    def _check_port_scanning(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Détecte les scans de ports.

        Args:
            packet: Paquet à analyser

        Returns:
            Informations sur l'attaque si détectée, sinon None
        """
        if packet[TCP].flags in ['S', 'FPU', 'UAPRSF', '']:  # Différents types de scan
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            key = f"{src_ip}->{dst_ip}"
            self.port_scan_counter[key].add(dst_port)

            # Seuil arbitraire pour la détection de scan de ports
            if len(self.port_scan_counter[key]) > 5:
                logger.warning(f"Possible scan de ports détecté de {src_ip} vers {dst_ip}")
                return {
                    "type": "Port Scanning",
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "ports_scanned": list(self.port_scan_counter[key]),
                    "scan_count": len(self.port_scan_counter[key]),
                    "packet": packet,
                }
        return None

    def _check_icmp_flood(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Détecte les attaques ICMP flood (Ping of Death).

        Args:
            packet: Paquet à analyser

        Returns:
            Informations sur l'attaque si détectée, sinon None
        """
        # Cette implémentation est simpliste et nécessiterait plus de contexte pour être précise
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Si le paquet est trop grand, cela peut être un indicateur de Ping of Death
        if len(packet) > 1000:
            logger.warning(f"Possible ICMP flood détecté de {ip_src} vers {ip_dst}")
            return {
                "type": "ICMP Flood",
                "source_ip": ip_src,
                "target_ip": ip_dst,
                "packet_size": len(packet),
                "packet": packet,
            }
        return None

    def get_detected_attacks(self) -> List[Dict[str, Any]]:
        """
        Retourne la liste des attaques détectées.

        Returns:
            Liste des attaques détectées
        """
        return self.detected_attacks 