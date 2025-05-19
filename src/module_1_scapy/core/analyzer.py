"""
Module d'analyse des protocoles réseau.
"""

import logging
from collections import Counter
from typing import Dict, List, Tuple

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """Classe d'analyse des protocoles réseau."""

    def __init__(self, packets: List[Packet] = None):
        """
        Initialise l'analyseur de protocoles.

        Args:
            packets: Liste optionnelle de paquets à analyser
        """
        self.packets = packets or []
        self.protocol_stats = {}
        logger.info("Analyseur de protocoles initialisé")

    def set_packets(self, packets: List[Packet]) -> None:
        """
        Définit les paquets à analyser.

        Args:
            packets: Liste de paquets
        """
        self.packets = packets
        logger.debug(f"Défini {len(packets)} paquets pour analyse")

    def get_protocol_stats(self) -> Dict[str, int]:
        """
        Analyse et compte les protocoles dans les paquets capturés.

        Returns:
            Dictionnaire des protocoles et leur nombre d'occurrences
        """
        if not self.packets:
            logger.warning("Aucun paquet à analyser")
            return {}

        counter = Counter()
        for packet in self.packets:
            protocols = self._identify_protocols(packet)
            for protocol in protocols:
                counter[protocol] += 1

        self.protocol_stats = dict(counter)
        logger.info(f"Statistiques de protocoles: {self.protocol_stats}")
        return self.protocol_stats

    def _identify_protocols(self, packet: Packet) -> List[str]:
        """
        Identifie les protocoles présents dans un paquet.

        Args:
            packet: Paquet à analyser

        Returns:
            Liste des protocoles identifiés dans le paquet
        """
        protocols = []

        if packet.haslayer(Ether):
            protocols.append("Ethernet")

        if packet.haslayer(IP):
            protocols.append("IP")

        if packet.haslayer(TCP):
            protocols.append("TCP")
            # Identification de protocoles de couche applicative basés sur les ports
            tcp_layer = packet[TCP]
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                protocols.append("HTTP")
            elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                protocols.append("HTTPS")
            elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                protocols.append("SSH")
            elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                protocols.append("FTP")

        if packet.haslayer(UDP):
            protocols.append("UDP")
            # Identification de protocoles basés sur UDP
            udp_layer = packet[UDP]
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                protocols.append("DNS")
            elif udp_layer.dport == 67 or udp_layer.sport == 67 or udp_layer.dport == 68 or udp_layer.sport == 68:
                protocols.append("DHCP")

        if packet.haslayer(ICMP):
            protocols.append("ICMP")

        if packet.haslayer(ARP):
            protocols.append("ARP")

        return protocols

    def analyze_ip_communication(self) -> Dict[Tuple[str, str], int]:
        """
        Analyse les communications IP source/destination.

        Returns:
            Dictionnaire des paires IP source/destination et leur nombre d'occurrences
        """
        counter = Counter()
        for packet in self.packets:
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                counter[(ip_src, ip_dst)] += 1

        return dict(counter)

    def get_unique_ip_addresses(self) -> Dict[str, Dict[str, int]]:
        """
        Obtient les adresses IP uniques et leur fréquence.

        Returns:
            Dictionnaire des adresses IP uniques
        """
        src_ips = Counter()
        dst_ips = Counter()

        for packet in self.packets:
            if packet.haslayer(IP):
                src_ips[packet[IP].src] += 1
                dst_ips[packet[IP].dst] += 1

        return {
            "source": dict(src_ips),
            "destination": dict(dst_ips)
        }


def analyze_packet_protocols(packets: List[Packet]) -> Dict[str, int]:
    """
    Fonction utilitaire pour analyser rapidement les protocoles des paquets.

    Args:
        packets: Liste de paquets à analyser

    Returns:
        Dictionnaire des protocoles et leur nombre d'occurrences
    """
    analyzer = ProtocolAnalyzer(packets)
    return analyzer.get_protocol_stats() 