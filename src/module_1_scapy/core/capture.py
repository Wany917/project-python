"""
Module de capture de paquets réseau avec Scapy.
"""

import logging
from typing import List, Callable, Optional

from scapy.sendrecv import sniff
from scapy.packet import Packet

logger = logging.getLogger(__name__)


class PacketCapture:
    """Classe permettant de capturer des paquets réseau avec Scapy."""

    def __init__(self, interface: str):
        """
        Initialise le capteur de paquets.

        Args:
            interface: Nom de l'interface réseau à surveiller
        """
        self.interface = interface
        self.packets = []
        logger.info(f"Initialisation de la capture sur l'interface {interface}")

    def start_capture(
        self, count: int = 0, timeout: int = None, filter_str: str = None, callback: Callable = None
    ) -> List[Packet]:
        """
        Démarre la capture de paquets.

        Args:
            count: Nombre de paquets à capturer (0 = illimité)
            timeout: Durée maximale de capture en secondes
            filter_str: Filtre BPF (Berkeley Packet Filter)
            callback: Fonction à appeler pour chaque paquet

        Returns:
            Liste des paquets capturés
        """
        logger.info(
            f"Démarrage de la capture (count={count}, timeout={timeout}, filter='{filter_str}')"
        )

        def packet_handler(packet: Packet) -> None:
            """Gère chaque paquet capturé."""
            self.packets.append(packet)
            if callback:
                callback(packet)

        try:
            self.packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout,
                filter=filter_str,
                prn=packet_handler,
                store=True,
            )
            logger.info(f"Capture terminée: {len(self.packets)} paquets capturés")
            return self.packets
        except Exception as e:
            logger.error(f"Erreur lors de la capture: {e}")
            raise

    def get_packets(self) -> List[Packet]:
        """
        Retourne les paquets capturés.

        Returns:
            Liste des paquets capturés
        """
        return self.packets


def capture_live_traffic(
    interface: str,
    count: int = 0,
    timeout: Optional[int] = None,
    filter_str: Optional[str] = None,
) -> List[Packet]:
    """
    Fonction utilitaire pour capturer rapidement du trafic réseau.

    Args:
        interface: Interface réseau à surveiller
        count: Nombre de paquets à capturer (0 = illimité)
        timeout: Durée maximale de capture en secondes
        filter_str: Filtre BPF (Berkeley Packet Filter)

    Returns:
        Liste des paquets capturés
    """
    capture = PacketCapture(interface)
    return capture.start_capture(count=count, timeout=timeout, filter_str=filter_str) 