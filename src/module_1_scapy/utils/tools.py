"""
Module d'utilitaires pour l'IDS/IPS.
"""

import logging
import socket
import subprocess
import sys
from typing import List, Optional
import colorlog

logger = logging.getLogger(__name__)


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Configure le système de logging.

    Args:
        log_level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Fichier de log optionnel
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Niveau de log invalide: {log_level}")

    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    color_format = "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    handlers = []

    # Handler pour la console avec couleurs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(colorlog.ColoredFormatter(color_format))
    handlers.append(console_handler)

    # Handler pour le fichier si spécifié (pas de couleur)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    # Configuration
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=handlers
    )
    logger.info(f"Logging configuré (niveau: {log_level})")


def get_network_interfaces() -> List[str]:
    """
    Récupère la liste des interfaces réseau disponibles.

    Returns:
        Liste des noms d'interfaces réseau
    """
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        logger.debug(f"Interfaces réseau détectées: {interfaces}")
        return interfaces
    except ImportError:
        logger.warning("Impossible d'utiliser scapy.arch.get_if_list(), utilisation de socket")
        try:
            # Méthode alternative si get_if_list n'est pas disponible
            import netifaces
            interfaces = netifaces.interfaces()
            logger.debug(f"Interfaces réseau détectées (netifaces): {interfaces}")
            return interfaces
        except ImportError:
            logger.error("Impossible de détecter les interfaces réseau")
            return []


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Récupère l'adresse IP associée à une interface réseau.

    Args:
        interface: Nom de l'interface réseau

    Returns:
        Adresse IP ou None si non trouvée
    """
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
        return None
    except (ImportError, ValueError):
        logger.warning(f"Impossible de récupérer l'IP de l'interface {interface}")
        return None


def is_valid_ip(ip: str) -> bool:
    """
    Vérifie si une chaîne est une adresse IP valide.

    Args:
        ip: Chaîne à vérifier

    Returns:
        True si l'adresse IP est valide, False sinon
    """
    if not ip or not isinstance(ip, str):
        return False
    
    # Vérification du format de l'adresse IP
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    # Vérification que chaque partie est un nombre entre 0 et 255
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, TypeError):
        return False 