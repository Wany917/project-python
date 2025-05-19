"""
Module de gestion du pare-feu pour le blocage d'adresses IP malveillantes.
"""

import logging
import subprocess
from typing import List, Optional

from module_1_scapy.utils.tools import is_valid_ip

logger = logging.getLogger(__name__)


def block_ip(ip_address: str, action: str = "add") -> bool:
    """
    Bloque ou débloque une adresse IP à l'aide des règles du pare-feu.
    Note: cette fonction nécessite des privilèges administrateur/root.

    Args:
        ip_address: Adresse IP à bloquer
        action: "add" pour bloquer, "remove" pour débloquer

    Returns:
        True si l'opération a réussi, False sinon
    """
    if not ip_address or not is_valid_ip(ip_address):
        logger.error(f"Adresse IP non valide: {ip_address}")
        return False

    try:
        # Détection du système d'exploitation
        import platform
        system = platform.system().lower()

        if system == "linux":
            # Utilisation d'iptables sur Linux
            cmd = [
                "iptables",
                "-A" if action == "add" else "-D",
                "INPUT",
                "-s",
                ip_address,
                "-j",
                "DROP"
            ]
        elif system == "darwin":  # macOS
            # Utilisation de pfctl sur macOS
            # Cette implémentation est simplifiée et peut nécessiter des ajustements
            cmd = [
                "pfctl",
                "-t",
                "blocklist",
                "-T",
                "add" if action == "add" else "delete",
                ip_address
            ]
        elif system == "windows":
            # Utilisation de netsh sur Windows
            rule_name = f"BLOCK-{ip_address}"
            if action == "add":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip_address}"
                ]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
        else:
            logger.error(f"Système d'exploitation non supporté: {system}")
            return False

        # Exécution de la commande
        logger.info(f"Exécution de la commande: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        logger.info(f"IP {ip_address} {'bloquée' if action == 'add' else 'débloquée'} avec succès")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors du blocage de l'IP {ip_address}: {e}")
        return False
    except Exception as e:
        logger.error(f"Exception lors du blocage de l'IP {ip_address}: {e}")
        return False


def block_multiple_ips(ip_addresses: List[str]) -> List[str]:
    """
    Bloque plusieurs adresses IP.

    Args:
        ip_addresses: Liste d'adresses IP à bloquer

    Returns:
        Liste des adresses IP qui ont été bloquées avec succès
    """
    blocked_ips = []
    for ip in ip_addresses:
        if block_ip(ip):
            blocked_ips.append(ip)
    
    logger.info(f"{len(blocked_ips)} adresses IP bloquées sur {len(ip_addresses)} fournies")
    return blocked_ips


def unblock_ip(ip_address: str) -> bool:
    """
    Débloque une adresse IP précédemment bloquée.

    Args:
        ip_address: Adresse IP à débloquer

    Returns:
        True si l'opération a réussi, False sinon
    """
    return block_ip(ip_address, action="remove") 