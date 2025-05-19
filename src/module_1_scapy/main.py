"""
Point d'entrée principal de l'IDS/IPS.
"""

import argparse
import logging
import os
import sys
import time
from typing import Dict, List, Any

from scapy.packet import Packet

from module_1_scapy.core.capture import PacketCapture
from module_1_scapy.core.analyzer import ProtocolAnalyzer
from module_1_scapy.core.detection import AttackDetector
from module_1_scapy.reporting.reporter import NetworkReporter
from module_1_scapy.utils.tools import setup_logging, get_network_interfaces
from module_1_scapy.utils.firewall import block_ip

logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parse les arguments de ligne de commande.

    Returns:
        Espace de noms contenant les arguments analysés
    """
    interfaces = get_network_interfaces()
    default_interface = interfaces[0] if interfaces else None

    parser = argparse.ArgumentParser(
        description="IDS/IPS avec Scapy - Détection et prévention d'intrusion réseau"
    )
    parser.add_argument(
        "-i", "--interface",
        default=default_interface,
        help=f"Interface réseau à analyser (défaut: {default_interface})"
    )
    parser.add_argument(
        "-o", "--output",
        default="report.pdf",
        help="Chemin du fichier de rapport à générer (défaut: report.pdf)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=60,
        help="Durée de la capture en secondes (défaut: 60)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Nombre de paquets à capturer (défaut: 0 = illimité)"
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="Filtre BPF pour la capture (défaut: aucun)"
    )
    parser.add_argument(
        "-l", "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Niveau de log (défaut: INFO)"
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Fichier de log (défaut: aucun, logs en console uniquement)"
    )
    parser.add_argument(
        "-b", "--block",
        action="store_true",
        help="Activer le blocage automatique des attaquants détectés"
    )
    pxser.add_argument(
        "--output-dir",
        default="reports",
        help="Répertoire de sortie pour les rapports et graphiques (défaut: reports)"
    )

    args = parser.parse_args()

    # Vérification des arguments
    if not args.interface:
        parser.error("Aucune interface réseau trouvée ou spécifiée")

    return args


class IdsIpsApplication:
    """Classe principale de l'application IDS/IPS."""

    def __init__(self, args: argparse.Namespace):
        """
        Initialise l'application.

        Args:
            args: Arguments de ligne de commande
        """
        self.args = args
        self.packets: List[Packet] = []
        self.protocol_stats: Dict[str, int] = {}
        self.detected_attacks: List[Dict[str, Any]] = []
        self.start_time = 0
        self.end_time = 0
        
        # Initialisation des composants
        self.capture = PacketCapture(args.interface)
        self.analyzer = ProtocolAnalyzer()
        self.detector = AttackDetector()
        self.reporter = NetworkReporter(args.output_dir)
        
        logger.info(f"Application IDS/IPS initialisée sur l'interface {args.interface}")

    def run(self) -> int:
        """
        Exécute l'application.

        Returns:
            Code de sortie (0 = succès, != 0 = erreur)
        """
        try:
            logger.info("Démarrage de l'application IDS/IPS")
            
            # Capture des paquets
            self._capture_packets()
            
            # Analyse des protocoles
            self._analyze_protocols()
            
            # Détection des attaques
            self._detect_attacks()
            
            # Génération du rapport
            self._generate_report()
            
            logger.info("Exécution terminée avec succès")
            return 0
        except KeyboardInterrupt:
            logger.info("Interruption utilisateur, arrêt de l'application")
            return 130
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution: {e}", exc_info=True)
            return 1

    def _capture_packets(self) -> None:
        """Capture les paquets réseau."""
        logger.info(
            f"Démarrage de la capture sur {self.args.interface} "
            f"(timeout={self.args.timeout}s, filter='{self.args.filter}')"
        )
        
        print(f"Capture en cours sur {self.args.interface}... Appuyez sur Ctrl+C pour arrêter.")
        
        self.start_time = time.time()
        
        def packet_callback(packet: Packet) -> None:
            """Callback appelé pour chaque paquet."""
            attack_info = self.detector.analyze_packet(packet)
            if attack_info:
                self.detected_attacks.append(attack_info)
                logger.warning(
                    f"Attaque détectée: {attack_info['type']} "
                    f"de {attack_info.get('source_ip', 'inconnu')}"
                )
                
                # Blocage optionnel des attaquants
                if self.args.block and 'source_ip' in attack_info:
                    block_ip(attack_info['source_ip'])
        
        try:
            self.packets = self.capture.start_capture(
                count=self.args.count,
                timeout=self.args.timeout,
                filter_str=self.args.filter,
                callback=packet_callback
            )
        finally:
            self.end_time = time.time()
            capture_duration = self.end_time - self.start_time
            logger.info(
                f"Capture terminée: {len(self.packets)} paquets en {capture_duration:.2f}s"
            )

    def _analyze_protocols(self) -> None:
        """Analyse les protocoles des paquets capturés."""
        logger.info("Analyse des protocoles...")
        self.analyzer.set_packets(self.packets)
        self.protocol_stats = self.analyzer.get_protocol_stats()
        logger.info(f"Analyse terminée: {len(self.protocol_stats)} protocoles détectés")

    def _detect_attacks(self) -> None:
        """Détecte les attaques dans les paquets capturés."""
        logger.info("Finalisation de la détection d'attaques...")
        logger.info(f"Détection terminée: {len(self.detected_attacks)} attaques détectées")

    def _generate_report(self) -> None:
        """Génère le rapport PDF avec les statistiques et analyses."""
        logger.info("Génération du rapport...")
        
        capture_info = {
            "interface": self.args.interface,
            "duration": round(self.end_time - self.start_time, 2),
            "packet_count": len(self.packets),
            "filter": self.args.filter or "Aucun",
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time)),
            "end_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.end_time)),
        }
        
        report_path = self.reporter.generate_full_report(
            protocol_stats=self.protocol_stats,
            attack_info=self.detected_attacks,
            capture_info=capture_info,
            filename=self.args.output
        )
        
        logger.info(f"Rapport généré: {report_path}")
        print(f"\nRapport généré avec succès: {os.path.abspath(report_path)}")


def main() -> int:
    """
    Fonction principale.

    Returns:
        Code de sortie (0 = succès, != 0 = erreur)
    """
    # Parse les arguments
    args = parse_arguments()
    
    # Configure le logging
    setup_logging(args.log_level, args.log_file)
    
    # Crée et exécute l'application
    app = IdsIpsApplication(args)
    return app.run()


if __name__ == "__main__":
    sys.exit(main()) 