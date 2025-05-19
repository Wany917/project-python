"""
Module de génération de rapports PDF avec graphiques.
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from fpdf import FPDF
import pygal
from scapy.packet import Packet
import cairosvg

logger = logging.getLogger(__name__)


class NetworkReporter:
    """Classe pour générer des rapports sur le trafic réseau."""

    def __init__(self, output_dir: str = "."):
        """
        Initialise le générateur de rapports.

        Args:
            output_dir: Répertoire de sortie pour les rapports
        """
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        logger.info(f"Générateur de rapports initialisé (sortie: {output_dir})")

    def generate_protocol_chart(
        self, protocol_stats: Dict[str, int], filename: str = "protocol_stats.svg"
    ) -> str:
        """
        Génère un graphique des statistiques de protocoles.

        Args:
            protocol_stats: Dictionnaire des protocoles et leur nombre d'occurrences
            filename: Nom du fichier SVG à générer

        Returns:
            Chemin du fichier SVG généré
        """
        if not protocol_stats:
            logger.warning("Aucune statistique de protocole à afficher")
            return ""

        # Création du graphique à barres
        bar_chart = pygal.Bar(style=pygal.style.LightColorizedStyle)
        bar_chart.title = "Statistiques de protocoles réseau"
        
        for proto, count in protocol_stats.items():
            bar_chart.add(proto, [count])

        # Chemin du fichier à générer
        output_path = os.path.join(self.output_dir, filename)
        bar_chart.render_to_file(output_path)
        logger.info(f"Graphique des protocoles généré: {output_path}")

        # Conversion SVG -> PNG pour insertion dans le PDF
        png_path = output_path.replace('.svg', '.png')
        try:
            cairosvg.svg2png(url=output_path, write_to=png_path)
            logger.info(f"Graphique converti en PNG: {png_path}")
        except Exception as e:
            logger.error(f"Erreur lors de la conversion SVG->PNG: {e}")
            png_path = None

        return output_path  # On retourne toujours le SVG pour compatibilité

    def generate_full_report(
        self,
        protocol_stats: Dict[str, int],
        attack_info: List[Dict[str, Any]],
        capture_info: Dict[str, Any],
        filename: str = "network_report.pdf",
    ) -> str:
        """
        Génère un rapport PDF complet avec graphiques et informations de sécurité.

        Args:
            protocol_stats: Statistiques des protocoles
            attack_info: Informations sur les attaques détectées
            capture_info: Informations sur la capture
            filename: Nom du fichier PDF à générer

        Returns:
            Chemin du fichier PDF généré
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Générer le graphique
        chart_path = self.generate_protocol_chart(protocol_stats)
        png_chart_path = chart_path.replace('.svg', '.png')
        
        # Créer le PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Titre et en-tête
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Rapport d'analyse réseau", 0, 1, "C")
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Généré le: {timestamp}", 0, 1, "C")
        pdf.ln(5)
        
        # Information de capture
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Informations de capture", 0, 1)
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Interface: {capture_info.get('interface', 'Non spécifiée')}", 0, 1)
        pdf.cell(0, 10, f"Durée: {capture_info.get('duration', '0')} secondes", 0, 1)
        pdf.cell(0, 10, f"Paquets capturés: {capture_info.get('packet_count', 0)}", 0, 1)
        pdf.ln(5)
        
        # Statistiques de protocoles
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Statistiques de protocoles", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        if chart_path and os.path.exists(png_chart_path):
            # Si on a un PNG, l'ajouter
            pdf.image(png_chart_path, x=10, y=None, w=180)
            pdf.ln(5)
        
        # Tableau des protocoles
        pdf.set_font("Arial", "B", 12)
        pdf.cell(100, 10, "Protocole", 1, 0, "C")
        pdf.cell(90, 10, "Nombre de paquets", 1, 1, "C")
        pdf.set_font("Arial", "", 12)
        
        for protocol, count in protocol_stats.items():
            pdf.cell(100, 10, protocol, 1, 0)
            pdf.cell(90, 10, str(count), 1, 1, "C")
        
        pdf.ln(10)
        
        # Analyse de sécurité
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Analyse de sécurité", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        if attack_info:
            pdf.cell(0, 10, f"Nombre d'attaques détectées: {len(attack_info)}", 0, 1)
            pdf.ln(5)
            
            # Détails des attaques
            pdf.set_font("Arial", "B", 12)
            pdf.cell(60, 10, "Type d'attaque", 1, 0, "C")
            pdf.cell(70, 10, "Source", 1, 0, "C")
            pdf.cell(60, 10, "Destination", 1, 1, "C")
            pdf.set_font("Arial", "", 12)
            
            for attack in attack_info:
                pdf.cell(60, 10, attack.get("type", "Inconnue"), 1, 0)
                pdf.cell(70, 10, attack.get("source_ip", "Inconnue"), 1, 0)
                pdf.cell(60, 10, attack.get("target_ip", attack.get("destination_ip", "Inconnue")), 1, 1)
                
            # Pour chaque attaque, ajouter une section détaillée
            pdf.ln(5)
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Détails des attaques", 0, 1)
            
            for i, attack in enumerate(attack_info):
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, f"Attaque {i+1}: {attack.get('type', 'Inconnue')}", 0, 1)
                pdf.set_font("Arial", "", 12)
                
                for key, value in attack.items():
                    if key not in ["type", "packet"] and value is not None:
                        pdf.cell(0, 10, f"{key}: {value}", 0, 1)
                
                pdf.ln(5)
        else:
            pdf.cell(0, 10, "Aucune attaque détectée. Le trafic semble légitime.", 0, 1)
        
        # Sauvegarder le PDF
        output_path = os.path.join(self.output_dir, filename)
        pdf.output(output_path)
        logger.info(f"Rapport PDF généré: {output_path}")
        
        return output_path 