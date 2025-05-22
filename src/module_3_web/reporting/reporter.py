"""
Module de génération de rapports d'analyse web.

Ce module génère des rapports détaillés sur les résultats
des analyses et tests effectués sur les applications web.
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Union
import csv
from io import StringIO

logger = logging.getLogger(__name__)


class WebReporter:
    """
    Classe pour la génération de rapports d'analyse web.
    
    Cette classe permet de générer des rapports sur les résultats
    des tests et analyses d'applications web.
    """
    
    def __init__(self, output_dir: str = "reports", create_dir: bool = True):
        """
        Initialise un nouveau générateur de rapports.
        
        Args:
            output_dir: Répertoire de sortie des rapports
            create_dir: Créer le répertoire s'il n'existe pas
        """
        self.output_dir = output_dir
        
        if create_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Répertoire de rapports créé: {output_dir}")
        
        logger.info(f"WebReporter initialisé (sortie: {output_dir})")
    
    def generate_fuzzing_report(self, results: Dict[str, Any], target_url: str, 
                               report_name: str = None) -> str:
        """
        Génère un rapport de fuzzing.
        
        Args:
            results: Résultats du fuzzing
            target_url: URL cible
            report_name: Nom du rapport (optionnel)
            
        Returns:
            Chemin du fichier de rapport généré
        """
        if report_name is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"fuzzing_report_{timestamp}"
        
        # Assurer l'extension .html
        if not report_name.endswith('.html'):
            report_name += '.html'
        
        report_path = os.path.join(self.output_dir, report_name)
        
        # Création du rapport HTML
        html_content = self._generate_fuzzing_html(results, target_url)
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Rapport de fuzzing généré: {report_path}")
            return report_path
        
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
            return ""
    
    def _generate_fuzzing_html(self, results: Dict[str, Any], target_url: str) -> str:
        """
        Génère le contenu HTML d'un rapport de fuzzing.
        
        Args:
            results: Résultats du fuzzing
            target_url: URL cible
            
        Returns:
            Contenu HTML du rapport
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Fuzzing Web</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #34495e; color: white; padding: 10px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .status-200 {{ color: green; }}
        .status-3xx {{ color: blue; }}
        .status-4xx {{ color: orange; }}
        .status-5xx {{ color: red; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport de Fuzzing Web</h1>
        </div>
        
        <div class="summary">
            <h2>Informations générales</h2>
            <p><strong>URL cible:</strong> {target_url}</p>
            <p><strong>Date:</strong> {timestamp}</p>
            <p><strong>Résultats trouvés:</strong> {len(results)}</p>
        </div>
        
        <h2>Résultats détaillés</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Statut</th>
                <th>Taille (octets)</th>
                <th>Temps (s)</th>
            </tr>
"""
        
        # Ajouter chaque résultat au tableau
        for url, info in results.items():
            status = info.get('status_code', 0)
            status_class = ""
            
            if 200 <= status < 300:
                status_class = "status-200"
            elif 300 <= status < 400:
                status_class = "status-3xx"
            elif 400 <= status < 500:
                status_class = "status-4xx"
            elif 500 <= status < 600:
                status_class = "status-5xx"
            
            html += f"""
            <tr>
                <td>{url}</td>
                <td class="{status_class}">{status}</td>
                <td>{info.get('content_length', 0)}</td>
                <td>{info.get('response_time', 0):.3f}</td>
            </tr>"""
        
        html += """
        </table>
        
        <div class="footer">
            <p>Généré avec module_3_web - Outil d'analyse de sécurité web</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def generate_vulnerability_report(self, vulnerabilities: List[Dict[str, Any]], 
                                     target: str, scan_info: Dict[str, Any] = None,
                                     format_type: str = 'html') -> str:
        """
        Génère un rapport de vulnérabilités.
        
        Args:
            vulnerabilities: Liste des vulnérabilités trouvées
            target: Cible de l'analyse (URL, domaine, etc.)
            scan_info: Informations sur l'analyse (optionnel)
            format_type: Format du rapport ('html', 'pdf', 'json', 'csv')
            
        Returns:
            Chemin du fichier de rapport généré
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"vulnerability_report_{timestamp}"
        
        # Compléter les informations de scan
        if scan_info is None:
            scan_info = {}
        
        scan_info.update({
            'timestamp': datetime.datetime.now().isoformat(),
            'target': target,
            'vulnerabilities_count': len(vulnerabilities)
        })
        
        # Générer le rapport dans le format demandé
        if format_type == 'json':
            report_path = os.path.join(self.output_dir, f"{report_name}.json")
            self._generate_json_vulnerability_report(report_path, vulnerabilities, scan_info)
        elif format_type == 'csv':
            report_path = os.path.join(self.output_dir, f"{report_name}.csv")
            self._generate_csv_vulnerability_report(report_path, vulnerabilities)
        elif format_type == 'html':
            report_path = os.path.join(self.output_dir, f"{report_name}.html")
            self._generate_html_vulnerability_report(report_path, vulnerabilities, scan_info)
        else:
            logger.error(f"Format de rapport non supporté: {format_type}")
            return ""
        
        logger.info(f"Rapport de vulnérabilités généré: {report_path}")
        return report_path
    
    def _generate_json_vulnerability_report(self, report_path: str, 
                                           vulnerabilities: List[Dict[str, Any]],
                                           scan_info: Dict[str, Any]) -> None:
        """
        Génère un rapport de vulnérabilités au format JSON.
        
        Args:
            report_path: Chemin du fichier de rapport
            vulnerabilities: Liste des vulnérabilités
            scan_info: Informations sur l'analyse
        """
        report_data = {
            'scan_info': scan_info,
            'vulnerabilities': vulnerabilities
        }
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport JSON: {str(e)}")
    
    def _generate_csv_vulnerability_report(self, report_path: str, 
                                          vulnerabilities: List[Dict[str, Any]]) -> None:
        """
        Génère un rapport de vulnérabilités au format CSV.
        
        Args:
            report_path: Chemin du fichier de rapport
            vulnerabilities: Liste des vulnérabilités
        """
        try:
            with open(report_path, 'w', newline='', encoding='utf-8') as f:
                if not vulnerabilities:
                    f.write("Aucune vulnérabilité trouvée")
                    return
                
                # Déterminer les champs à partir du premier élément
                fieldnames = list(vulnerabilities[0].keys())
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(vulnerabilities)
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport CSV: {str(e)}")
    
    def _generate_html_vulnerability_report(self, report_path: str, 
                                           vulnerabilities: List[Dict[str, Any]],
                                           scan_info: Dict[str, Any]) -> None:
        """
        Génère un rapport de vulnérabilités au format HTML.
        
        Args:
            report_path: Chemin du fichier de rapport
            vulnerabilities: Liste des vulnérabilités
            scan_info: Informations sur l'analyse
        """
        try:
            html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Vulnérabilités Web</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #34495e; color: white; padding: 10px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
        .vulnerability {{ margin: 20px 0; padding: 15px; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; }}
        .severity-high {{ border-left: 5px solid #e74c3c; }}
        .severity-medium {{ border-left: 5px solid #f39c12; }}
        .severity-low {{ border-left: 5px solid #3498db; }}
        .severity-info {{ border-left: 5px solid #2ecc71; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport de Vulnérabilités Web</h1>
        </div>
        
        <div class="summary">
            <h2>Informations générales</h2>
            <p><strong>Cible:</strong> {scan_info.get('target', 'Non spécifiée')}</p>
            <p><strong>Date:</strong> {scan_info.get('timestamp', 'Non spécifiée')}</p>
            <p><strong>Vulnérabilités trouvées:</strong> {scan_info.get('vulnerabilities_count', 0)}</p>
        </div>
        
        <h2>Vulnérabilités détectées</h2>
"""
            
            if not vulnerabilities:
                html += "<p>Aucune vulnérabilité détectée.</p>"
            else:
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'info').lower()
                    html += f"""
        <div class="vulnerability severity-{severity}">
            <h3>{vuln.get('name', 'Vulnérabilité non nommée')}</h3>
            <p><strong>Sévérité:</strong> {severity.capitalize()}</p>
            <p><strong>URL:</strong> {vuln.get('url', 'Non spécifiée')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'Aucune description')}</p>
"""
                    
                    # Ajouter les détails supplémentaires s'ils existent
                    if 'details' in vuln and vuln['details']:
                        html += f"""            <h4>Détails</h4>
            <pre>{vuln['details']}</pre>
"""
                    
                    # Ajouter les suggestions de correction si elles existent
                    if 'remediation' in vuln and vuln['remediation']:
                        html += f"""            <h4>Recommandations</h4>
            <p>{vuln['remediation']}</p>
"""
                    
                    html += "        </div>\n"
            
            html += """
        <div class="footer">
            <p>Généré avec module_3_web - Outil d'analyse de sécurité web</p>
        </div>
    </div>
</body>
</html>"""
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport HTML: {str(e)}")
    
    def export_requests_history(self, history: List[Dict[str, Any]], 
                               format_type: str = 'csv') -> str:
        """
        Exporte l'historique des requêtes dans un fichier.
        
        Args:
            history: Liste des requêtes
            format_type: Format d'export ('csv', 'json')
            
        Returns:
            Chemin du fichier exporté
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"requests_history_{timestamp}"
        
        if format_type == 'json':
            export_path = os.path.join(self.output_dir, f"{filename}.json")
            try:
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(history, f, indent=2, default=str)
                logger.info(f"Historique exporté en JSON: {export_path}")
                return export_path
            except Exception as e:
                logger.error(f"Erreur lors de l'export JSON: {str(e)}")
                return ""
        
        elif format_type == 'csv':
            export_path = os.path.join(self.output_dir, f"{filename}.csv")
            try:
                with open(export_path, 'w', newline='', encoding='utf-8') as f:
                    if not history:
                        f.write("Aucune requête dans l'historique")
                        return export_path
                    
                    # Créer un ensemble de tous les champs possibles
                    all_fields = set()
                    for entry in history:
                        all_fields.update(entry.keys())
                    
                    # Exclure certains champs complexes
                    excluded_fields = {'headers', 'data', 'params'}
                    fieldnames = [f for f in all_fields if f not in excluded_fields]
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(history)
                
                logger.info(f"Historique exporté en CSV: {export_path}")
                return export_path
            
            except Exception as e:
                logger.error(f"Erreur lors de l'export CSV: {str(e)}")
                return ""
        
        else:
            logger.error(f"Format d'export non supporté: {format_type}")
            return "" 