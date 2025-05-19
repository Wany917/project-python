# IDS/IPS avec Scapy - Module 1

## Description
Ce projet implémente un système de détection et de prévention d'intrusion (IDS/IPS) en utilisant la bibliothèque Scapy de Python. L'outil est capable d'analyser le trafic réseau en temps réel, de détecter les tentatives d'attaques et de générer des rapports détaillés.

## Fonctionnalités
- Capture de paquets réseau sur une interface spécifique
- Analyse des protocoles réseau reçus sur la carte
- Génération de rapports PDF avec graphiques et tableaux des protocoles détectés
- Détection et signalement de trafic illégitime (injection SQL, ARP Spoofing, etc.)
- Blocage optionnel des machines attaquantes

## Prérequis
- Python 3.13 ou supérieur
- Poetry pour la gestion des dépendances
- Scapy pour l'analyse de trafic
- PyGal pour la génération de graphiques
- FPDF pour la génération de rapports PDF

## Installation

1. Cloner le dépôt :
```bash
git clone [URL_DU_DEPOT]
cd module-1-scapy
```

2. Installer les dépendances avec Poetry :
```bash
poetry install
```

## Utilisation

### Lancer l'outil de détection :
```bash
poetry run python -m module_1_scapy.main --interface eth0
```

### Options disponibles :
- `--interface` : Interface réseau à analyser (obligatoire)
- `--output` : Chemin du fichier de rapport à générer (défaut: `report.pdf`)
- `--timeout` : Durée de la capture en secondes (défaut: 60)
- `--block` : Activer le blocage automatique des attaquants (optionnel)

## Structure du projet
Voir le fichier [CONVENTIONS.md](CONVENTIONS.md) pour plus de détails sur la structure du projet et les conventions de code.

## Développement

### Installation de l'environnement de développement :
```bash
poetry install --with dev
pre-commit install
```

### Exécuter les tests :
```bash
poetry run pytest
```

## Contributeurs
- [Nom du contributeur 1]
- [Nom du contributeur 2]

## Licence
Ce projet est distribué sous licence [LICENCE]. Voir le fichier LICENSE pour plus de détails.
