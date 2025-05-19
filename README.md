# IDS/IPS & Analyse Shellcode Python (Scapy, Capstone, Unicorn)

## Description
Ce projet implémente un système de détection et de prévention d'intrusion (IDS/IPS) en utilisant la bibliothèque Scapy de Python. L'outil est capable d'analyser le trafic réseau en temps réel, de détecter les tentatives d'attaques et de générer des rapports détaillés.

### **Nouveau : Module 2 (en développement)**
Le projet s'enrichit d'un **Module 2** dédié à l'analyse de shellcodes, au désassemblage et à l'émulation de code malveillant. Ce module vise à :
- Charger et analyser des shellcodes (statique et dynamique)
- Désassembler le code binaire (avec Capstone)
- Émuler l'exécution de shellcodes (avec Unicorn)
- Générer des rapports d'analyse détaillés

> **Statut :** Le module 2 est en cours de développement. Suivez les mises à jour dans le dossier `src/module_2_shellcode/`.

## Fonctionnalités
- Capture de paquets réseau sur une interface spécifique
- Analyse des protocoles réseau reçus sur la carte
- Génération de rapports PDF avec graphiques et tableaux des protocoles détectés
- Détection et signalement de trafic illégitime (injection SQL, ARP Spoofing, etc.)
- Blocage optionnel des machines attaquantes
- **(À venir)** Analyse de shellcode, désassemblage, émulation, rapport d'analyse (Module 2)

## Prérequis
- Python 3.10 ou supérieur
- Poetry pour la gestion des dépendances
- Scapy pour l'analyse de trafic
- PyGal pour la génération de graphiques
- FPDF pour la génération de rapports PDF
- Capstone, Unicorn, Pwntools (pour le module 2)

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

### Lancer l'outil de détection (Module 1) :
```bash
poetry run python -m module_1_scapy.main --interface eth0
```

### (À venir) Lancer l'analyse de shellcode (Module 2) :
```bash
poetry run python -m module_2_shellcode.main --help
```

### Options disponibles Module 1 :
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
