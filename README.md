# Surveillance Réseau avec Détection d'Intrusion en Temps Réel

Ce projet est une application de surveillance réseau qui détecte les activités suspectes telles que les scans de ports, les balayages ICMP (Ping Sweep) et les attaques DoS (Denial of Service). L'application est composée de deux parties principales :

- **Agent de Surveillance** : Un programme Python qui capture le trafic réseau, analyse les paquets et envoie des alertes au serveur en cas de détection d'activités suspectes.
- **Serveur Web** : Une application Flask qui reçoit les alertes, les enregistre et affiche un tableau de bord en temps réel pour la visualisation des alertes.

## Table des Matières

- [Fonctionnalités](#fonctionnalités)
- [Architecture du Projet](#architecture-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Lancement du Serveur](#lancement-du-serveur)
- [Lancement de l'Agent](#lancement-de-lagent)
- [Utilisation](#utilisation)
- [Personnalisation](#personnalisation)
- [Dépannage](#dépannage)
- [Licence](#licence)

## Fonctionnalités

- **Détection des Scans de Ports** : Identifie les adresses IP qui tentent de scanner plusieurs ports sur le réseau.
- **Détection des Ping Sweeps** : Détecte les adresses IP qui envoient un grand nombre de requêtes ICMP Echo (ping) sur le réseau.
- **Détection des Attaques DoS** : Surveille les flux de trafic pour détecter des volumes inhabituels de paquets vers une destination spécifique.
- **Tableau de Bord en Temps Réel** : Affiche les alertes en temps réel via une interface web conviviale.
- **Enregistrement des Alertes** : Stocke les alertes dans un fichier JSON pour une analyse ultérieure.
- **Interface Graphique pour l'Agent** : Permet de sélectionner l'interface réseau et affiche les logs en temps réel.

## Architecture du Projet

- **agent.py** : Script Python qui capture et analyse le trafic réseau sur une interface spécifiée.
- **main.py** : Application Flask qui sert le tableau de bord web et reçoit les alertes de l'agent.
- **templates/** : Dossier contenant les fichiers HTML pour le rendu des pages web.
- **static/** : Dossier contenant les fichiers statiques (JavaScript, CSS).
- **config.json** : Fichier de configuration pour l'agent.
- **alerts.json** : Fichier généré par le serveur pour stocker les alertes reçues.

## Prérequis

- Python 3.6+
- pip (gestionnaire de paquets Python)
- Virtualenv (recommandé)
- **Dépendances Python** :
  - Flask
  - Flask-Bootstrap
  - psutil
  - scapy
  - requests
  - tkinter (généralement inclus avec Python)
- **Permissions Administrateur** : L'agent nécessite des privilèges élevés pour capturer le trafic réseau.

## Installation

**Cloner le Répertoire du Projet** :

```bash
git clone https://github.com/votre-utilisateur/votre-projet.git
cd NIDS
```

**Installer les Dépendances** :

```bash
pip install -r requirements.txt
```

Si vous n'avez pas de fichier `requirements.txt`, vous pouvez installer les packages manuellement :

```bash
pip install Flask Flask-Bootstrap psutil scapy requests
```

## Configuration

### Configuration de l'Agent (`config.json`)

Créez un fichier `config.json` à la racine du projet avec le contenu suivant :

{
"server_url": "http://localhost:5000/receive_alert"
}

- `server_url` : L'URL où l'agent enverra les alertes. Si le serveur est sur une autre machine ou un autre port, modifiez cette valeur en conséquence.

## Lancement du Serveur

1. Assurez-vous que l'Environnement Virtuel est Activé.
2. Exécutez le Serveur Flask :

   python main.py

   Le serveur démarrera sur `http://0.0.0.0:5000` par défaut.

3. Vérifiez que le Serveur Fonctionne :
   - Ouvrez un navigateur web et accédez à `http://localhost:5000` pour voir le tableau de bord.

## Lancement de l'Agent

> **Important** : L'agent doit être exécuté avec des privilèges administrateur pour capturer le trafic réseau.

1. Exécutez l'Agent :
   - Lancer le agent.exe
2. Sélectionnez l'Interface Réseau :
   - Une fenêtre s'ouvrira vous demandant de choisir l'interface réseau à surveiller.
3. L'Agent Démarre la Capture :
   - Une fois l'interface sélectionnée, l'agent commencera à capturer et analyser le trafic réseau.

## Utilisation

### Visualisation des Alertes :

- Le tableau de bord affichera les alertes groupées par adresse IP source. Cliquez sur une adresse IP pour voir les détails des alertes associées.

### Alertes en Temps Réel :

- Les nouvelles alertes seront automatiquement ajoutées au tableau de bord cela nécessiter un rafraîchissement manuel de la page.

### Détails de l'Alerte :

- Cliquez sur "Voir détails" pour obtenir des informations supplémentaires sur une alerte spécifique, y compris le type d'alerte, les adresses IP source et destination, les ports concernés, etc.

## Personnalisation

### Modification des Seuils de Détection

Dans `agent.py`, vous pouvez ajuster les variables suivantes pour modifier les seuils de détection :

- `ICMP_THRESHOLD` : Nombre de requêtes ICMP pour considérer un ping sweep.
- `PORT_SCAN_THRESHOLD` : Nombre de ports différents pour considérer un scan de ports.
- `DOS_THRESHOLD` : Nombre de paquets en peu de temps pour considérer une attaque DoS.
- `DOS_TIME_WINDOW` : Fenêtre de temps en secondes pour le comptage DoS.

### Ajout du Nom d'Hôte aux Alertes

Pour identifier facilement la source des alertes lorsque plusieurs agents sont déployés, le nom d'hôte est ajouté aux alertes.

- **Modifications Apportées** :
  - Dans `agent.py`, le nom d'hôte est récupéré et inclus dans chaque alerte envoyée.
    ```python
    import socket
    HOSTNAME = socket.gethostname()
    ```
  - Lors de la création des alertes :
    ```python
    detection = {
        "type": "Scan de Ports",
        "hostname": HOSTNAME,
        "src_ip": src_ip,
        # autres champs...
    }
    ```
  - Dans `main.py` et les templates, le champ `hostname` est utilisé pour afficher le nom d'hôte associé à chaque alerte.

## Dépannage

### Problèmes Courants

- **L'Agent ne Capte pas de Trafic** :
  - Assurez-vous que l'agent est exécuté avec les privilèges administrateur.
  - Vérifiez que l'interface réseau sélectionnée est active et qu'il y a du trafic.
- **Le Tableau de Bord n'Affiche pas les Alertes** :
  - Vérifiez que le serveur Flask est en cours d'exécution.
  - Assurez-vous que `SERVER_URL` dans `config.json` pointe vers le bon endpoint.
  - Consultez les logs du serveur (`server.log`) pour d'éventuelles erreurs.
- **Erreur lors de l'Installation des Dépendances** :
  - Assurez-vous que vous utilisez une version compatible de Python.
  - Mettez à jour `pip` :
    ```bash
    pip install --upgrade pip
    ```
- **Problèmes de Permissions** :
  - Sous Unix/Linux, utilisez `sudo` pour exécuter l'agent.
  - Sous Windows, exécutez le script en tant qu'administrateur.

### Logs et Debugging

- **Logs du Serveur** :
  - Les logs du serveur sont enregistrés dans le fichier `server.log`.
- **Logs de l'Agent** :
  - Les messages de l'agent sont affichés dans l'interface graphique.

## Licence

Ce projet est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

Ce README a été généré pour fournir une documentation complète du projet de surveillance réseau avec détection d'intrusion en temps réel. N'hésitez pas à modifier et adapter ce document en fonction de vos besoins spécifiques.
