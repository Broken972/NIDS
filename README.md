# 📡 Surveillance Réseau avec Détection d'Intrusion en Temps Réel 🚨

Ce projet est une application de **surveillance réseau** qui détecte les activités suspectes telles que :

- 🚀 **Scans de ports**
- 📶 **Balayages ICMP (Ping Sweep)**
- 🛑 **Attaques DoS (Denial of Service)**

L'application est composée de deux parties principales :

- 🤖 **Agent de Surveillance** : Un programme Python qui capture le trafic réseau, analyse les paquets et envoie des alertes au serveur en cas de détection d'activités suspectes.
- 🖥️ **Serveur de Surveillance** : Un serveur centralisé qui reçoit les alertes de tous les agents déployés sur le réseau, les analyse, et affiche une interface pour la gestion et la visualisation des événements.

## 🚀 Comment Commencer ?

1. **Installer les dépendances** : Utilisez `pip install -r requirements.txt` pour installer toutes les bibliothèques nécessaires.
2. **Configurer l'Agent** : Modifiez le fichier `config.json` pour sélectionner IP du server.
3. **Lancer l'Agent et le Serveur** : Exécutez `agent.exe` pour démarrer l'agent de surveillance et `python main.py` pour démarrer le serveur centralisé.

Vous aurait une interface graphique pour visualiser les alertes et les événements en temps réel. Il faut rafrachir la page pour voir les alertes. Cette fonctionnalité sera améliorée dans les prochaines versions.

👨‍💻 _Conçu pour aider à renforcer la sécurité de votre réseau en identifiant rapidement les menaces potentielles._
