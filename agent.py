# Imports nécessaires
import psutil
import sys
import json
import threading
import os
import time
import socket
from scapy.all import sniff, TCP, UDP, ICMP, IP, DNS
import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from collections import defaultdict

# Déterminer le chemin vers le fichier config.json en fonction de l'environnement (exécutable ou script)
if getattr(sys, "frozen", False):
    application_path = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(application_path, "config.json")

# Charger les paramètres de configuration depuis config.json
try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
except Exception as e:
    messagebox.showerror(
        "Erreur", f"Impossible de charger le fichier de configuration:\n{e}"
    )
    sys.exit(1)

SERVER_URL = config.get("server_url")

# Récupérer le nom de l'ordinateur (hostname)
HOSTNAME = socket.gethostname()

# Structures pour stocker les informations sur le trafic réseau
icmp_counts = defaultdict(int)
port_scan_counts = defaultdict(set)
dos_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
ssh_telnet_connections = set()
dns_packet_counts = defaultdict(int)

# Définir les seuils pour les différentes détections
ICMP_THRESHOLD = 10  # ping
PORT_SCAN_THRESHOLD = 20  # nombre de ports scannés pour détecter un scan de port
DOS_THRESHOLD = 100  # nombre de paquets pour détecter une attaque DoS
DOS_TIME_WINDOW = 5  # fenêtre de temps en secondes pour le comptage DoS
DNS_SIZE_THRESHOLD = 512  # taille seuil pour les paquets DNS
DNS_COUNT_THRESHOLD = 10  # nombre de paquets DNS volumineux pour détecter une attaque


def list_network_interfaces():
    # Récupérer la liste des interfaces réseau disponibles
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())


def select_interface_gui():
    # Interface graphique pour sélectionner l'interface réseau à surveiller
    interfaces = list_network_interfaces()
    if not interfaces:
        messagebox.showerror("Erreur", "Aucune interface réseau détectée.")
        sys.exit(1)

    def on_select():
        # Sélectionner l'interface choisie par l'utilisateur
        selected = combo.get()
        if selected:
            root.selected_interface = selected
            root.destroy()
        else:
            messagebox.showwarning(
                "Sélection requise", "Veuillez sélectionner une interface."
            )

    root = tk.Tk()
    root.title("Sélection de l'interface réseau")
    root.geometry("300x100")
    root.resizable(False, False)

    tk.Label(root, text="Veuillez choisir une interface réseau:").pack(pady=5)
    combo = ttk.Combobox(root, values=interfaces, state="readonly")
    combo.pack(pady=5)
    combo.current(0)  # Par défaut, sélectionner la première interface

    tk.Button(root, text="Valider", command=on_select).pack(pady=5)

    root.mainloop()

    return getattr(root, "selected_interface", None)


def send_alert(detection, app):
    # Envoyer une alerte au serveur via une requête POST
    try:
        response = requests.post(SERVER_URL, json=detection, timeout=5)
        response.raise_for_status()
        app.log_message(f"Alerte envoyée : {detection}")
    except requests.exceptions.RequestException as e:
        app.log_message(f"Erreur lors de l'envoi de l'alerte : {e}")


# Fonctions de détection pour différents types d'attaques ou comportements suspects
def detect_ping_sweep(packet_info, app):
    src_ip = packet_info["src_ip"]
    icmp_counts[src_ip] += 1

    # Détecter un balayage ping si le seuil est atteint
    if icmp_counts[src_ip] >= ICMP_THRESHOLD:
        detection = {
            "type": "Ping Sweep",
            "src_ip": src_ip,
            "count": icmp_counts[src_ip],
            "timestamp": time.time(),
            "hostname": HOSTNAME,
        }
        send_alert(detection, app)
        icmp_counts[src_ip] = 0


def detect_port_scan(packet_info, app):
    src_ip = packet_info["src_ip"]
    dst_port = packet_info["dst_port"]
    port_scan_counts[src_ip].add(dst_port)

    # Détecter un scan de ports si le nombre de ports scannés dépasse le seuil
    if len(port_scan_counts[src_ip]) >= PORT_SCAN_THRESHOLD:
        detection = {
            "type": "Scan de Ports",
            "src_ip": src_ip,
            "ports": list(port_scan_counts[src_ip]),
            "timestamp": time.time(),
            "hostname": HOSTNAME,
        }
        send_alert(detection, app)
        port_scan_counts[src_ip].clear()


def detect_dos(packet_info, app):
    dst_ip = packet_info["dst_ip"]
    current_time = time.time()
    dos_counts[dst_ip]["count"] += 1

    # Réinitialiser le comptage si la fenêtre de temps est dépassée
    if current_time - dos_counts[dst_ip]["timestamp"] > DOS_TIME_WINDOW:
        dos_counts[dst_ip]["count"] = 1
        dos_counts[dst_ip]["timestamp"] = current_time

    # Détecter une attaque DoS si le nombre de paquets dépasse le seuil
    if dos_counts[dst_ip]["count"] >= DOS_THRESHOLD:
        detection = {
            "type": "Attaque DoS",
            "dst_ip": dst_ip,
            "count": dos_counts[dst_ip]["count"],
            "timestamp": current_time,
            "hostname": HOSTNAME,
        }
        send_alert(detection, app)
        dos_counts[dst_ip]["count"] = 0


def detect_ssh_telnet(packet_info, app):
    src_ip = packet_info["src_ip"]
    dst_ip = packet_info["dst_ip"]
    dst_port = packet_info["dst_port"]

    # Détecter une connexion SSH ou Telnet
    if dst_port in [22, 23]:
        connection = (src_ip, dst_ip, dst_port)
        if connection not in ssh_telnet_connections:
            ssh_telnet_connections.add(connection)
            detection = {
                "type": "Connexion SSH/Telnet",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "timestamp": time.time(),
                "hostname": HOSTNAME,
            }
            send_alert(detection, app)


# Ceci est un test GPT pour detecter les paquet DNS trop volumineux
def detect_oversized_dns(packet_info, app, packet):
    if packet.haslayer(DNS):
        dns_length = len(packet[DNS])
        # Détecter des paquets DNS surdimensionnés
        if dns_length > DNS_SIZE_THRESHOLD:
            src_ip = packet_info["src_ip"]
            dns_packet_counts[src_ip] += 1

            if dns_packet_counts[src_ip] >= DNS_COUNT_THRESHOLD:
                detection = {
                    "type": "Paquets DNS surdimensionnés",
                    "src_ip": src_ip,
                    "count": dns_packet_counts[src_ip],
                    "timestamp": time.time(),
                    "hostname": HOSTNAME,
                }
                send_alert(detection, app)
                dns_packet_counts[src_ip] = 0


def analyze_packet(packet, app):
    # Analyser chaque paquet pour identifier les informations importantes
    packet_info = {}

    if not packet.haslayer(IP):
        return

    packet_info["src_ip"] = packet[IP].src
    packet_info["dst_ip"] = packet[IP].dst

    # Vérifier différents types de paquets pour détecter les activités suspectes
    if packet.haslayer(ICMP):
        packet_info["protocol"] = "ICMP"
        detect_ping_sweep(packet_info, app)

    elif packet.haslayer(TCP) or packet.haslayer(UDP):
        if packet.haslayer(TCP):
            packet_info["protocol"] = "TCP"
            packet_info["dst_port"] = packet[TCP].dport
            detect_ssh_telnet(packet_info, app)
        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            packet_info["dst_port"] = packet[UDP].dport

        if packet_info["protocol"] in ["TCP", "UDP"]:
            detect_port_scan(packet_info, app)
            detect_dos(packet_info, app)

    # Vérifier les paquets DNS
    if packet.haslayer(UDP) and packet[UDP].dport == 53:
        detect_oversized_dns(packet_info, app, packet)
    elif packet.haslayer(TCP) and packet[TCP].dport == 53:
        detect_oversized_dns(packet_info, app, packet)


def packet_callback(packet):
    try:
        # Analyser chaque paquet capturé
        analyze_packet(packet, app)
    except Exception as e:
        app.log_message(f"Erreur lors de l'analyse du paquet : {e}")


def start_sniffing(interface):
    # Démarrer la capture des paquets sur l'interface réseau spécifiée
    try:
        sniff(
            prn=packet_callback,
            store=0,
            iface=interface,
        )
    except Exception as e:
        app.log_message(f"Erreur lors du démarrage du sniffer : {e}")


def run_sniffer(interface):
    # Lancer le sniffer dans un thread distinct pour ne pas bloquer l'interface utilisateur
    threading.Thread(target=start_sniffing, args=(interface,), daemon=True).start()


class AgentApp(tk.Tk):
    def __init__(self, interface):
        super().__init__()
        self.title("Agent de Surveillance Réseau")
        self.geometry("600x400")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.interface = interface

        # Afficher l'interface réseau sélectionnée
        tk.Label(self, text=f"Interface sélectionnée : {interface}").pack(pady=5)

        # Zone de texte pour afficher les messages de log
        self.log_text = scrolledtext.ScrolledText(
            self, state="disabled", width=70, height=20
        )
        self.log_text.pack(pady=5)

        # Bouton pour arrêter l'agent de surveillance
        self.stop_button = tk.Button(
            self, text="Arrêter l'agent", command=self.on_closing
        )
        self.stop_button.pack(pady=5)

    def on_closing(self):
        # Confirmation avant de fermer l'application
        if messagebox.askokcancel(
            "Quitter", "Voulez-vous arrêter l'agent et quitter ?"
        ):
            self.destroy()
            sys.exit(0)

    def log_message(self, message):
        # Ajouter un message de log à l'interface utilisateur
        self.after(0, self._append_log_message, message)

    def _append_log_message(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)  # Faire défiler la zone de texte vers le bas


if __name__ == "__main__":
    # Lancer l'application pour sélectionner l'interface réseau et démarrer le sniffer
    interface = select_interface_gui()
    if interface:
        app = AgentApp(interface)
        run_sniffer(interface)
        app.log_message("Agent démarré. Capture des paquets en cours...")
        app.mainloop()
    else:
        messagebox.showinfo(
            "Agent", "Aucune interface sélectionnée. Fermeture de l'agent."
        )
