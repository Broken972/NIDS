from flask import Flask, request, jsonify, render_template, url_for, Response
from flask_bootstrap import Bootstrap
import logging
import json
import os
from datetime import datetime
import threading
import queue
import webbrowser
import time

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Chemin du fichier qui contient les alertes
alerts_file = "alerts.json"

# Créer le fichier des alertes s'il n'existe pas encore
if not os.path.exists(alerts_file):
    with open(alerts_file, "w") as f:
        json.dump([], f)

# Configurer le système de logging pour enregistrer les événements dans server.log
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

# File d'attente pour gérer les alertes en temps réel
alert_queue = queue.Queue()


@app.route("/receive_alert", methods=["POST"])
def receive_alert():
    alert = request.json

    # Créer un ID unique basé sur le timestamp pour chaque alerte
    alert_id = int(datetime.now().timestamp() * 1000)
    alert["id"] = alert_id

    # Lire le contenu du fichier d'alertes, le mettre à jour, puis le sauvegarder
    try:
        with open(alerts_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = []

    data.append(alert)

    with open(alerts_file, "w") as f:
        json.dump(data, f, indent=4)

    # Ajouter l'alerte à la file d'attente pour être envoyée en temps réel
    alert_queue.put(alert)

    logging.info(f"Nouvelle alerte reçue: {alert}")
    return jsonify({"status": "received"}), 200


@app.route("/", methods=["GET"])
def dashboard():
    # Charger toutes les alertes stockées dans le fichier JSON
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Grouper les alertes par adresse IP source pour un affichage organisé
    grouped_alerts = {}
    for alert in alerts:
        src_ip = alert.get("src_ip", "Inconnu")
        if src_ip not in grouped_alerts:
            grouped_alerts[src_ip] = []
        grouped_alerts[src_ip].append(alert)

    return render_template("dashboard.html", grouped_alerts=grouped_alerts)


@app.route("/source/<path:src_ip>", methods=["GET"])
def source_alerts(src_ip):
    # Charger toutes les alertes depuis le fichier JSON
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Filtrer les alertes par adresse IP source spécifique
    source_alerts = [a for a in alerts if a.get("src_ip") == src_ip]

    return render_template("source_alerts.html", src_ip=src_ip, alerts=source_alerts)


@app.route("/alert/<int:alert_id>", methods=["GET"])
def alert_detail(alert_id):
    # Charger toutes les alertes stockées dans le fichier JSON
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Chercher l'alerte spécifique par son ID
    alert = next((a for a in alerts if a["id"] == alert_id), None)

    if alert:
        return render_template("alert_detail.html", alert=alert)
    else:
        return "Alerte non trouvée", 404


# Filtre pour afficher la date dans un format lisible
@app.template_filter("datetimeformat")
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


# Route pour les alertes en temps réel (Server-Sent Events)
@app.route("/alerts")
def alerts():
    def generate():
        while True:
            alert = alert_queue.get()
            yield f"data: {json.dumps(alert)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


# Gérer les erreurs internes du serveur pour un retour d'erreur clair
@app.errorhandler(Exception)
def unhandled_exception(e):
    app.logger.error(f"Exception: {e}")
    return jsonify({"error": "Unhandled Exception"}), 500


def open_browser():
    # Attendre une seconde puis ouvrir le navigateur web par défaut sur le tableau de bord
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5000/")


if __name__ == "__main__":
    # Ouvrir automatiquement le navigateur web puis démarrer l'application Flask
    threading.Thread(target=open_browser).start()
    app.run(host="0.0.0.0", port=5000)
