from flask import Flask, request, jsonify, render_template, url_for, Response
from flask_bootstrap import Bootstrap
import logging
import json
import os
from datetime import datetime
import threading
import queue

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Chemin vers le fichier des alertes
alerts_file = "alerts.json"

# Assurer que le fichier des alertes existe
if not os.path.exists(alerts_file):
    with open(alerts_file, "w") as f:
        json.dump([], f)

# Configurer le logging
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

# File d'attente pour les alertes en temps réel
alert_queue = queue.Queue()


@app.route("/receive_alert", methods=["POST"])
def receive_alert():
    alert = request.json

    # Assigner un identifiant unique à chaque alerte
    alert_id = int(datetime.now().timestamp() * 1000)
    alert["id"] = alert_id

    # Enregistrer l'alerte dans le fichier alerts.json
    try:
        with open(alerts_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = []

    data.append(alert)

    with open(alerts_file, "w") as f:
        json.dump(data, f, indent=4)

    # Mettre l'alerte dans la file d'attente pour les SSE
    alert_queue.put(alert)

    logging.info(f"Nouvelle alerte reçue: {alert}")
    return jsonify({"status": "received"}), 200


@app.route("/", methods=["GET"])
def dashboard():
    # Charger les alertes depuis le fichier
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Regrouper les alertes par adresse IP source
    grouped_alerts = {}
    for alert in alerts:
        src_ip = alert.get("src_ip", "Inconnu")
        if src_ip not in grouped_alerts:
            grouped_alerts[src_ip] = []
        grouped_alerts[src_ip].append(alert)

    return render_template("dashboard.html", grouped_alerts=grouped_alerts)


# Modifier la route pour utiliser le convertisseur 'path'
@app.route("/source/<path:src_ip>", methods=["GET"])
def source_alerts(src_ip):
    # Charger les alertes depuis le fichier
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Filtrer les alertes pour l'IP source donnée
    source_alerts = [a for a in alerts if a.get("src_ip") == src_ip]

    return render_template("source_alerts.html", src_ip=src_ip, alerts=source_alerts)


@app.route("/alert/<int:alert_id>", methods=["GET"])
def alert_detail(alert_id):
    # Charger les alertes depuis le fichier
    with open(alerts_file, "r") as f:
        alerts = json.load(f)

    # Trouver l'alerte avec l'ID correspondant
    alert = next((a for a in alerts if a["id"] == alert_id), None)

    if alert:
        return render_template("alert_detail.html", alert=alert)
    else:
        return "Alerte non trouvée", 404


# Filtre pour formater la date
@app.template_filter("datetimeformat")
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


# Route pour les Server-Sent Events
@app.route("/alerts")
def alerts():
    def generate():
        while True:
            alert = alert_queue.get()
            yield f"data: {json.dumps(alert)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


# Gestion des erreurs internes du serveur
@app.errorhandler(Exception)
def unhandled_exception(e):
    app.logger.error(f"Exception: {e}")
    return jsonify({"error": "Unhandled Exception"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
