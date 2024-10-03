document.addEventListener("DOMContentLoaded", function () {
  var source = new EventSource("/alerts");
  var alertsList = document.getElementById("alerts");

  source.onmessage = function (event) {
    var alert = JSON.parse(event.data);

    var li = document.createElement("li");
    li.textContent = `${alert.type} détecté de ${alert.src_ip || "N/A"} à ${
      alert.dst_ip || "N/A"
    } le ${new Date(alert.timestamp * 1000).toLocaleString()}`;
    alertsList.appendChild(li);
  };
});
