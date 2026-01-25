fetch("/api/dpi/packets?limit=100")
    .then(response => response.json())
    .then(data => {
        const tbody = document.querySelector("#packetsTable tbody");

        data.packets.forEach(packet => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${packet.timestamp ?? ""}</td>
                <td>${packet.src_ip ?? ""}</td>
                <td>${packet.dst_ip ?? ""}</td>
                <td>${packet.protocol ?? ""}</td>
                <td>${packet.src_port ?? ""}</td>
                <td>${packet.dst_port ?? ""}</td>
                <td>${packet.payload_size ?? ""}</td>
                <td>${packet.threat_level ?? "none"}</td>
                <td>${packet.threat_score ?? 0}</td>
            `;

            tbody.appendChild(row);
        });
    })
    .catch(err => {
        console.error("Error loading packets:", err);
    });
