async function fetchLogs() {
    try {
        const response = await fetch("/api/attacks"); // Fetch logs from Express API
        if (!response.ok) throw new Error("Failed to fetch logs");

        const data = await response.json();
        const tableBody = document.getElementById("attack-log");
        tableBody.innerHTML = "";

        data.forEach(log => {
            const row = `<tr>
                <td>${new Date(log.Timestamp * 1000).toLocaleString()}</td>
                <td>${log.Src_IP}</td>
                <td>${log.Attack_Type}</td>
                <td>${log.Src_Port}</td>
                <td>${log.Dst_IP}</td>
                <td>${log.Dst_Port}</td>
            </tr>`;
            tableBody.innerHTML += row;
        });
    } catch (error) {
        console.error("Error fetching logs:", error);
    }
}

// Refresh data every 5 seconds
setInterval(fetchLogs, 5000);
fetchLogs();
