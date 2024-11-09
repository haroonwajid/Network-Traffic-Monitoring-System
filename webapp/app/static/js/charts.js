function initializeCharts() {
    // Protocol distribution chart
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    charts.protocol = new Chart(protocolCtx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56'
                ]
            }]
        }
    });

    // Traffic rate chart
    const trafficCtx = document.getElementById('trafficRateChart').getContext('2d');
    charts.traffic = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets per Second',
                data: [],
                borderColor: '#36A2EB',
                tension: 0.1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateCharts(data) {
    // Update protocol chart
    const protocols = data.protocol_stats.map(stat => stat[0]);
    const counts = data.protocol_stats.map(stat => stat[1]);
    
    charts.protocol.data.labels = protocols;
    charts.protocol.data.datasets[0].data = counts;
    charts.protocol.update();

    // Update traffic rate chart
    const timestamp = new Date().toLocaleTimeString();
    charts.traffic.data.labels.push(timestamp);
    charts.traffic.data.datasets[0].data.push(data.global_stats[1]);
    
    if (charts.traffic.data.labels.length > 60) {
        charts.traffic.data.labels.shift();
        charts.traffic.data.datasets[0].data.shift();
    }
    
    charts.traffic.update();
}

// Initialize charts when the page loads
document.addEventListener('DOMContentLoaded', initializeCharts); 