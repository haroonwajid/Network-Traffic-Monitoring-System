const socket = io();
let charts = {};

socket.on('connect', () => {
    console.log('Connected to server');
    requestMetrics();
});

socket.on('metrics_update', (data) => {
    updateDashboard(data);
});

function requestMetrics() {
    socket.emit('request_metrics');
    setTimeout(requestMetrics, 1000); // Request updates every second
}

function updateDashboard(data) {
    // Update global stats
    document.getElementById('totalPackets').textContent = data.global_stats[0];
    document.getElementById('packetsPerSecond').textContent = 
        data.global_stats[1].toFixed(2);

    // Update charts
    updateCharts(data);
    
    // Update connections table
    updateConnectionsTable(data.connection_stats);
} 