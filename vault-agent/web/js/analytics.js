// Analytics functionality
class AnalyticsManager {
    constructor(app) {
        this.app = app;
        this.charts = {};
    }

    async loadData() {
        try {
            await this.initializeCharts();
        } catch (error) {
            console.error('Error loading analytics data:', error);
            this.app.showAlert('Failed to load analytics data', 'error');
        }
    }

    async initializeCharts() {
        await Promise.all([
            this.initializeRequestVolumeChart(),
            this.initializeResponseTimeChart(),
            this.initializeErrorRateChart()
        ]);
    }

    async initializeRequestVolumeChart() {
        try {
            const data = await this.app.apiRequest('/analytics/request-volume?period=24h');
            const ctx = document.getElementById('requestVolumeChart');
            if (!ctx) return;
            
            this.charts.requestVolume = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        label: 'Requests',
                        data: data.values || [],
                        backgroundColor: 'rgba(0, 123, 255, 0.8)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        } catch (error) {
            console.error('Error initializing request volume chart:', error);
        }
    }

    async initializeResponseTimeChart() {
        try {
            const data = await this.app.apiRequest('/analytics/response-times?period=24h');
            const ctx = document.getElementById('responseTimeChart');
            if (!ctx) return;
            
            this.charts.responseTime = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        label: 'Response Time (ms)',
                        data: data.values || [],
                        borderColor: '#28a745',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        } catch (error) {
            console.error('Error initializing response time chart:', error);
        }
    }

    async initializeErrorRateChart() {
        try {
            const data = await this.app.apiRequest('/analytics/error-rates?period=24h');
            const ctx = document.getElementById('errorRateChart');
            if (!ctx) return;
            
            this.charts.errorRate = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        label: 'Error Rate (%)',
                        data: data.values || [],
                        borderColor: '#dc3545',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        } catch (error) {
            console.error('Error initializing error rate chart:', error);
        }
    }
}

// Global functions
function updateAnalytics() {
    if (window.analyticsManager) {
        window.analyticsManager.loadData();
    }
}

VaultApp.prototype.loadAnalyticsData = async function() {
    if (!this.analyticsManager) {
        this.analyticsManager = new AnalyticsManager(this);
    }
    await this.analyticsManager.loadData();
    window.analyticsManager = this.analyticsManager;
};