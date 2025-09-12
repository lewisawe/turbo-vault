// Dashboard functionality
class Dashboard {
    constructor(app) {
        this.app = app;
        this.charts = {};
        this.refreshInterval = null;
    }

    async loadData() {
        try {
            await Promise.all([
                this.loadSystemStats(),
                this.loadSystemHealth(),
                this.loadRecentActivity(),
                this.initializeCharts()
            ]);
            
            this.startAutoRefresh();
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.app.showAlert('Failed to load dashboard data', 'error');
        }
    }

    async loadSystemStats() {
        try {
            const stats = await this.app.apiRequest('/system/stats');
            
            document.getElementById('totalSecrets').textContent = stats.secrets || 0;
            document.getElementById('totalPolicies').textContent = stats.policies || 0;
            document.getElementById('totalUsers').textContent = stats.users || 0;
            document.getElementById('uptime').textContent = this.app.formatDuration(stats.uptime || 0);
        } catch (error) {
            console.error('Error loading system stats:', error);
        }
    }

    async loadSystemHealth() {
        try {
            const health = await this.app.apiRequest('/system/health');
            
            this.updateHealthMetric('cpuUsage', 'cpuValue', health.cpu_usage || 0);
            this.updateHealthMetric('memoryUsage', 'memoryValue', health.memory_usage || 0);
            this.updateHealthMetric('storageUsage', 'storageValue', health.storage_usage || 0);
        } catch (error) {
            console.error('Error loading system health:', error);
        }
    }

    updateHealthMetric(barId, valueId, percentage) {
        const bar = document.getElementById(barId);
        const value = document.getElementById(valueId);
        
        if (bar && value) {
            bar.style.width = `${percentage}%`;
            value.textContent = `${Math.round(percentage)}%`;
            
            // Update color based on usage
            if (percentage > 90) {
                bar.style.background = '#dc3545';
            } else if (percentage > 70) {
                bar.style.background = '#ffc107';
            } else {
                bar.style.background = '#28a745';
            }
        }
    }

    async loadRecentActivity() {
        try {
            const activity = await this.app.apiRequest('/system/activity?limit=10');
            const container = document.getElementById('recentActivity');
            
            if (!container) return;
            
            container.innerHTML = '';
            
            if (activity.events && activity.events.length > 0) {
                activity.events.forEach(event => {
                    const item = this.createActivityItem(event);
                    container.appendChild(item);
                });
            } else {
                container.innerHTML = '<p class="text-muted">No recent activity</p>';
            }
        } catch (error) {
            console.error('Error loading recent activity:', error);
        }
    }

    createActivityItem(event) {
        const item = document.createElement('div');
        item.className = 'activity-item';
        
        const icon = this.getActivityIcon(event.type);
        const timeAgo = this.getTimeAgo(event.timestamp);
        
        item.innerHTML = `
            <div class="activity-icon">
                <i class="${icon}"></i>
            </div>
            <div class="activity-content">
                <div class="activity-title">${event.description}</div>
                <div class="activity-time">${timeAgo}</div>
            </div>
        `;
        
        return item;
    }

    getActivityIcon(eventType) {
        const icons = {
            'secret_access': 'fas fa-key',
            'secret_create': 'fas fa-plus',
            'secret_update': 'fas fa-edit',
            'secret_delete': 'fas fa-trash',
            'policy_change': 'fas fa-shield-alt',
            'user_login': 'fas fa-sign-in-alt',
            'system_start': 'fas fa-power-off',
            'backup_created': 'fas fa-save'
        };
        
        return icons[eventType] || 'fas fa-info-circle';
    }

    getTimeAgo(timestamp) {
        const now = new Date();
        const eventTime = new Date(timestamp);
        const diffMs = now - eventTime;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
    }

    async initializeCharts() {
        await Promise.all([
            this.initializeAccessChart(),
            this.initializePerformanceChart()
        ]);
    }

    async initializeAccessChart() {
        try {
            const data = await this.app.apiRequest('/analytics/access-patterns?period=24h');
            
            const ctx = document.getElementById('accessChart');
            if (!ctx) return;
            
            this.charts.access = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        label: 'Secret Accesses',
                        data: data.values || [],
                        borderColor: '#007bff',
                        backgroundColor: 'rgba(0, 123, 255, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Error initializing access chart:', error);
        }
    }

    async initializePerformanceChart() {
        try {
            const data = await this.app.apiRequest('/metrics/performance?period=1h');
            
            const ctx = document.getElementById('performanceChart');
            if (!ctx) return;
            
            this.charts.performance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: [
                        {
                            label: 'Response Time (ms)',
                            data: data.response_times || [],
                            borderColor: '#28a745',
                            backgroundColor: 'rgba(40, 167, 69, 0.1)',
                            yAxisID: 'y'
                        },
                        {
                            label: 'Requests/sec',
                            data: data.request_rates || [],
                            borderColor: '#ffc107',
                            backgroundColor: 'rgba(255, 193, 7, 0.1)',
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false,
                    },
                    scales: {
                        y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            title: {
                                display: true,
                                text: 'Response Time (ms)'
                            }
                        },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            title: {
                                display: true,
                                text: 'Requests/sec'
                            },
                            grid: {
                                drawOnChartArea: false,
                            },
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top'
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Error initializing performance chart:', error);
        }
    }

    updateMetrics(metrics) {
        // Update real-time metrics from WebSocket
        if (metrics.cpu_usage !== undefined) {
            this.updateHealthMetric('cpuUsage', 'cpuValue', metrics.cpu_usage);
        }
        
        if (metrics.memory_usage !== undefined) {
            this.updateHealthMetric('memoryUsage', 'memoryValue', metrics.memory_usage);
        }
        
        if (metrics.storage_usage !== undefined) {
            this.updateHealthMetric('storageUsage', 'storageValue', metrics.storage_usage);
        }
        
        // Update charts with new data points
        if (metrics.access_count && this.charts.access) {
            this.addDataPoint(this.charts.access, new Date().toLocaleTimeString(), metrics.access_count);
        }
        
        if (metrics.response_time && this.charts.performance) {
            const time = new Date().toLocaleTimeString();
            this.addDataPoint(this.charts.performance, time, metrics.response_time, 0);
            this.addDataPoint(this.charts.performance, time, metrics.request_rate, 1);
        }
    }

    addDataPoint(chart, label, value, datasetIndex = 0) {
        const maxPoints = 20;
        
        chart.data.labels.push(label);
        chart.data.datasets[datasetIndex].data.push(value);
        
        // Keep only the last N points
        if (chart.data.labels.length > maxPoints) {
            chart.data.labels.shift();
            chart.data.datasets[datasetIndex].data.shift();
        }
        
        chart.update('none');
    }

    startAutoRefresh() {
        // Refresh dashboard data every 30 seconds
        this.refreshInterval = setInterval(() => {
            this.loadSystemStats();
            this.loadSystemHealth();
            this.loadRecentActivity();
        }, 30000);
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    destroy() {
        this.stopAutoRefresh();
        
        // Destroy charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        
        this.charts = {};
    }
}

// Global functions for dashboard
function refreshDashboard() {
    if (window.dashboard) {
        window.dashboard.loadData();
    }
}

// Extend VaultApp to include dashboard functionality
VaultApp.prototype.loadDashboardData = async function() {
    if (!this.dashboard) {
        this.dashboard = new Dashboard(this);
    }
    
    await this.dashboard.loadData();
    window.dashboard = this.dashboard;
};

VaultApp.prototype.updateDashboardMetrics = function(metrics) {
    if (this.dashboard) {
        this.dashboard.updateMetrics(metrics);
    }
};