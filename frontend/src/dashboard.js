/**
 * dashboard.js — Real-time metrics, threat feed, and model performance display.
 */

// Live counters
const state = {
  totalProcessed: 0,
  totalThreats: 0,
  totalAllowed: 0,
  totalBlocked: 0,
  avgLatency: 0,
  latencySum: 0,
  threatFeed: [],
  attackTypes: {},
};

/**
 * Render the dashboard layout
 */
export function renderDashboard(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <!-- Metrics Cards -->
    <div class="dashboard-grid">
      <div class="metric-card">
        <div class="metric-label">Total Processed</div>
        <div class="metric-value cyan" id="metric-total">0</div>
        <div class="metric-change">Events through pipeline</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Threats Detected</div>
        <div class="metric-value magenta" id="metric-threats">0</div>
        <div class="metric-change">Anomalies identified by AI</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Allowed</div>
        <div class="metric-value lime" id="metric-allowed">0</div>
        <div class="metric-change">Safe connections passed</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Blocked / Critical</div>
        <div class="metric-value magenta" id="metric-blocked">0</div>
        <div class="metric-change">Threats neutralized</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Avg Latency</div>
        <div class="metric-value amber" id="metric-latency">0ms</div>
        <div class="metric-change">Pipeline processing time</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Detection Rate</div>
        <div class="metric-value lime" id="metric-rate">100%</div>
        <div class="metric-change">Model accuracy (F1)</div>
      </div>
    </div>

    <!-- Model Performance -->
    <div style="margin-top: var(--space-2xl);">
      <div class="section-title">Model Performance</div>
      <div class="model-perf-grid">
        <div class="perf-card">
          <div class="perf-card-title">XGBoost F1</div>
          <div class="perf-card-value" id="perf-xgb">1.0000</div>
        </div>
        <div class="perf-card">
          <div class="perf-card-title">LightGBM F1</div>
          <div class="perf-card-value" id="perf-lgb">--</div>
        </div>
        <div class="perf-card">
          <div class="perf-card-title">Ensemble F1</div>
          <div class="perf-card-value" id="perf-ens">1.0000</div>
        </div>
        <div class="perf-card">
          <div class="perf-card-title">Threshold</div>
          <div class="perf-card-value" id="perf-thr" style="color: var(--amber);">--</div>
        </div>
      </div>
    </div>

    <!-- Pipeline Health -->
    <div style="margin-top: var(--space-2xl);">
      <div class="section-title">Infrastructure Health</div>
      <div class="pipeline-health-grid" id="health-grid">
        <div class="health-item">
          <div class="status-dot" id="health-kafka"></div>
          <span>Kafka</span>
        </div>
        <div class="health-item">
          <div class="status-dot" id="health-es"></div>
          <span>Elasticsearch</span>
        </div>
        <div class="health-item">
          <div class="status-dot" id="health-vault"></div>
          <span>Vault</span>
        </div>
        <div class="health-item">
          <div class="status-dot" id="health-model"></div>
          <span>AI Model</span>
        </div>
      </div>
    </div>

    <!-- Threat Feed -->
    <div style="margin-top: var(--space-2xl);">
      <div class="threat-feed" id="threat-feed">
        <div class="threat-feed-header">
          <span class="threat-feed-title">Live Threat Feed</span>
          <span class="live-badge">LIVE</span>
        </div>
        <div id="threat-feed-list">
          <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 12px; padding: var(--space-lg);">
            No threats detected yet
          </div>
        </div>
      </div>
    </div>
  `;
}

/**
 * Update dashboard with a new prediction result
 */
export function updateDashboard(prediction) {
  state.totalProcessed++;
  state.latencySum += prediction.total_latency_ms || 0;
  state.avgLatency = state.latencySum / state.totalProcessed;

  if (prediction.is_threat) {
    state.totalThreats++;
    state.totalBlocked++;

    // Add to threat feed
    state.threatFeed.unshift({
      ...prediction,
      time: new Date().toLocaleTimeString(),
    });
    if (state.threatFeed.length > 30) state.threatFeed.pop();
  } else {
    state.totalAllowed++;
  }

  // Update metric cards
  updateElement('metric-total', state.totalProcessed.toLocaleString());
  updateElement('metric-threats', state.totalThreats.toLocaleString());
  updateElement('metric-allowed', state.totalAllowed.toLocaleString());
  updateElement('metric-blocked', state.totalBlocked.toLocaleString());
  updateElement('metric-latency', `${state.avgLatency.toFixed(1)}ms`);

  const rate = state.totalProcessed > 0
    ? ((state.totalAllowed / state.totalProcessed) * 100).toFixed(1)
    : '100';
  updateElement('metric-rate', `${rate}%`);

  // Update threat feed display
  updateThreatFeed();
}

/**
 * Update health indicators from API
 */
export async function updateHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();

    setHealthDot('health-kafka', data.kafka_connected);
    setHealthDot('health-es', data.elasticsearch_connected);
    setHealthDot('health-vault', data.vault_connected);
    setHealthDot('health-model', data.model_loaded);
  } catch (e) {
    // Backend not available
    setHealthDot('health-kafka', false);
    setHealthDot('health-es', false);
    setHealthDot('health-vault', false);
    setHealthDot('health-model', false);
  }
}

/**
 * Update model performance metrics from API
 */
export async function updateModelMetrics() {
  try {
    const res = await fetch('/api/metrics');
    if (!res.ok) return;
    const data = await res.json();

    if (data.model_metrics) {
      updateElement('perf-xgb', (data.model_metrics.xgboost_f1 || 0).toFixed(4));
      updateElement('perf-lgb', (data.model_metrics.lightgbm_f1 || 0).toFixed(4));
      updateElement('perf-ens', (data.model_metrics.ensemble_f1 || 0).toFixed(4));
    }
  } catch (e) {
    // Backend not available
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function updateThreatFeed() {
  const list = document.getElementById('threat-feed-list');
  if (!list) return;

  if (state.threatFeed.length === 0) return;

  list.innerHTML = state.threatFeed.slice(0, 20).map(threat => {
    const severity = threat.threat_score > 0.9 ? 'critical' : 'high';
    const summary = threat.event_summary || {};
    return `
      <div class="threat-item ${severity}">
        <span class="event-badge ${severity === 'critical' ? 'critical' : 'block'}">
          ${threat.threat_action || 'BLOCK'}
        </span>
        <span style="color: var(--text-primary); min-width: 100px;">${summary.user || 'unknown'}</span>
        <span style="color: var(--cyan-dim); min-width: 90px;">${summary.source_ip || '--'}</span>
        <span style="color: var(--text-secondary); flex: 1;">${summary.process_name || '--'}</span>
        <span style="color: var(--magenta); min-width: 60px;">${((threat.threat_score || 0) * 100).toFixed(1)}%</span>
        <span style="color: var(--text-muted); min-width: 70px;">${threat.time}</span>
      </div>
    `;
  }).join('');
}

function updateElement(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setHealthDot(id, isHealthy) {
  const dot = document.getElementById(id);
  if (!dot) return;
  dot.className = `status-dot ${isHealthy ? '' : 'danger'}`;
}
