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
  vaultRotationCount: 0,
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

    <div style="display: flex; gap: var(--space-2xl); margin-top: var(--space-2xl);">
        
        <!-- Left Column: Models & Vault -->
        <div style="flex: 1;">
            <!-- Model Performance -->
            <div>
              <div class="section-title">Model Performance</div>
              <div class="model-perf-grid">
                <div class="perf-card">
                  <div class="perf-card-title">XGBoost Prob</div>
                  <div class="perf-card-value" id="perf-xgb">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">LightGBM Prob</div>
                  <div class="perf-card-value" id="perf-lgb">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">Ensemble Score</div>
                  <div class="perf-card-value" id="perf-ens">--</div>
                </div>
                <div class="perf-card">
                  <div class="perf-card-title">Threshold</div>
                  <div class="perf-card-value" id="perf-thr" style="color: var(--amber);">--</div>
                </div>
              </div>
            </div>

            <!-- Vault Credentials -->
            <div style="margin-top: var(--space-2xl);">
              <div class="section-title">HashiCorp Vault Credentials</div>
              <div class="vault-card" id="vault-card" style="background: rgba(20, 20, 25, 0.8); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: var(--space-lg); transition: all 0.3s ease;">
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">DB_PASSWORD</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-db-pw">****</div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">API_KEY</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-api-key">****</div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: var(--space-md);">
                    <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">SERVICE_TOKEN</div>
                    <div style="color: var(--cyan); font-family: var(--font-mono);" id="vault-svc-token">****</div>
                </div>
                <div style="border-top: 1px solid var(--border-color); margin-top: var(--space-md); padding-top: var(--space-md); display: flex; justify-content: space-between;">
                    <div style="color: var(--text-muted); font-size: 12px;">Rotations: <span id="vault-rotations" style="color: var(--magenta); font-weight: 600;">0</span></div>
                    <div style="color: var(--text-muted); font-size: 12px;">Last Reason: <span id="vault-reason" style="color: var(--amber);">none</span></div>
                </div>
              </div>
            </div>
            
            <!-- Attack Type Breakdown -->
            <div style="margin-top: var(--space-2xl);">
              <div class="section-title">Attack Type Breakdown</div>
              <div id="attack-breakdown" style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-sm); font-family: var(--font-mono); font-size: 12px;">
                <!-- Filled dynamically -->
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
        </div>

        <!-- Right Column: Threat Feed -->
        <div style="flex: 2;">
            <div class="threat-feed" id="threat-feed" style="height: 100%;">
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
        
    </div>
  `;
  
  // Start polling vault credentials
  setInterval(updateVaultCredentials, 5000);
  updateVaultCredentials();

  // Initialize dashboard counters from backend metrics (persist across reloads)
  initDashboardFromBackend();
}

/**
 * Initialize dashboard state from backend metrics so counters persist across reloads
 */
async function initDashboardFromBackend() {
  try {
    const res = await fetch('/api/metrics');
    if (!res.ok) return;
    const data = await res.json();

    state.totalProcessed = data.total_requests || 0;
    state.totalThreats = data.total_threats || 0;
    state.totalAllowed = data.total_allowed || 0;
    state.totalBlocked = (data.total_blocked || 0) + (data.total_critical || 0);
    state.avgLatency = data.avg_latency_ms || 0;
    state.latencySum = state.avgLatency * state.totalProcessed;
    state.attackTypes = data.attack_types || {};

    // Update all metric cards
    updateElement('metric-total', state.totalProcessed.toLocaleString());
    updateElement('metric-threats', state.totalThreats.toLocaleString());
    updateElement('metric-allowed', state.totalAllowed.toLocaleString());
    updateElement('metric-blocked', state.totalBlocked.toLocaleString());
    updateElement('metric-latency', `${state.avgLatency.toFixed(1)}ms`);

    const rate = state.totalProcessed > 0
      ? ((state.totalProcessed - state.totalThreats) / state.totalProcessed * 100)
      : 100;
    updateElement('metric-rate', `${rate.toFixed(1)}%`);

    // Rebuild attack breakdown chart
    if (Object.keys(state.attackTypes).length > 0) {
      updateAttackBreakdown();
    }

    console.log(`[HPE] Dashboard initialized: ${state.totalProcessed} events, ${state.totalThreats} threats`);
  } catch (e) {
    console.warn('[HPE] Could not fetch backend metrics for dashboard init');
  }
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

    // Track attack types
    const aType = prediction.event_summary?.anomaly_type || 'Unknown';
    if (!state.attackTypes[aType]) state.attackTypes[aType] = 0;
    state.attackTypes[aType]++;
    updateAttackBreakdown();

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
  
  // Update recent model scores from prediction
  if (prediction.xgb_score !== undefined) {
      updateElement('perf-xgb', (prediction.xgb_score || 0).toFixed(4));
      updateElement('perf-lgb', (prediction.lgb_score || 0).toFixed(4));
      updateElement('perf-ens', (prediction.ensemble_score || 0).toFixed(4));
      updateElement('perf-thr', (prediction.threshold || 0.5).toFixed(4));
  }
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
 * Update Vault Credentials
 */
async function updateVaultCredentials() {
    try {
        const res = await fetch('/api/vault/credentials');
        if (!res.ok) return;
        const data = await res.json();
        
        if (data.error) return;
        
        updateElement('vault-db-pw', data.db_password);
        updateElement('vault-api-key', data.api_key);
        updateElement('vault-svc-token', data.service_token);
        updateElement('vault-reason', data.rotation_reason);
        
        const newCount = data.rotation_count || 0;
        if (newCount > state.vaultRotationCount) {
            // Flash the card red on rotation
            const card = document.getElementById('vault-card');
            if (card) {
                card.style.borderColor = 'var(--magenta)';
                card.style.boxShadow = '0 0 15px rgba(233, 69, 96, 0.5)';
                setTimeout(() => {
                    card.style.borderColor = 'var(--border-color)';
                    card.style.boxShadow = 'none';
                }, 1500);
            }
            state.vaultRotationCount = newCount;
        }
        updateElement('vault-rotations', state.vaultRotationCount.toString());
        
    } catch(e) {
        // Ignore
    }
}

function updateAttackBreakdown() {
    const container = document.getElementById('attack-breakdown');
    if (!container) return;
    
    const types = Object.entries(state.attackTypes).sort((a, b) => b[1] - a[1]);
    
    container.innerHTML = types.map(([type, count]) => `
        <div style="display: flex; justify-content: space-between; background: rgba(0,0,0,0.2); padding: 4px 8px; border-radius: 4px;">
            <span style="color: var(--text-secondary);">${type}</span>
            <span style="color: var(--magenta);">${count}</span>
        </div>
    `).join('');
}


/**
 * Update model performance metrics from API (kept for backwards compatibility)
 * In v2, model scores are updated inline from each prediction result.
 */
export async function updateModelMetrics() {
  // No-op: model scores are now updated per-event in updateDashboard()
}


// ── Helpers ───────────────────────────────────────────────────────────────

function updateThreatFeed() {
  const list = document.getElementById('threat-feed-list');
  if (!list) return;

  if (state.threatFeed.length === 0) return;

  list.innerHTML = state.threatFeed.slice(0, 20).map(threat => {
    const severity = threat.threat_score > 0.9 ? 'critical' : 'high';
    const summary = threat.event_summary || {};
    const aType = summary.anomaly_type && summary.anomaly_type !== 'None' ? summary.anomaly_type : 'BLOCK';
    return `
      <div class="threat-item ${severity}">
        <span class="event-badge ${severity === 'critical' ? 'critical' : 'block'}">
          ${aType}
        </span>
        <span style="color: var(--text-primary); min-width: 100px;">${summary.user || 'unknown'}</span>
        <span style="color: var(--cyan-dim); min-width: 90px;">${summary.source_ip || '--'}</span>
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
