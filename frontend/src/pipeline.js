/**
 * pipeline.js — 10-stage pipeline visualization with animated data packets.
 * Shows both normal (green) and threat (red) flows with stage-by-stage animation.
 */

// Pipeline stage definitions
const STAGES = [
  { name: 'Network / Apps', icon: '🌐', isReal: false },
  { name: 'Zeek / Suricata', icon: '🛡️', isReal: false },
  { name: 'Elastic Beats', icon: '📊', isReal: false },
  { name: 'Apache Kafka', icon: '⚡', isReal: true },
  { name: 'AI Engine', icon: '🧠', isReal: true },
  { name: 'SOAR', icon: '🔄', isReal: false },
  { name: 'Vault', icon: '🔐', isReal: true },
  { name: 'Cred Rotation', icon: '🔑', isReal: false },
  { name: 'Cred Distributed', icon: '📤', isReal: false },
  { name: 'ELK / Grafana', icon: '📈', isReal: true },
];

let currentAnimation = null;

const STAGE_EXPLANATIONS = [
  "We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.",
  "Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).",
  "To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.",
  "To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as a buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.",
  "The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on an AI ensemble (XGBoost, LightGBM, and Isolation Forest) to predict if an event is a novel threat.",
  "If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human, it automatically triggers incident response playbooks—like isolating machines or initiating password resets.",
  "As part of the automated response, HashiCorp Vault is engaged to secure our infrastructure. Vault manages dynamic secrets; when a threat is detected, it receives an API command to immediately begin revoking compromised access.",
  "Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services, effectively locking the attacker out.",
  "Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets to our servers and microservices using encrypted tunnels (TLS), restoring security without taking the system offline.",
  "Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana or Grafana."
];

/**
 * Render the static pipeline structure
 */
export function renderPipeline(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  let html = '<div class="pipeline-flow">';

  STAGES.forEach((stage, idx) => {
    // Node
    html += `
      <div class="pipeline-node" id="pipeline-node-${idx}" data-stage="${idx}" title="Click to view details">
        <div class="node-icon-wrapper ${stage.isReal ? 'real-tool' : ''}">
          <span class="node-icon">${stage.icon}</span>
        </div>
        <span class="node-name">${stage.name}</span>
        <span class="node-latency" id="node-latency-${idx}">--ms</span>
      </div>
    `;

    // Connector (except after last node)
    if (idx < STAGES.length - 1) {
      html += `<div class="pipeline-connector" id="connector-${idx}"></div>`;
    }
  });

  html += '</div>';

  // Event log
  html += `
    <div class="pipeline-event-log" id="pipeline-event-log">
      <div style="text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 12px; padding: var(--space-lg);">
        Waiting for events...
      </div>
    </div>
  `;

  container.innerHTML = html;

  // Bind click listeners for modals
  STAGES.forEach((_, idx) => {
    const el = document.getElementById(`pipeline-node-${idx}`);
    if (el) {
      el.addEventListener('click', () => showStageModal(idx));
    }
  });

  // Setup modal close handlers
  const modal = document.getElementById('stage-modal');
  const btn = document.getElementById('stage-modal-close');
  if (btn) btn.addEventListener('click', () => modal.style.display = 'none');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
  }
}

function showStageModal(idx) {
  const modal = document.getElementById('stage-modal');
  const header = document.getElementById('stage-modal-header');
  const body = document.getElementById('stage-modal-body');
  
  if (!modal || !header || !body) return;

  const stage = STAGES[idx];
  header.innerHTML = `<span style="margin-right: 8px;">${stage.icon}</span> ${stage.name}`;
  body.textContent = STAGE_EXPLANATIONS[idx];

  modal.style.display = 'flex';
}

/**
 * Animate Vault Credential Rotation Terminal
 */
async function animateVaultRotation(prediction) {
  const terminal = document.getElementById('vault-terminal');
  const body = document.getElementById('vault-terminal-body');
  if (!terminal || !body) return;

  terminal.style.display = 'block';
  body.innerHTML = '';

  const lines = [
    { text: '> Initializing Vault connection via API...', delay: 400, class: '' },
    { text: '[OK] Vault authenticated. Protocol: TLS 1.3', delay: 300, class: 'success' },
    { text: `> Analyzing threat vector. Score: ${(prediction.threat_score * 100).toFixed(1)}%`, delay: 500, class: 'warning' },
    { text: '> Revoking compromised service tokens...', delay: 600, class: '' },
    { text: '[OK] Tokens revoked successfully.', delay: 200, class: 'success' },
    { text: '> Generating secure DB credentials (AES-256)...', delay: 700, class: '' },
    { text: '[OK] db_password updated.', delay: 200, class: 'success' },
    { text: '> Rotating API keys for Microservices...', delay: 500, class: '' },
    { text: '[OK] api_gateway, service_mesh credentials synced.', delay: 200, class: 'success' },
    { text: '> SECURE POSTURE RESTORED.', delay: 800, class: 'success' }
  ];

  for (const line of lines) {
    const el = document.createElement('div');
    el.className = `terminal-line ${line.class}`;
    el.textContent = line.text;
    body.appendChild(el);
    await sleep(line.delay);
  }

  await sleep(1500);
  terminal.style.display = 'none';
}

/**
 * Animate a single event flowing through the pipeline
 */
export async function animatePipelineEvent(predictionResult) {
  const stages = predictionResult?.pipeline_stages || [];
  const isThreat = predictionResult?.is_threat || false;
  const threatAction = predictionResult?.threat_action || 'ALLOW';
  const summary = predictionResult?.event_summary || {};

  // Reset all nodes
  resetPipeline();

  // Determine how far the packet travels
  const threatDetectionStage = 4; // AI Engine index

  for (let i = 0; i < STAGES.length; i++) {
    const node = document.getElementById(`pipeline-node-${i}`);
    const connector = document.getElementById(`connector-${i}`);
    const latencyEl = document.getElementById(`node-latency-${i}`);

    if (!node) continue;

    // Determine packet color at this stage
    const isRed = isThreat && i >= threatDetectionStage;

    // Activate node
    node.classList.add(isRed ? 'threat' : 'active');

    // Update latency
    if (latencyEl && stages[i]) {
      latencyEl.textContent = `${stages[i].latency_ms?.toFixed(1) || '--'}ms`;
    }

    // Trigger Vault specific visualization on Stage 6
    if (i === 6 && isThreat) {
      await animateVaultRotation(predictionResult);
    }

    // Animate connector (data packet traveling)
    if (connector) {
      connector.classList.add(isRed ? 'threat' : 'active');

      // Create traveling packet
      const packet = document.createElement('div');
      packet.className = `data-packet ${isRed ? 'threat' : 'safe'}`;
      connector.appendChild(packet);

      await sleep(120);

      // Remove packet after animation
      setTimeout(() => packet.remove(), 800);
    }

    await sleep(100);
  }

  // Show result banner
  showResultBanner(isThreat, threatAction);

  // Add to event log
  addEventToLog(predictionResult);
}

/**
 * Reset pipeline visual state
 */
function resetPipeline() {
  STAGES.forEach((_, idx) => {
    const node = document.getElementById(`pipeline-node-${idx}`);
    const connector = document.getElementById(`connector-${idx}`);
    const latencyEl = document.getElementById(`node-latency-${idx}`);

    if (node) {
      node.classList.remove('active', 'threat');
    }
    if (connector) {
      connector.classList.remove('active', 'threat');
    }
    if (latencyEl) {
      latencyEl.textContent = '--ms';
    }
  });
}

/**
 * Show a result status banner
 */
function showResultBanner(isThreat, action) {
  // Remove existing banner
  const existing = document.querySelector('.result-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.className = `result-banner ${isThreat ? 'neutralized' : 'secured'}`;
  banner.textContent = isThreat
    ? `⚠ THREAT NEUTRALIZED — ${action}`
    : '✓ SECURED — TRAFFIC ALLOWED';

  document.body.appendChild(banner);

  setTimeout(() => banner.remove(), 3000);
}

/**
 * Add an event entry to the pipeline log
 */
function addEventToLog(prediction) {
  const log = document.getElementById('pipeline-event-log');
  if (!log) return;

  // Clear placeholder
  if (log.querySelector('[style*="Waiting"]')) {
    log.innerHTML = '';
  }

  const summary = prediction.event_summary || {};
  const action = prediction.threat_action || 'ALLOW';
  const score = prediction.threat_score || 0;

  const badgeClass = action === 'ALLOW' ? 'allow'
    : action === 'MONITOR' ? 'monitor'
    : action === 'BLOCK' ? 'block'
    : 'critical';

  const entry = document.createElement('div');
  entry.className = 'pipeline-event';
  entry.innerHTML = `
    <span class="event-badge ${badgeClass}">${action}</span>
    <span class="event-user">${summary.user || 'unknown'}</span>
    <span class="event-ip">${summary.source_ip || '--'}</span>
    <span class="event-process">${summary.process_name || '--'}</span>
    <span class="event-score">${(score * 100).toFixed(1)}%</span>
    <span class="event-time">${new Date().toLocaleTimeString()}</span>
  `;

  log.insertBefore(entry, log.firstChild);

  // Keep max 50 entries
  while (log.children.length > 50) {
    log.removeChild(log.lastChild);
  }
}

/**
 * Update pipeline stage latencies from live data
 */
export function updateStageLatencies(stages) {
  if (!stages) return;
  stages.forEach((stage, idx) => {
    const el = document.getElementById(`node-latency-${idx}`);
    if (el) {
      el.textContent = `${stage.latency_ms?.toFixed(1) || '--'}ms`;
    }
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
