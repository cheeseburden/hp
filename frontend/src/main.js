/**
 * main.js — HPE Threat Detection Pipeline — Application Entry Point
 * Orchestrates globe, pipeline, dashboard, and WebSocket simulation.
 */

import './styles/index.css';
import { initGlobe, addArc } from './globe.js';
import { renderPipeline, animatePipelineEvent } from './pipeline.js';
import { renderDashboard, updateDashboard, updateHealth, updateModelMetrics } from './dashboard.js';
import { initStarField } from './effects.js';

// ── State ─────────────────────────────────────────────────────────────────────
let ws = null;
let isSimulating = false;
let eventQueue = [];
let processingEvent = false;

// ── Initialize Application ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  console.log('[HPE] Initializing Threat Detection Pipeline...');

  // Init star field background
  initStarField('globe-section');

  // Init 3D Globe
  initGlobe('globe-container');

  // Render pipeline structure
  renderPipeline('pipeline-content');

  // Render dashboard
  renderDashboard('dashboard-content');

  // Start health polling
  updateHealth();
  updateModelMetrics();
  setInterval(updateHealth, 10000);
  setInterval(updateModelMetrics, 30000);

  // Section navigation
  setupSectionNav();

  // Connect WebSocket for simulation
  connectSimulation();

  // Start processing event queue
  processEventQueue();

  console.log('[HPE] Initialization complete');
});

// ── WebSocket Simulation ──────────────────────────────────────────────────────
function connectSimulation() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/simulate`;

  console.log(`[HPE] Connecting to WebSocket: ${wsUrl}`);

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[HPE] WebSocket connected — simulation started');
      isSimulating = true;
      updateConnectionStatus(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleSimulationMessage(data);
      } catch (e) {
        console.error('[HPE] Failed to parse message:', e);
      }
    };

    ws.onclose = () => {
      console.log('[HPE] WebSocket disconnected');
      isSimulating = false;
      updateConnectionStatus(false);

      // Reconnect after 5 seconds
      setTimeout(connectSimulation, 5000);
    };

    ws.onerror = (err) => {
      console.error('[HPE] WebSocket error:', err);
      updateConnectionStatus(false);

      // Fallback: load sample events and simulate locally
      setTimeout(() => {
        if (!isSimulating) {
          loadAndSimulateLocally();
        }
      }, 3000);
    };
  } catch (e) {
    console.error('[HPE] WebSocket connection failed:', e);
    // Fallback
    setTimeout(loadAndSimulateLocally, 2000);
  }
}

function handleSimulationMessage(message) {
  switch (message.type) {
    case 'server_info':
      console.log('[HPE] Server info:', message.data);
      break;

    case 'pipeline_result':
      // Queue the event for sequential processing
      eventQueue.push(message.data);
      break;

    case 'error':
      console.error('[HPE] Simulation error:', message.data);
      break;
  }
}

// ── Event Queue Processing ───────────────────────────────────────────────────
async function processEventQueue() {
  while (true) {
    if (eventQueue.length > 0 && !processingEvent) {
      processingEvent = true;
      const data = eventQueue.shift();

      try {
        const event = data.event;
        const prediction = data.prediction;

        // Update globe with arc
        addArc(event, prediction);

        // Animate pipeline
        await animatePipelineEvent(prediction);

        // Update dashboard
        updateDashboard(prediction);

        // Update HUD
        updateGlobeHUD(prediction);

      } catch (e) {
        console.error('[HPE] Event processing error:', e);
      }

      processingEvent = false;
    }

    await sleep(100);
  }
}

// ── Local Simulation Fallback ─────────────────────────────────────────────────
async function loadAndSimulateLocally() {
  console.log('[HPE] Loading sample events for local simulation...');

  try {
    const res = await fetch('/api/sample-events');
    if (!res.ok) {
      console.error('[HPE] Failed to load sample events, using internal demo');
      startInternalDemo();
      return;
    }

    const data = await res.json();
    const normal = data.sample_normal || [];
    const attack = data.sample_attack || [];
    const allEvents = [...normal, ...attack];

    if (allEvents.length === 0) {
      startInternalDemo();
      return;
    }

    console.log(`[HPE] Local simulation with ${allEvents.length} events`);

    // Simulate by posting to predict endpoint
    let idx = 0;
    isSimulating = true;

    const simulate = async () => {
      if (!isSimulating) return;

      const event = allEvents[idx % allEvents.length];
      idx++;

      try {
        const res = await fetch('/api/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(event),
        });

        if (res.ok) {
          const prediction = await res.json();
          eventQueue.push({ event, prediction });
        }
      } catch (e) {
        console.error('[HPE] Local sim error:', e);
      }

      setTimeout(simulate, Math.random() * 2000 + 1000);
    };

    simulate();
  } catch (e) {
    console.error('[HPE] Local simulation failed:', e);
    startInternalDemo();
  }
}

// ── Internal Demo (no backend) ────────────────────────────────────────────────
function startInternalDemo() {
  console.log('[HPE] Starting internal demo mode (no backend)');

  const demoEvents = [
    { user: 'john.smith', source_ip: '10.2.3.50', destination_ip: '10.1.0.10', event_type: 'network_connection', process_name: 'chrome.exe', hostname: 'WS-NYC-001' },
    { user: 'svc_backup', source_ip: '10.3.1.20', destination_ip: '10.1.0.5', event_type: 'process_start', process_name: 'backup_agent.exe', hostname: 'SRV-SF-010' },
    { user: 'alice.wong', source_ip: '10.4.2.100', destination_ip: '10.1.0.15', event_type: 'file_access', process_name: 'explorer.exe', hostname: 'WS-LDN-022' },
    { user: 'daniel.davis004', source_ip: '10.2.3.69', destination_ip: '10.1.0.10', event_type: 'network_connection', process_name: 'powershell.exe', hostname: 'WS-SAL-0005', command_line: 'Test-NetConnection -ComputerName app_db -Port 1433' },
  ];

  const geoMap = {
    '10.1.': { lat: 12.97, lng: 77.59, city: 'Bangalore' },
    '10.2.': { lat: 40.71, lng: -74.01, city: 'New York' },
    '10.3.': { lat: 37.77, lng: -122.42, city: 'San Francisco' },
    '10.4.': { lat: 51.51, lng: -0.13, city: 'London' },
  };

  function ipToGeo(ip) {
    for (const [prefix, geo] of Object.entries(geoMap)) {
      if (ip && ip.startsWith(prefix)) return geo;
    }
    return { lat: 0, lng: 0, city: 'Unknown' };
  }

  let idx = 0;
  const runDemo = () => {
    const event = demoEvents[idx % demoEvents.length];
    const isThreat = event.process_name === 'powershell.exe' && event.command_line;

    const prediction = {
      event_id: `demo-${idx}`,
      is_threat: isThreat,
      threat_score: isThreat ? 0.95 : Math.random() * 0.1,
      threat_action: isThreat ? 'BLOCK' : 'ALLOW',
      xgb_score: isThreat ? 0.98 : Math.random() * 0.05,
      lgb_score: isThreat ? 0.92 : Math.random() * 0.08,
      ensemble_score: isThreat ? 0.95 : Math.random() * 0.06,
      threshold: 1.0,
      source_geo: ipToGeo(event.source_ip),
      destination_geo: ipToGeo(event.destination_ip),
      pipeline_stages: Array.from({ length: 10 }, (_, i) => ({
        stage_name: `Stage ${i + 1}`,
        latency_ms: Math.random() * 5 + 0.5,
        status: 'completed',
      })),
      total_latency_ms: Math.random() * 30 + 10,
      timestamp: new Date().toISOString(),
      event_summary: event,
    };

    eventQueue.push({ event, prediction });
    idx++;
    setTimeout(runDemo, Math.random() * 3000 + 1500);
  };

  runDemo();
}

// ── Globe HUD Updates ─────────────────────────────────────────────────────────
let hudTotalEvents = 0;
let hudTotalThreats = 0;

function updateGlobeHUD(prediction) {
  hudTotalEvents++;
  if (prediction.is_threat) hudTotalThreats++;

  const totalEl = document.getElementById('hud-event-count');
  const threatEl = document.getElementById('hud-threat-count');
  const levelEl = document.getElementById('hud-threat-level');
  const levelFill = document.getElementById('threat-level-fill');

  if (totalEl) totalEl.textContent = hudTotalEvents.toLocaleString();
  if (threatEl) threatEl.textContent = hudTotalThreats.toLocaleString();

  const threatPercent = hudTotalEvents > 0 ? (hudTotalThreats / hudTotalEvents * 100) : 0;
  if (levelEl) {
    if (threatPercent > 10) {
      levelEl.textContent = 'CRITICAL';
      levelEl.className = 'hud-value danger';
    } else if (threatPercent > 5) {
      levelEl.textContent = 'ELEVATED';
      levelEl.className = 'hud-value';
      levelEl.style.color = 'var(--amber)';
    } else {
      levelEl.textContent = 'NOMINAL';
      levelEl.className = 'hud-value success';
    }
  }
  if (levelFill) {
    levelFill.style.width = `${Math.min(threatPercent * 5, 100)}%`;
  }
}

function updateConnectionStatus(connected) {
  const dot = document.getElementById('status-ws-dot');
  const text = document.getElementById('status-ws-text');
  if (dot) dot.className = `status-dot ${connected ? '' : 'warning'}`;
  if (text) text.textContent = connected ? 'SYSTEM LIVE' : 'LOCAL SIMULATION';
}

// ── Section Navigation ───────────────────────────────────────────────────────
function setupSectionNav() {
  const dots = document.querySelectorAll('.section-nav-dot');
  const sections = ['globe-section', 'pipeline-section', 'dashboard-section'];

  dots.forEach((dot, idx) => {
    dot.addEventListener('click', () => {
      const section = document.getElementById(sections[idx]);
      if (section) section.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Intersection observer for active dot
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const idx = sections.indexOf(entry.target.id);
          dots.forEach((d, i) => d.classList.toggle('active', i === idx));
        }
      });
    },
    { threshold: 0.5 }
  );

  sections.forEach(id => {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  });
}

// ── Utility ──────────────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
