'use strict';

/* ================================================================
   app.js — Sidebar state & AJAX helpers for forensic analyzer UI
   No frameworks. Vanilla JS only.
   ================================================================ */

// Switch to a different case: preserve current interface path
function switchCase(uploadId) {
  if (!uploadId) return;
  const url = new URL(window.location.href);
  url.searchParams.set('upload_id', uploadId);
  window.location.href = url.toString();
}

// Generic JSON fetch helper
async function apiFetch(url, options = {}) {
  const defaults = {
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
  };
  const res = await fetch(url, { ...defaults, ...options });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

// Show/hide spinner on a button while an async operation runs
async function withSpinner(btn, fn) {
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Running…';
  try {
    await fn();
  } finally {
    btn.innerHTML = orig;
    btn.disabled = false;
  }
}

// ── Interface 2: Filter Button ─────────────────────────────────

const filterBtn = document.getElementById('btn-run-filter');
if (filterBtn) {
  filterBtn.addEventListener('click', async () => {
    const uploadId = filterBtn.dataset.uploadId;
    const statusEl = document.getElementById('filter-status');
    const summaryEl = document.getElementById('filter-summary');

    await withSpinner(filterBtn, async () => {
      statusEl.textContent = 'Running pipeline…';
      statusEl.className = 'alert alert-info';
      statusEl.classList.remove('hidden');
      summaryEl.classList.add('hidden');

      try {
        const data = await apiFetch(`/api/filter/${uploadId}`, { method: 'POST' });
        statusEl.textContent = 'Filter complete.';
        statusEl.className = 'alert alert-success';

        // Update summary stats
        document.getElementById('stat-packets').textContent = data.packet_count ?? '-';
        document.getElementById('stat-flows').textContent = data.flow_count ?? '-';
        document.getElementById('stat-whatsapp').textContent = data.whatsapp_count ?? '-';
        document.getElementById('stat-os').textContent = data.detected_os ?? '-';
        summaryEl.classList.remove('hidden');

        // Update sidebar dot
        const dot = document.getElementById('dot-2');
        if (dot) dot.className = 'status-dot filtered';

        // Enable Interface 3 nav item
        const nav3 = document.getElementById('nav-iface3');
        if (nav3) {
          nav3.classList.remove('disabled');
          nav3.href = `/interface/3?upload_id=${uploadId}`;
        }
      } catch (e) {
        statusEl.textContent = 'Error: ' + e.message;
        statusEl.className = 'alert alert-warning';
      }
    });
  });
}

// ── Interface 3: Analyze Button ────────────────────────────────

const analyzeBtn = document.getElementById('btn-run-analyze');
if (analyzeBtn) {
  analyzeBtn.addEventListener('click', async () => {
    const uploadId = analyzeBtn.dataset.uploadId;
    const statusEl = document.getElementById('analyze-status');

    await withSpinner(analyzeBtn, async () => {
      statusEl.textContent = 'Grouping parties and geolocating…';
      statusEl.className = 'alert alert-info';
      statusEl.classList.remove('hidden');

      try {
        await apiFetch(`/api/analyze/${uploadId}`, { method: 'POST' });
        statusEl.textContent = 'Analysis complete. Reloading…';
        statusEl.className = 'alert alert-success';
        // Full reload to render charts/map
        setTimeout(() => window.location.reload(), 800);
      } catch (e) {
        statusEl.textContent = 'Error: ' + e.message;
        statusEl.className = 'alert alert-warning';
      }
    });
  });
}
