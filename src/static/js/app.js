/**
 * FootprintIQ - Enterprise Application Interactivity & Animation Engine
 * Features:
 * - IntersectionObserver Scroll-Triggered Reveals
 * - prefers-reduced-motion compliance
 * - Sidebar Collapsible State Persistence (localStorage)
 * - Safe DOM Manipulation (XSS-safe text nodes)
 * - Dynamic Investigation-to-Target Linking
 * - System Health Diagnostics Modal
 */

(function () {
  'use strict';

  // =========================================================================
  // 0. CSRF TOKEN INJECTION FOR SAME-ORIGIN STATE-CHANGING REQUESTS
  // =========================================================================
  function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)fiq_csrf=([^;]+)/);
    if (match && match[1]) {
      return decodeURIComponent(match[1]);
    }
    const meta = document.querySelector('meta[name="fiq-csrf"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  }

  window.FIQ_GetCsrfToken = getCsrfToken;

  if (typeof window.fetch === 'function') {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      const opts = init ? Object.assign({}, init) : {};
      const method = String(opts.method || (typeof Request !== 'undefined' && input instanceof Request ? input.method : 'GET')).toUpperCase();
      if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
        let sameOrigin = true;
        try {
          const urlStr = typeof input === 'string' ? input : (input && input.url ? input.url : '');
          if (urlStr) {
            const parsed = new URL(urlStr, window.location.origin);
            sameOrigin = parsed.origin === window.location.origin;
          }
        } catch (_) {
          sameOrigin = true;
        }
        if (sameOrigin) {
          const csrf = getCsrfToken();
          if (csrf) {
            const headers = new Headers(opts.headers || (typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined));
            if (!headers.has('X-CSRF-Token')) {
              headers.set('X-CSRF-Token', csrf);
            }
            opts.headers = headers;
          }
        }
      }
      return nativeFetch(input, opts);
    };
  }

  // =========================================================================
  // 0B. THEME PREFERENCE ENGINE (LIGHT / DARK / SYSTEM) & IST TIMEZONE HELPER
  // =========================================================================
  const THEME_STORAGE_KEY = 'fiq_theme';

  window.FIQ_ResolveEffectiveTheme = function (pref) {
    const p = String(pref || 'light').toLowerCase();
    if (p === 'dark' || p === 'light') return p;
    if (p === 'system') {
      try {
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      } catch (_) {}
    }
    return 'light';
  };

  window.FIQ_GetThemePreference = function () {
    const isAuth = (document.querySelector('meta[name="fiq-authenticated"]') || {}).content === 'true';
    const meta = document.querySelector('meta[name="fiq-theme-preference"]');
    const metaPref = meta ? (meta.getAttribute('content') || 'light') : 'light';
    if (isAuth) return metaPref;
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch (_) {}
    return metaPref || 'light';
  };

  window.FIQ_GetTheme = function () {
    return document.documentElement.getAttribute('data-theme') || 'light';
  };

  function syncThemeToggleUI(pref, eff) {
    document.querySelectorAll('[data-fiq-theme-toggle]').forEach(function (btn) {
      btn.setAttribute('aria-pressed', eff === 'dark' ? 'true' : 'false');
      btn.setAttribute('title', `Theme: ${pref} (currently ${eff}) — click to switch`);
      const lbl = btn.querySelector('[data-fiq-theme-label]');
      if (lbl) lbl.textContent = eff === 'dark' ? 'Dark' : 'Light';
    });
    document.querySelectorAll('[data-theme-choice]').forEach(function (el) {
      const choice = el.getAttribute('data-theme-choice');
      const active = choice === pref;
      el.classList.toggle('ring-2', active);
      el.classList.toggle('ring-blue-500', active);
      el.classList.toggle('border-blue-500', active);
    });
  }

  window.FIQ_ApplyTheme = async function (pref, persistServer) {
    const cleanPref = (pref === 'dark' || pref === 'light' || pref === 'system') ? pref : 'light';
    const eff = window.FIQ_ResolveEffectiveTheme(cleanPref);
    try { localStorage.setItem(THEME_STORAGE_KEY, cleanPref); } catch (_) {}
    document.documentElement.setAttribute('data-theme', eff);
    document.documentElement.setAttribute('data-theme-pref', cleanPref);
    if (document.body) {
      document.body.setAttribute('data-theme', eff);
    }
    syncThemeToggleUI(cleanPref, eff);
    window.dispatchEvent(new CustomEvent('fiq:themechange', { detail: { preference: cleanPref, effective: eff } }));
    if (persistServer) {
      try {
        await window.fetch('/api/v1/auth/me/preferences', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ theme_preference: cleanPref }),
        });
      } catch (_) {}
    }
    return eff;
  };

  window.FIQ_FormatIST = function (rawTs, includeSeconds) {
    if (!rawTs) return '—';
    let s = String(rawTs).trim();
    if (!s) return '—';
    if (s.includes('IST')) return s;
    if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) {
      s = s.replace(' ', 'T') + 'Z';
    }
    const d = new Date(s);
    if (isNaN(d.getTime())) return String(rawTs);
    try {
      const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Kolkata',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: includeSeconds ? '2-digit' : undefined,
        hour12: true,
      }).formatToParts(d);
      const map = {};
      parts.forEach(function (p) { map[p.type] = p.value; });
      const dayPeriod = (map.dayPeriod || '').toUpperCase();
      const timeCore = includeSeconds
        ? `${map.hour}:${map.minute}:${map.second}`
        : `${map.hour}:${map.minute}`;
      return `${map.day} ${map.month} ${map.year}, ${timeCore} ${dayPeriod} IST`;
    } catch (_) {
      return s;
    }
  };

  try {
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
        if (window.FIQ_GetThemePreference() === 'system') {
          window.FIQ_ApplyTheme('system', false);
        }
      });
    }
  } catch (_) {}

  window.FIQ_Logout = async function () {
    try {
      await window.fetch('/api/v1/auth/logout', { method: 'POST' });
    } catch (_) {}
    window.location.href = '/login';
  };

  // =========================================================================
  // 1. SCROLL-TRIGGERED ANIMATION OBSERVER
  // =========================================================================
  function initScrollAnimations() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const elements = document.querySelectorAll('.reveal-on-scroll');

    if (prefersReducedMotion || !('IntersectionObserver' in window)) {
      elements.forEach(function (el) {
        el.classList.add('reveal-visible');
      });
      return;
    }

    const observer = new IntersectionObserver(
      function (entries, obs) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('reveal-visible');
            obs.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.08,
        rootMargin: '0px 0px -40px 0px'
      }
    );

    elements.forEach(function (el) {
      observer.observe(el);
    });
  }

  // =========================================================================
  // 2. SIDEBAR COLLAPSE / EXPAND TOGGLE
  // =========================================================================
  function initSidebar() {
    const sidebar = document.getElementById('fiqSidebar');
    const toggleBtn = document.getElementById('sidebarToggleBtn');
    const collapseTextEls = document.querySelectorAll('.sidebar-label');
    const STORAGE_KEY = 'fiq_sidebar_collapsed';

    if (!sidebar || !toggleBtn) return;

    function applySidebarState(isCollapsed) {
      if (isCollapsed) {
        sidebar.classList.add('sidebar-collapsed');
        sidebar.style.width = '4.5rem';
        collapseTextEls.forEach(function (el) {
          el.classList.add('hidden');
        });
      } else {
        sidebar.classList.remove('sidebar-collapsed');
        sidebar.style.width = '16rem';
        collapseTextEls.forEach(function (el) {
          el.classList.remove('hidden');
        });
      }
    }

    // Load saved state
    const savedState = localStorage.getItem(STORAGE_KEY) === 'true';
    applySidebarState(savedState);

    toggleBtn.addEventListener('click', function () {
      const willBeCollapsed = !sidebar.classList.contains('sidebar-collapsed');
      applySidebarState(willBeCollapsed);
      localStorage.setItem(STORAGE_KEY, willBeCollapsed);
    });
  }

  // =========================================================================
  // 3. SAFE DOM NOTIFICATION HELPER (NO RAW INNERHTML)
  // =========================================================================
  window.FIQ_Alert = function (containerId, message, type) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clear previous
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    const alertBox = document.createElement('div');
    alertBox.className = 'p-3.5 rounded-lg text-xs font-medium flex items-center justify-between border transition-all ';

    if (type === 'success') {
      alertBox.className += 'bg-emerald-50 text-emerald-800 border-emerald-200';
    } else if (type === 'error') {
      alertBox.className += 'bg-rose-50 text-rose-800 border-rose-200';
    } else if (type === 'loading') {
      alertBox.className += 'bg-blue-50 text-blue-800 border-blue-200';
    } else {
      alertBox.className += 'bg-slate-50 text-slate-800 border-slate-200';
    }

    const textSpan = document.createElement('span');
    textSpan.textContent = message;
    alertBox.appendChild(textSpan);

    container.appendChild(alertBox);
    container.classList.remove('hidden');
  };

  // =========================================================================
  // 4. DYNAMIC INVESTIGATION -> TARGETS LINKING (SCANS PAGE)
  // =========================================================================
  window.initDynamicScanTargets = function () {
    const invSelect = document.getElementById('scanInvestigationSelect');
    const targetSelect = document.getElementById('scanTargetSelect');
    if (!invSelect || !targetSelect) return;

    function updateTargets() {
      const selectedInv = invSelect.value;
      const options = targetSelect.querySelectorAll('option');
      let firstVisible = null;

      options.forEach(function (opt) {
        const optInv = opt.getAttribute('data-investigation');
        if (!optInv || optInv === selectedInv || optInv === 'ALL') {
          opt.style.display = '';
          if (!firstVisible) firstVisible = opt;
        } else {
          opt.style.display = 'none';
        }
      });

      if (firstVisible && (!targetSelect.selectedOptions[0] || targetSelect.selectedOptions[0].style.display === 'none')) {
        targetSelect.value = firstVisible.value;
      }
    }

    invSelect.addEventListener('change', updateTargets);
    updateTargets();
  };

  // =========================================================================
  // 5. SYSTEM HEALTH MODAL
  // =========================================================================
  window.openHealthModal = async function () {
    const modal = document.getElementById('healthModal');
    const content = document.getElementById('healthModalContent');
    if (!modal || !content) return;

    modal.classList.remove('hidden');
    content.textContent = 'Querying system diagnostics...';

    try {
      const res = await fetch('/api/v1/health');
      const data = await res.json();

      while (content.firstChild) {
        content.removeChild(content.firstChild);
      }

      const grid = document.createElement('div');
      grid.className = 'grid grid-cols-1 md:grid-cols-2 gap-4 text-xs';

      function createHealthCard(title, status, details) {
        const card = document.createElement('div');
        card.className = 'p-3 rounded-lg border border-slate-200 bg-slate-50/70';

        const head = document.createElement('div');
        head.className = 'flex items-center justify-between mb-1';

        const titleEl = document.createElement('span');
        titleEl.className = 'font-semibold text-slate-900';
        titleEl.textContent = title;

        const badge = document.createElement('span');
        const isOnline = status === 'ONLINE' || status === 'OPERATIONAL' || status === 'Active';
        badge.className = 'px-2 py-0.5 rounded text-[11px] font-bold ' +
          (isOnline ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800');
        badge.textContent = status;

        head.appendChild(titleEl);
        head.appendChild(badge);
        card.appendChild(head);

        const detEl = document.createElement('p');
        detEl.className = 'text-slate-500 text-[11px]';
        detEl.textContent = details;
        card.appendChild(detEl);

        return card;
      }

      grid.appendChild(createHealthCard('Campaign Data Store', data.database?.status || 'Active', 'Persistent campaign and findings storage'));
      grid.appendChild(createHealthCard('Evidence Archive', data.object_storage?.status || 'ONLINE', 'Integrity-verified artifact preservation'));
      grid.appendChild(createHealthCard('Network Assessment Engine', data.network_scanner?.status || 'ONLINE', 'Port, service & safety script scanner'));
      const nucleiData = data.vulnerability_scanners?.nuclei || {};
      grid.appendChild(createHealthCard(
        'ProjectDiscovery Nuclei',
        nucleiData.status || 'UNAVAILABLE',
        `${nucleiData.version || 'Nuclei'} • ${nucleiData.templates_count || 0} templates • ${nucleiData.profiles_count || 0} safe profiles`
      ));
      const graphData = data.graph_intelligence || {};
      grid.appendChild(createHealthCard(
        'Entity Graph & Maltego',
        graphData.status || 'ONLINE',
        graphData.mode || 'Correlation + GraphML/CSV Interchange'
      ));

      // Enhanced Tenable Nessus Card with Live Connection Testing
      const nessusData = data.vulnerability_scanners?.nessus || {};
      const nessusCard = document.createElement('div');
      nessusCard.className = 'p-3 rounded-lg border border-slate-200 bg-slate-50/70 space-y-2';

      const nHead = document.createElement('div');
      nHead.className = 'flex items-center justify-between';
      const nTitle = document.createElement('span');
      nTitle.className = 'font-semibold text-slate-900';
      nTitle.textContent = 'Tenable Nessus Bridge';
      const nBadge = document.createElement('span');
      const isNessusOnline = nessusData.status === 'ONLINE' || nessusData.mode === 'LIVE';
      nBadge.id = 'diagNessusBadge';
      nBadge.className = 'px-2 py-0.5 rounded text-[11px] font-bold ' +
        (isNessusOnline ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-700');
      nBadge.textContent = nessusData.status || 'OFFLINE';
      nHead.appendChild(nTitle);
      nHead.appendChild(nBadge);
      nessusCard.appendChild(nHead);

      const nDetails = document.createElement('p');
      nDetails.id = 'diagNessusDetails';
      nDetails.className = 'text-slate-500 text-[11px] leading-relaxed';
      nDetails.textContent = `Status: ${nessusData.status || 'UNKNOWN'} • Mode: ${nessusData.mode || 'API Adapter'}`;
      nessusCard.appendChild(nDetails);

      const nBtnRow = document.createElement('div');
      nBtnRow.className = 'pt-1 flex items-center justify-between';

      const nTestBtn = document.createElement('button');
      nTestBtn.className = 'px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-200 rounded text-slate-700 text-[10px] font-semibold transition';
      nTestBtn.textContent = 'Test Connection';
      nTestBtn.onclick = async function () {
        nTestBtn.disabled = true;
        nTestBtn.textContent = 'Testing...';
        try {
          const testRes = await fetch('/api/v1/scanners/nessus/test', { method: 'POST' });
          const testData = await testRes.json();
          nBadge.textContent = testData.status || (testData.connected ? 'Operational' : 'Unavailable');
          if (testData.connected && testData.scan_api_enabled === false) {
            nBadge.textContent = 'Connected (Read-Only)';
            nBadge.className = 'px-2 py-0.5 rounded text-[11px] font-bold bg-amber-100 text-amber-800';
            nDetails.textContent = `Verified: ${testData.version || 'Nessus'} (${testData.nessus_type || testData.edition || 'Essentials'}) • ${testData.limitations || 'Scan launch restricted by license (scan_api=false)'}`;
          } else if (testData.connected) {
            nBadge.className = 'px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-100 text-emerald-800';
            nDetails.textContent = `Verified: ${testData.version || 'Nessus 10.x'} (${testData.nessus_type || testData.edition || 'Professional'}) • API Ready`;
          } else {
            nBadge.className = 'px-2 py-0.5 rounded text-[11px] font-bold bg-amber-100 text-amber-800';
            nDetails.textContent = `Status: ${testData.status} • ${testData.error || 'Check environment variables'}`;
          }
        } catch (e) {
          nBadge.textContent = 'Error';
          nBadge.className = 'px-2 py-0.5 rounded text-[11px] font-bold bg-rose-100 text-rose-800';
          nDetails.textContent = 'API Test Request Failed: ' + e.message;
        } finally {
          nTestBtn.disabled = false;
          nTestBtn.textContent = 'Retest';
        }
      };
      nBtnRow.appendChild(nTestBtn);
      nessusCard.appendChild(nBtnRow);

      grid.appendChild(nessusCard);

      content.appendChild(grid);
    } catch (err) {
      content.textContent = 'Error loading diagnostics: ' + err.message;
    }
  };

  window.closeHealthModal = function () {
    const modal = document.getElementById('healthModal');
    if (modal) modal.classList.add('hidden');
  };

  // =========================================================================
  // 3D INTERACTIVE CARDS & KEYBOARD ACCESSIBILITY
  // =========================================================================
  function init3DCards() {
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    document.querySelectorAll('.fiq-3d-card').forEach(function (card) {
      if (!reduceMotion) {
        card.addEventListener('pointermove', function (ev) {
          const rect = card.getBoundingClientRect();
          if (!rect.width || !rect.height) return;
          const x = (ev.clientX - rect.left) / rect.width - 0.5;
          const y = (ev.clientY - rect.top) / rect.height - 0.5;
          card.style.setProperty('--fiq-rx', (-y * 4).toFixed(2) + 'deg');
          card.style.setProperty('--fiq-ry', (x * 4).toFixed(2) + 'deg');
        });
        card.addEventListener('pointerleave', function () {
          card.style.removeProperty('--fiq-rx');
          card.style.removeProperty('--fiq-ry');
        });
      }
      card.addEventListener('keydown', function (ev) {
        if ((ev.key === 'Enter' || ev.key === ' ') && card.hasAttribute('data-fiq-key-click')) {
          if (ev.target === card) {
            ev.preventDefault();
            card.click();
          }
        }
      });
    });
  }

  // =========================================================================
  // INITIALIZATION ON DOM READY
  // =========================================================================
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-progress-width]').forEach(function (el) {
      const pct = Math.max(0, Math.min(100, Number(el.dataset.progressWidth || 0)));
      el.style.width = `${pct}%`;
    });
    initScrollAnimations();
    initSidebar();
    init3DCards();
    const initialPref = window.FIQ_GetThemePreference();
    window.FIQ_ApplyTheme(initialPref, false);
    document.querySelectorAll('[data-fiq-theme-toggle]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const nextTheme = window.FIQ_GetTheme() === 'dark' ? 'light' : 'dark';
        window.FIQ_ApplyTheme(nextTheme, true);
      });
    });
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  });

})();

