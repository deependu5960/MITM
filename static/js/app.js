(() => {
  "use strict";

  const state = {
    devices: [],
    iface: null,
    localName: null,
    scanning: false,
    stage: "idle",
    progress: 0,
    lastScan: null,
    error: null,
    search: "",
    filterType: "all",
    poll: null,
  };

  const mitm = {
    session: null,
    es: null,
    paused: false,
    filter: "ALL",
    count: 0,
    pollTimer: null,
    maxRows: 500,
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  // ==========================================================================
  // Icons
  // ==========================================================================
  const ICON = {
    Phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Tablet: '<rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Laptop: '<rect x="3" y="5" width="18" height="11" rx="2"/><line x1="2" y1="20" x2="22" y2="20"/>',
    Computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "Windows PC": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "This Device": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    Mac: '<path d="M16 3c-1 0-2 .5-3 1.5S11 6.5 11 8c0 1.5 1 3 2 4s2.5 1.5 3 1.5c.7 0 1.3-.3 2-.7.6-.4 1-.4 1.5 0 .5.3 1.2.7 2 .7.5 0 1-.1 1.5-.4C24 12 25 9.5 25 7c0-.5-.4-1-1-1-.7 0-1.5.2-2 .8"/>',
    Router: '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
    "Network Device": '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
    TV: '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Android TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Samsung TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Sony TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "LG TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Roku TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Fire TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Apple TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Philips TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Hisense TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "TCL TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    Chromecast: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M5 12a7 7 0 0 1 7-7"/>',
    Printer: '<path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2"/>',
    Scanner: '<rect x="3" y="8" width="18" height="10" rx="2"/><path d="M7 8V4h10v4"/><circle cx="12" cy="13" r="2"/>',
    "Smart Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    Speaker: '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "Sonos Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "AirPlay Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "Apple Device": '<path d="M16 3c-1 0-2 .5-3 1.5S11 6.5 11 8c0 1.5 1 3 2 4s2.5 1.5 3 1.5c.7 0 1.3-.3 2-.7.6-.4 1-.4 1.5 0 .5.3 1.2.7 2 .7.5 0 1-.1 1.5-.4C24 12 25 9.5 25 7c0-.5-.4-1-1-1-.7 0-1.5.2-2 .8"/>',
    NAS: '<rect x="3" y="6" width="18" height="4" rx="1"/><rect x="3" y="14" width="18" height="4" rx="1"/><circle cx="7" cy="8" r=".7"/><circle cx="7" cy="16" r=".7"/>',
    "Synology NAS": '<rect x="3" y="6" width="18" height="4" rx="1"/><rect x="3" y="14" width="18" height="4" rx="1"/><circle cx="7" cy="8" r=".7"/><circle cx="7" cy="16" r=".7"/>',
    "QNAP NAS": '<rect x="3" y="6" width="18" height="4" rx="1"/><rect x="3" y="14" width="18" height="4" rx="1"/><circle cx="7" cy="8" r=".7"/><circle cx="7" cy="16" r=".7"/>',
    Console: '<rect x="2" y="8" width="20" height="10" rx="3"/><circle cx="8" cy="13" r="1.4"/><circle cx="16" cy="13" r="1.4"/>',
    Xbox: '<rect x="2" y="8" width="20" height="10" rx="3"/><circle cx="8" cy="13" r="1.4"/><circle cx="16" cy="13" r="1.4"/>',
    PlayStation: '<rect x="2" y="8" width="20" height="10" rx="3"/><circle cx="8" cy="13" r="1.4"/><circle cx="16" cy="13" r="1.4"/>',
    "Nintendo Switch": '<rect x="2" y="8" width="20" height="10" rx="3"/><circle cx="8" cy="13" r="1.4"/><circle cx="16" cy="13" r="1.4"/>',
    Camera: '<path d="M2 7h3l2-3h10l2 3h3v13H2z"/><circle cx="12" cy="13" r="4"/>',
    "Smart Home": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "HomeKit Accessory": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "Matter Device": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "Raspberry Pi": '<rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="12" cy="12" r="3"/>',
    Server: '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><circle cx="7" cy="7" r=".8"/><circle cx="7" cy="17" r=".8"/>',
    "Virtual Machine": '<rect x="3" y="4" width="18" height="12" rx="2"/><rect x="6" y="16" width="12" height="4"/>',
    "Linux Device": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "Mobile Device": '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Device: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    Unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12" y2="17.01"/>',
  };

  // ==========================================================================
  // Helpers
  // ==========================================================================
  const esc = (s) => (s === null || s === undefined) ? "" :
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const escAttr = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));

  const fmtTime = (ts) => ts
    ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : "Never";

  const fmtRel = (ts) => {
    if (!ts) return "—";
    const d = Math.floor(Date.now() / 1000 - ts);
    if (d < 5) return "just now";
    if (d < 60) return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    return Math.floor(d / 3600) + "h ago";
  };

  const icon = (type) => ICON[type] || ICON.Unknown;

  function svg(path, size = 20) {
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${path}</svg>`;
  }

  function toast(msg, kind = "") {
    const el = $("#toast");
    if (!el) return;
    el.textContent = msg;
    el.className = "toast " + kind;
    el.classList.remove("hidden");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.add("hidden"), 3200);
  }

  function copy(text, label) {
    if (!text) { toast("Nothing to copy", "err"); return; }
    navigator.clipboard.writeText(text).then(
      () => toast(label + " copied", "ok"),
      () => toast("Copy failed", "err"),
    );
  }

  // ==========================================================================
  // Custom dropdown
  // ==========================================================================
  function closeAllDropdowns() {
    document.querySelectorAll(".dropdown-menu").forEach((m) => m.classList.add("hidden"));
    document.querySelectorAll(".dropdown-trigger").forEach((t) => t.classList.remove("open"));
  }

  document.addEventListener("click", closeAllDropdowns);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAllDropdowns(); });

  function buildDropdown(ids, items, current, onSelect) {
    const trigger = document.getElementById(ids.trigger);
    const menu = document.getElementById(ids.menu);
    const label = document.getElementById(ids.label);
    if (!trigger || !menu || !label) return null;

    const currentItem = items.find((i) => i.value === current) || items[0];
    label.textContent = currentItem.label;

    menu.innerHTML = items.map((item) => {
      const active = item.value === current ? " active" : "";
      const countHtml = typeof item.count === "number"
        ? `<span class="count">${item.count}</span>` : "";
      return `<div class="dropdown-item${active}" data-value="${escAttr(item.value)}">
                <span>${esc(item.label)}</span>
                ${countHtml}
              </div>`;
    }).join("");

    trigger.onclick = (e) => {
      e.stopPropagation();
      const wasOpen = !menu.classList.contains("hidden");
      closeAllDropdowns();
      if (!wasOpen) {
        menu.classList.remove("hidden");
        trigger.classList.add("open");
      }
    };

    menu.querySelectorAll(".dropdown-item").forEach((el) => {
      el.onclick = (e) => {
        e.stopPropagation();
        const val = el.dataset.value;
        const item = items.find((i) => i.value === val);
        label.textContent = item ? item.label : val;
        menu.querySelectorAll(".dropdown-item").forEach((m) => m.classList.remove("active"));
        el.classList.add("active");
        closeAllDropdowns();
        onSelect(val);
      };
    });

    return { trigger, menu, label };
  }

  // ==========================================================================
  // Scanner views
  // ==========================================================================
  function showApp() {
    const landing = $("#landing");
    const app = $("#app");
    if (landing) landing.classList.add("hidden");
    if (app) app.classList.remove("hidden");
    window.scrollTo(0, 0);
  }

  function renderLanding() {
    const iface = state.iface || {};
    const lIf = $("#landing-iface"); if (lIf) lIf.textContent = iface.name || "—";
    const lIp = $("#landing-ip"); if (lIp) lIp.textContent = iface.ip || "—";
    const lCidr = $("#landing-cidr"); if (lCidr) lCidr.textContent = iface.cidr || "—";

    const btn = $("#landing-scan");
    if (!btn) return;
    btn.disabled = state.scanning;
    btn.classList.toggle("loading", state.scanning);
    const span = btn.querySelector("span");
    if (span) span.textContent = state.scanning ? "Scanning…" : "Start Scanning";

    const foot = $("#landing-foot-text");
    if (foot) {
      if (state.scanning) foot.textContent = state.stage && state.stage !== "idle" ? state.stage + "…" : "Starting…";
      else if (state.error) foot.textContent = "Last scan failed";
      else foot.textContent = "Ready when you are";
    }
  }

  function renderProgress() {
    const p = $("#progress");
    if (!p) return;
    if (state.scanning) {
      p.classList.remove("hidden");
      const fill = $("#progress-fill");
      if (fill) fill.style.width = (state.progress || 0) + "%";
      const txt = $("#progress-text");
      if (txt) txt.textContent = (state.stage && state.stage !== "idle" ? state.stage : "Starting") + "…";
    } else {
      p.classList.add("hidden");
    }
  }

  function renderTopbar() {
    const iface = state.iface || {};
    const dot = $("#top-dot");
    if (dot) {
      if (state.scanning) dot.className = "dot scanning";
      else if (state.error) dot.className = "dot error";
      else dot.className = "dot online";
    }
    const tn = $("#top-net"); if (tn) tn.textContent = iface.ip ? `${iface.name || "iface"} · ${iface.ip}` : "No network";
    const tc = $("#top-count"); if (tc) tc.textContent = state.devices.length;
    const tt = $("#top-time"); if (tt) tt.textContent = state.lastScan ? fmtTime(state.lastScan) : "never";
    const btn = $("#btn-scan"); if (btn) btn.disabled = state.scanning;
    const bl = $("#btn-scan-label"); if (bl) bl.textContent = state.scanning ? "Scanning" : "Scan";
  }

  function renderSummary() {
    const self = state.devices.find((d) => d.is_self);
    const router = state.devices.find((d) => d.is_gateway);
    const iface = state.iface || {};
    const s1 = $("#sum-self"); if (s1) s1.textContent = (self && (self.hostname || self.ip)) || state.localName || "—";
    const s2 = $("#sum-router"); if (s2) s2.textContent = (router && (router.hostname || router.ip)) || "—";
    const s3 = $("#sum-cidr"); if (s3) s3.textContent = iface.cidr || "—";
    const s4 = $("#sum-time"); if (s4) s4.textContent = state.lastScan ? fmtTime(state.lastScan) : "Never";
  }

  function renderTypeFilter() {
    const counts = {};
    for (const d of state.devices) {
      const t = d.type || "Unknown";
      counts[t] = (counts[t] || 0) + 1;
    }
    const types = Object.keys(counts).sort((a, b) => {
      if (a === "Unknown") return 1;
      if (b === "Unknown") return -1;
      return a.localeCompare(b);
    });
    const items = [
      { value: "all", label: "All types", count: state.devices.length },
      ...types.map((t) => ({ value: t, label: t, count: counts[t] })),
    ];
    if (!items.some((i) => i.value === state.filterType)) {
      state.filterType = "all";
    }
    buildDropdown(
      { trigger: "filter-type-trigger", menu: "filter-type-menu", label: "filter-type-label" },
      items,
      state.filterType,
      (val) => { state.filterType = val; renderGroups(); }
    );
  }

  function buildCard(d) {
    const card = document.createElement("div");
    card.className = "device" +
      (d.is_self ? " self" : "") +
      (d.is_gateway ? " gateway" : "");

    const hasName = !!(d.hostname && d.hostname !== "Unknown Device");
    const displayName = hasName ? d.hostname : "Unknown Device";
    const nameClass = hasName ? "" : "unknown";

    let primaryTag = "";
    let primaryClass = "";
    if (d.is_self) { primaryTag = "This Device"; primaryClass = "self"; }
    else if (d.is_gateway) { primaryTag = "Router"; primaryClass = "gateway"; }

    const vendorChip = d.vendor
      ? `<span class="vendor-chip">${esc(d.vendor)}</span>` : "";

    const mitmButton = (!d.is_self && !d.is_gateway)
      ? `<button class="tag mitm-btn" data-mitm-ip="${escAttr(d.ip)}" title="Start MITM lab session">MITM</button>`
      : "";

    card.innerHTML = `
      <div class="device-head">
        <div class="device-avatar">${svg(icon(d.type), 22)}</div>
        <div class="device-tags">
          ${primaryTag ? `<span class="tag ${primaryClass}">${primaryTag}</span>` : ""}
          <span class="tag type">${esc(d.type || "Unknown")}</span>
          ${mitmButton}
        </div>
      </div>
      <div class="device-name ${nameClass}">${esc(displayName)}</div>
      <div class="device-meta">
        ${vendorChip}
        ${d.is_self ? '<span class="meta-chip self-chip">you</span>' : ""}
      </div>
      <div class="device-rows">
        <div class="device-row">
          <span class="k">IP</span>
          <span class="v">${esc(d.ip || "—")}</span>
        </div>
        <div class="device-row">
          <span class="k">MAC</span>
          <span class="v ${d.mac ? "" : "dim"}">${esc(d.mac || "not available")}</span>
        </div>
      </div>
    `;

    card.addEventListener("click", () => openModal(d));

    const mitmBtn = card.querySelector("[data-mitm-ip]");
    if (mitmBtn) {
      mitmBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        confirmAndStartMitm(d);
      });
    }

    return card;
  }

  function renderGroups() {
    const pinned = $("#group-pinned");
    const others = $("#group-others");
    const empty = $("#empty");
    const pinnedGrid = $("#grid-pinned");
    const othersGrid = $("#grid-others");
    if (!pinnedGrid || !othersGrid) return;

    pinnedGrid.innerHTML = "";
    othersGrid.innerHTML = "";

    let list = state.devices.slice();
    if (state.filterType !== "all") {
      list = list.filter((d) => (d.type || "Unknown") === state.filterType);
    }
    if (state.search) {
      const q = state.search.toLowerCase();
      list = list.filter((d) =>
        [d.hostname, d.ip, d.mac, d.vendor, d.type]
          .some((v) => v && String(v).toLowerCase().includes(q)));
    }

    const countEl = $("#device-count");
    if (countEl) countEl.textContent = list.length;

    if (list.length === 0) {
      if (pinned) pinned.classList.add("hidden");
      if (others) others.classList.add("hidden");
      if (empty) empty.classList.remove("hidden");
      return;
    }
    if (empty) empty.classList.add("hidden");

    const keyDevices = list
      .filter((d) => d.is_self || d.is_gateway)
      .sort((a, b) => {
        if (a.is_self && !b.is_self) return -1;
        if (b.is_self && !a.is_self) return 1;
        return 0;
      });

    const otherDevices = list
      .filter((d) => !d.is_self && !d.is_gateway)
      .sort((a, b) => {
        const n = (ip) => (ip || "").split(".").reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
        return n(a.ip) - n(b.ip);
      });

    if (keyDevices.length && pinned) {
      pinned.classList.remove("hidden");
      keyDevices.forEach((d) => pinnedGrid.appendChild(buildCard(d)));
    } else if (pinned) {
      pinned.classList.add("hidden");
    }

    if (otherDevices.length && others) {
      others.classList.remove("hidden");
      const oc = $("#others-count");
      if (oc) oc.textContent = otherDevices.length;
      otherDevices.forEach((d) => othersGrid.appendChild(buildCard(d)));
    } else if (others) {
      others.classList.add("hidden");
    }
  }

  // ==========================================================================
  // Modal
  // ==========================================================================
  function openModal(d) {
    const modal = $("#modal");
    if (!modal) return;
    const name = d.hostname || "Unknown Device";
    const mt = $("#modal-title"); if (mt) mt.textContent = name;
    const ms = $("#modal-sub"); if (ms) ms.textContent = d.ip || "";
    const mi = $("#modal-icon"); if (mi) mi.innerHTML = svg(icon(d.type), 22);

    const rows = [
      ["Hostname", d.hostname, false],
      ["IP Address", d.ip, true],
      ["MAC Address", d.mac, true],
      ["Vendor", d.vendor, false],
      ["Device Type", d.type, false],
      ["Status", d.status, false],
      ["Last Seen", d.last_seen ? fmtRel(d.last_seen) : null, false],
      ["Name Source", d.name_source && d.name_source !== "none" ? d.name_source : null, false],
      ["Services", d.services && d.services.length ? d.services.join(", ") : null, false],
      ["Network", state.iface ? state.iface.cidr : null, false],
      ["Interface", state.iface ? state.iface.name : null, false],
    ];

    const body = $("#modal-body");
    if (!body) return;
    body.innerHTML = `<div class="detail-grid">` +
      rows.map(([k, v, canCopy]) => {
        const na = v === null || v === undefined || v === "";
        const cls = na ? "na" : "";
        const val = na ? "Not available" : esc(v);
        const copyBtn = canCopy && !na
          ? `<span class="copy" data-copy="${escAttr(v)}" title="Copy">${svg('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>', 12)}</span>`
          : "";
        return `<div class="detail-k">${esc(k)}</div><div class="detail-v ${cls}">${val}${copyBtn}</div>`;
      }).join("") +
      `</div>`;

    $$("#modal-body .copy").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.stopPropagation();
        copy(el.dataset.copy, "Value");
      });
    });

    modal.classList.remove("hidden");
  }

  function closeModal() {
    const m = $("#modal");
    if (m) m.classList.add("hidden");
  }

  // ==========================================================================
  // Scanner API
  // ==========================================================================
  async function fetchNetwork() {
    try {
      const r = await fetch("/api/network");
      const d = await r.json();
      state.iface = d.interface;
      state.localName = d.local_name;
    } catch (_) {}
  }

  async function fetchDevices() {
    try {
      const r = await fetch("/api/devices");
      const d = await r.json();
      state.devices = d.devices || [];
      state.scanning = !!d.scanning;
      state.stage = d.stage || "idle";
      state.progress = d.progress || 0;
      state.lastScan = d.last_scan;
      state.iface = d.iface || state.iface;
      state.localName = d.local_name || state.localName;
      state.error = d.error;

      const banner = $("#banner");
      if (banner) {
        if (state.error) { banner.textContent = state.error; banner.classList.remove("hidden"); }
        else banner.classList.add("hidden");
      }

      renderLanding();
      renderProgress();
      renderTopbar();
      renderSummary();
      renderTypeFilter();
      renderGroups();
    } catch (e) {
      toast("Cannot reach server: " + e.message, "err");
    }
  }

  async function startScan(fromLanding) {
    if (state.scanning) return;
    if (fromLanding) showApp();
    try { await fetch("/api/scan", { method: "POST" }); } catch (_) {}
    state.scanning = true;
    renderProgress();
    renderTopbar();
    renderLanding();

    clearInterval(state.poll);
    state.poll = setInterval(async () => {
      await fetchDevices();
      if (!state.scanning) {
        clearInterval(state.poll);
        state.poll = null;
        if (state.devices.length) toast(`Scan complete — ${state.devices.length} device(s) found.`, "ok");
        else toast("Scan complete — no devices found.", "");
      }
    }, 700);
  }

  // ==========================================================================
  // MITM client
  // ==========================================================================
  function confirmAndStartMitm(d) {
    const ok = window.confirm(
      "I confirm this target is a device I own/control in my authorized lab.\n\n" +
      `Target: ${d.hostname || "Unknown"}  (${d.ip})\n` +
      `MAC: ${d.mac || "unknown"}`
    );
    if (!ok) return;
    startMitm(d.ip);
  }

  async function startMitm(ip) {
    try {
      const r = await fetch("/api/mitm/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, confirm: true }),
      });
      const data = await r.json();
      if (!r.ok || !data.success) {
        toast(data.error || "Could not start MITM", "err");
        return;
      }
      openMitmPanel(data.session);
      connectMitmStream();
      toast("MITM started", "ok");
    } catch (e) {
      toast("MITM start error: " + e.message, "err");
    }
  }

  async function stopMitm() {
    try {
      const r = await fetch("/api/mitm/stop", { method: "POST" });
      const data = await r.json();
      if (!r.ok || !data.success) {
        toast(data.error || "Could not stop MITM", "err");
        return;
      }
      closeMitmPanel();
      disconnectMitmStream();
      toast("MITM stopped", "ok");
    } catch (e) {
      toast("MITM stop error: " + e.message, "err");
    }
  }

  function openMitmPanel(session) {
    const panel = $("#mitm-panel");
    if (!panel) return;
    panel.classList.remove("hidden");
    applySessionToPanel(session);
    mitm.count = 0;
    const pc = $("#packet-count"); if (pc) pc.textContent = "0 packets";
    const tb = $("#packet-tbody"); if (tb) tb.innerHTML = "";
    const pe = $("#packet-empty"); if (pe) pe.classList.remove("hidden");
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function closeMitmPanel() {
    const panel = $("#mitm-panel");
    if (panel) panel.classList.add("hidden");
  }

  function applySessionToPanel(s) {
    if (!s) return;
    const dot = $("#mitm-dot");
    const stateVal = s.state || "stopped";
    if (dot) {
      dot.className = "dot " + (stateVal === "running" ? "online"
                              : stateVal === "error" ? "error"
                              : stateVal === "starting" || stateVal === "stopping" ? "scanning"
                              : "");
    }
    const st = $("#mitm-state"); if (st) st.textContent = stateVal;
    const vip = $("#mitm-vip"); if (vip) vip.textContent = s.victim_ip || "—";
    const vmac = $("#mitm-vmac"); if (vmac) vmac.textContent = s.victim_mac || "—";
    const gip = $("#mitm-gip"); if (gip) gip.textContent = s.gateway_ip || "—";
    const gmac = $("#mitm-gmac"); if (gmac) gmac.textContent = s.gateway_mac || "—";
    const ifc = $("#mitm-iface"); if (ifc) ifc.textContent = s.attacker_iface || "—";
    const aip = $("#mitm-aip"); if (aip) aip.textContent = s.attacker_ip || "—";
    const amac = $("#mitm-amac"); if (amac) amac.textContent = s.attacker_mac || "—";
  }

  function connectMitmStream() {
    disconnectMitmStream();
    try {
      mitm.es = new EventSource("/api/mitm/stream");
      mitm.es.addEventListener("packet", (ev) => {
        try {
          const rec = JSON.parse(ev.data);
          appendPacket(rec);
        } catch (_) {}
      });
      mitm.es.onerror = () => {
        // Browser will auto-reconnect.
      };
    } catch (e) {
      toast("SSE unsupported: " + e.message, "err");
    }
  }

  function disconnectMitmStream() {
    if (mitm.es) {
      try { mitm.es.close(); } catch (_) {}
      mitm.es = null;
    }
  }

  function appendPacket(rec) {
    if (mitm.paused) return;
    if (mitm.filter !== "ALL" && rec.protocol !== mitm.filter) return;
    mitm.count++;
    const pc = $("#packet-count"); if (pc) pc.textContent = mitm.count + " packets";
    const pe = $("#packet-empty"); if (pe) pe.classList.add("hidden");

    const tbody = $("#packet-tbody");
    if (!tbody) return;

    const tr = document.createElement("tr");
    const timeStr = new Date(rec.ts * 1000).toLocaleTimeString([], {
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    const src = rec.src_ip || rec.src_mac || "—";
    const dst = rec.dst_ip || rec.dst_mac || "—";
    tr.innerHTML = `
      <td class="mono">${esc(timeStr)}</td>
      <td class="mono">${esc(src)}</td>
      <td class="mono">${esc(dst)}</td>
      <td><span class="proto-badge ${esc(rec.protocol)}">${esc(rec.protocol)}</span></td>
      <td class="mono">${rec.length}</td>
      <td class="dim">${esc(rec.summary)}</td>
    `;
    tbody.prepend(tr);
    while (tbody.children.length > mitm.maxRows) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function wireMitmPanel() {
    const stopBtn = $("#mitm-stop");
    if (stopBtn) stopBtn.addEventListener("click", stopMitm);

    const clearBtn = $("#mitm-clear");
    if (clearBtn) clearBtn.addEventListener("click", async () => {
      try { await fetch("/api/mitm/clear", { method: "POST" }); } catch (_) {}
      const tb = $("#packet-tbody"); if (tb) tb.innerHTML = "";
      mitm.count = 0;
      const pc = $("#packet-count"); if (pc) pc.textContent = "0 packets";
      const pe = $("#packet-empty"); if (pe) pe.classList.remove("hidden");
    });

    const pauseBtn = $("#mitm-pause");
    if (pauseBtn) pauseBtn.addEventListener("click", async () => {
      const path = mitm.paused ? "/api/mitm/resume" : "/api/mitm/pause";
      try { await fetch(path, { method: "POST" }); } catch (_) {}
      mitm.paused = !mitm.paused;
      pauseBtn.textContent = mitm.paused ? "Resume" : "Pause";
    });

    document.querySelectorAll(".packet-filters .chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        document.querySelectorAll(".packet-filters .chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        mitm.filter = chip.dataset.filter || "ALL";
      });
    });
  }

  async function pollMitmStatus() {
    try {
      const r = await fetch("/api/mitm/status");
      const d = await r.json();
      mitm.session = d;
      const panel = $("#mitm-panel");
      if (!panel) return;
      if (d.state && d.state !== "stopped") {
        applySessionToPanel(d);
        if (panel.classList.contains("hidden")) {
          openMitmPanel(d);
          connectMitmStream();
        }
      } else if (d.state === "stopped") {
        if (!panel.classList.contains("hidden")) {
          closeMitmPanel();
          disconnectMitmStream();
        }
      }
    } catch (_) {}
  }

  // ==========================================================================
  // Wire + boot
  // ==========================================================================
  function wire() {
    const landingBtn = $("#landing-scan");
    if (landingBtn) landingBtn.addEventListener("click", () => startScan(true));

    const scanBtn = $("#btn-scan");
    if (scanBtn) scanBtn.addEventListener("click", () => startScan(false));

    const refreshBtn = $("#btn-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", async () => {
        await fetchNetwork();
        await fetchDevices();
        toast("Refreshed", "ok");
      });
    }

    const searchInput = $("#search");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        state.search = e.target.value.trim();
        renderGroups();
      });
    }

    $$("#modal [data-close]").forEach((el) => el.addEventListener("click", closeModal));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeModal(); }
    });

    wireMitmPanel();
  }

  async function boot() {
    wire();
    await fetchNetwork();
    await fetchDevices();

    if (state.scanning) {
      state.poll = setInterval(async () => {
        await fetchDevices();
        if (!state.scanning) { clearInterval(state.poll); state.poll = null; }
      }, 700);
    }

    // Poll MITM status — picks up session started from another tab or
    // already running when the page loads.
    mitm.pollTimer = setInterval(pollMitmStatus, 4000);
    pollMitmStatus();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();