(() => {
  "use strict";

  // ==========================================================================
  // Global state
  // ==========================================================================
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
    pendingTarget: null,
    activeTab: "control",
  };

  const mitmFlows = {
    map: new Map(),      // flow.key -> flow object
    packets: new Map(),  // flow.key -> array of packets (max 200)
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  // ==========================================================================
  // Icons (per device type)
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

  function humanBytes(n) {
    if (!n) return "0 B";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  }

  function humanAgo(ts) {
    if (!ts) return "—";
    const d = Math.floor(Date.now() / 1000 - ts);
    if (d < 2) return "just now";
    if (d < 60) return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    return Math.floor(d / 3600) + "h ago";
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    return ip.startsWith("10.") || ip.startsWith("192.168.")
        || ip.startsWith("172.16.") || ip.startsWith("172.17.")
        || ip.startsWith("172.18.") || ip.startsWith("172.19.")
        || ip.startsWith("172.2") || ip.startsWith("172.30.")
        || ip.startsWith("172.31.") || ip.startsWith("127.");
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
      const countHtml = typeof item.count === "number" ? `<span class="count">${item.count}</span>` : "";
      return `<div class="dropdown-item${active}" data-value="${escAttr(item.value)}">
                <span>${esc(item.label)}</span>${countHtml}
              </div>`;
    }).join("");

    trigger.onclick = (e) => {
      e.stopPropagation();
      const wasOpen = !menu.classList.contains("hidden");
      closeAllDropdowns();
      if (!wasOpen) { menu.classList.remove("hidden"); trigger.classList.add("open"); }
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
  // Landing / topbar / summary
  // ==========================================================================
  function showApp() {
    const landing = $("#landing"), app = $("#app");
    if (landing) landing.classList.add("hidden");
    if (app) app.classList.remove("hidden");
    window.scrollTo(0, 0);
  }

  function renderLanding() {
    const iface = state.iface || {};
    const lIf = $("#landing-iface"); if (lIf) lIf.textContent = iface.name || "—";
    const lIp = $("#landing-ip"); if (lIp) lIp.textContent = iface.ip || "—";
    const lCidr = $("#landing-cidr"); if (lCidr) lCidr.textContent = iface.cidr || "—";
    const btn = $("#landing-scan"); if (!btn) return;
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
    const p = $("#progress"); if (!p) return;
    if (state.scanning) {
      p.classList.remove("hidden");
      const fill = $("#progress-fill"); if (fill) fill.style.width = (state.progress || 0) + "%";
      const txt = $("#progress-text");
      if (txt) txt.textContent = (state.stage && state.stage !== "idle" ? state.stage : "Starting") + "…";
    } else p.classList.add("hidden");
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
    if (!items.some((i) => i.value === state.filterType)) state.filterType = "all";
    buildDropdown(
      { trigger: "filter-type-trigger", menu: "filter-type-menu", label: "filter-type-label" },
      items,
      state.filterType,
      (val) => { state.filterType = val; renderGroups(); }
    );
  }

  // ==========================================================================
  // Device cards
  // ==========================================================================
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

    const vendorChip = d.vendor ? `<span class="vendor-chip">${esc(d.vendor)}</span>` : "";
    const eligible = !d.is_self && !d.is_gateway && !!d.ip;

    const actionBlock = eligible
      ? `<button type="button" class="device-mitm-btn" data-mitm-action="start">
           <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
             <path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>
           </svg>
           <span>Start MITM</span>
         </button>`
      : `<div class="device-hint dim">${d.is_self ? "This is you" : "Gateway"}</div>`;

    card.innerHTML = `
      <div class="device-head">
        <div class="device-avatar">${svg(icon(d.type), 22)}</div>
        <div class="device-tags">
          ${primaryTag ? `<span class="tag ${primaryClass}">${primaryTag}</span>` : ""}
          <span class="tag type">${esc(d.type || "Unknown")}</span>
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
      ${actionBlock}
    `;

    if (eligible) {
      const btn = card.querySelector("[data-mitm-action]");
      if (btn) {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          askConfirmAndStartMitm(d);
        });
      }
      card.classList.add("clickable");
      card.addEventListener("click", () => askConfirmAndStartMitm(d));
    }

    return card;
  }

  function renderGroups() {
    const pinned = $("#group-pinned"), others = $("#group-others"), empty = $("#empty");
    const pinnedGrid = $("#grid-pinned"), othersGrid = $("#grid-others");
    if (!pinnedGrid || !othersGrid) return;
    pinnedGrid.innerHTML = ""; othersGrid.innerHTML = "";

    let list = state.devices.slice();
    if (state.filterType !== "all") list = list.filter((d) => (d.type || "Unknown") === state.filterType);
    if (state.search) {
      const q = state.search.toLowerCase();
      list = list.filter((d) =>
        [d.hostname, d.ip, d.mac, d.vendor, d.type]
          .some((v) => v && String(v).toLowerCase().includes(q)));
    }

    const countEl = $("#device-count"); if (countEl) countEl.textContent = list.length;

    if (list.length === 0) {
      if (pinned) pinned.classList.add("hidden");
      if (others) others.classList.add("hidden");
      if (empty) empty.classList.remove("hidden");
      return;
    }
    if (empty) empty.classList.add("hidden");

    const keyDevices = list.filter((d) => d.is_self || d.is_gateway)
      .sort((a, b) => (a.is_self && !b.is_self) ? -1 : (b.is_self && !a.is_self) ? 1 : 0);
    const otherDevices = list.filter((d) => !d.is_self && !d.is_gateway)
      .sort((a, b) => {
        const n = (ip) => (ip || "").split(".").reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
        return n(a.ip) - n(b.ip);
      });

    if (keyDevices.length && pinned) {
      pinned.classList.remove("hidden");
      keyDevices.forEach((d) => pinnedGrid.appendChild(buildCard(d)));
    } else if (pinned) pinned.classList.add("hidden");

    if (otherDevices.length && others) {
      others.classList.remove("hidden");
      const oc = $("#others-count"); if (oc) oc.textContent = otherDevices.length;
      otherDevices.forEach((d) => othersGrid.appendChild(buildCard(d)));
    } else if (others) others.classList.add("hidden");
  }

  // ==========================================================================
  // MITM — confirm modal
  // ==========================================================================
  function askConfirmAndStartMitm(device) {
    mitm.pendingTarget = device;
    const sub = $("#mitm-confirm-sub");
    if (sub) sub.textContent = `${device.hostname || "Unknown"} · ${device.ip}`;
    const t = $("#mitm-confirm-target");
    if (t) t.textContent = device.hostname ? `${device.hostname} · ${device.ip}` : device.ip;
    const m = $("#mitm-confirm-mac"); if (m) m.textContent = device.mac || "not available";
    const i = $("#mitm-confirm-iface"); if (i) i.textContent = (state.iface && state.iface.name) || "—";
    const selfDev = state.devices.find((d) => d.is_self);
    const a = $("#mitm-confirm-amac"); if (a) a.textContent = (selfDev && selfDev.mac) || "auto-detected";
    const cModal = $("#mitm-confirm");
    if (cModal) cModal.classList.remove("hidden");
  }

  function closeMitmConfirm() {
    const m = $("#mitm-confirm");
    if (m) m.classList.add("hidden");
    mitm.pendingTarget = null;
  }

  // ==========================================================================
  // MITM — start / stop
  // ==========================================================================
  async function startMitm(ip) {
    try {
      const r = await fetch("/api/mitm/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, confirm: true }),
      });
      const data = await r.json();
      if (!r.ok || !data.success) { toast(data.error || "Could not start MITM", "err"); return; }
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
      if (!r.ok || !data.success) { toast(data.error || "Could not stop MITM", "err"); return; }
      closeMitmPanel();
      disconnectMitmStream();
      toast("MITM stopped", "ok");
    } catch (e) {
      toast("MITM stop error: " + e.message, "err");
    }
  }

  // ==========================================================================
  // MITM — panel + tabs
  // ==========================================================================
  function openMitmPanel(session) {
    const panel = $("#mitm-panel");
    if (!panel) return;
    panel.classList.remove("hidden");
    applySessionToPanel(session);
    mitm.count = 0;
    mitmFlows.map.clear();
    mitmFlows.packets.clear();
    const tb = $("#packet-tbody"); if (tb) tb.innerHTML = "";
    const pe = $("#packet-empty"); if (pe) pe.classList.remove("hidden");
    const tlist = $("#traffic-list"); if (tlist) tlist.innerHTML = "";
    const tempty = $("#traffic-empty"); if (tempty) tempty.classList.remove("hidden");
    const pc = $("#packet-count"); if (pc) pc.textContent = "0 packets";
    setMitmTab("control");
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function closeMitmPanel() {
    const panel = $("#mitm-panel");
    if (panel) panel.classList.add("hidden");
    closeFlowDrawer();
  }

  function setMitmTab(name) {
    mitm.activeTab = name;
    document.querySelectorAll(".mitm-tab").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === name);
    });
    document.querySelectorAll(".mitm-tabpane").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.pane !== name);
    });
  }

  function applySessionToPanel(s) {
    if (!s) return;
    const sv = s.state || "stopped";
    const dot = $("#mitm-dot");
    if (dot) {
      dot.className = "dot " + (sv === "running" ? "online"
                              : sv === "error" ? "error"
                              : (sv === "starting" || sv === "stopping") ? "scanning"
                              : "");
    }
    const st = $("#mitm-state"); if (st) st.textContent = sv;

    // Target rows (top of panel)
    const vname = $("#mitm-vname"); if (vname) vname.textContent = s.victim_name || "—";
    const vip = $("#mitm-vip"); if (vip) vip.textContent = s.victim_ip || "—";
    const gname = $("#mitm-gname"); if (gname) gname.textContent = s.gateway_name || "—";
    const gip = $("#mitm-gip"); if (gip) gip.textContent = s.gateway_ip || "—";
    const ifc = $("#mitm-iface"); if (ifc) ifc.textContent = s.attacker_iface || "—";
    const amac = $("#mitm-amac"); if (amac) amac.textContent = s.attacker_mac || "—";

    // Control tab
    const cState = $("#ctrl-state-badge");
    if (cState) {
      cState.textContent = sv;
      cState.className = "control-state-badge " + (
        sv === "running" ? "ok" : sv === "error" ? "err" : "idle"
      );
    }
    const cSub = $("#ctrl-state-sub");
    if (cSub) {
      if (sv === "running" && s.started_at) {
        const secs = Math.max(1, Math.floor(Date.now() / 1000 - s.started_at));
        const m = Math.floor(secs / 60), ss = secs % 60;
        cSub.textContent = `Session active for ${m}m ${ss.toString().padStart(2, "0")}s`;
      } else if (sv === "error") {
        cSub.textContent = s.error || "Session failed";
      } else {
        cSub.textContent = "No session running";
      }
    }
    const cv = $("#ctrl-victim");
    if (cv) cv.textContent = s.victim_name
      ? `${s.victim_name} · ${s.victim_ip || "—"}` : (s.victim_ip || "—");
    const cg = $("#ctrl-gateway");
    if (cg) cg.textContent = s.gateway_name
      ? `${s.gateway_name} · ${s.gateway_ip || "—"}` : (s.gateway_ip || "—");
    const ci = $("#ctrl-iface"); if (ci) ci.textContent = s.attacker_iface || "—";
    const cf = $("#ctrl-forwarding"); if (cf) cf.textContent = s.forwarded ? "ON" : "OFF";
    const cp = $("#ctrl-packets"); if (cp) cp.textContent = mitm.count.toString();

    // ARP tab targets
    const victimLabel = s.victim_name || s.victim_ip || "target";
    const gatewayLabel = s.gateway_name || s.gateway_ip || "gateway";
    const avt = $("#arp-victim-target"); if (avt) avt.textContent = `${victimLabel} (${s.victim_ip || "—"})`;
    const agt = $("#arp-gateway-target"); if (agt) agt.textContent = `${gatewayLabel} (${s.gateway_ip || "—"})`;
    const avc = $("#arp-victim-claim"); if (avc) avc.textContent = s.gateway_ip || "—";
    const avm = $("#arp-victim-mac"); if (avm) avm.textContent = s.attacker_mac || "—";
    const avt2 = $("#arp-victim-truth"); if (avt2) avt2.textContent = s.gateway_mac || "—";
    const agc = $("#arp-gateway-claim"); if (agc) agc.textContent = s.victim_ip || "—";
    const agm = $("#arp-gateway-mac"); if (agm) agm.textContent = s.attacker_mac || "—";
    const agt2 = $("#arp-gateway-truth"); if (agt2) agt2.textContent = s.victim_mac || "—";

    // Traffic tab title
    const tt = $("#traffic-title");
    if (tt) tt.textContent = `${victimLabel} is browsing…`;
  }

  // ==========================================================================
  // MITM — SSE stream
  // ==========================================================================
  function connectMitmStream() {
    disconnectMitmStream();
    try {
      mitm.es = new EventSource("/api/mitm/stream");
      mitm.es.addEventListener("packet", (ev) => {
        try { appendPacket(JSON.parse(ev.data)); } catch (_) {}
      });
      mitm.es.addEventListener("flow", (ev) => {
        try { appendFlow(JSON.parse(ev.data)); } catch (_) {}
      });
      mitm.es.addEventListener("arp", (ev) => {
        try { applyArpStats(JSON.parse(ev.data)); } catch (_) {}
      });
      mitm.es.onerror = () => {};
    } catch (e) {
      toast("SSE unsupported: " + e.message, "err");
    }
  }

  function disconnectMitmStream() {
    if (mitm.es) { try { mitm.es.close(); } catch (_) {} mitm.es = null; }
  }

  // ==========================================================================
  // MITM — packet + flow rendering
  // ==========================================================================
  function appendPacket(rec) {
    if (mitm.paused) return;
    mitm.count++;

    // Buffer packets per flow for the drawer
    if (rec.flow_key) {
      const arr = mitmFlows.packets.get(rec.flow_key) || [];
      arr.push(rec);
      while (arr.length > 200) arr.shift();
      mitmFlows.packets.set(rec.flow_key, arr);
    }

    // Raw tab filter
    if (mitm.filter !== "ALL" && rec.protocol !== mitm.filter) {
      updateCounters();
      return;
    }
    const tbody = $("#packet-tbody");
    if (!tbody) { updateCounters(); return; }

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
    while (tbody.children.length > mitm.maxRows) tbody.removeChild(tbody.lastChild);
    const pe = $("#packet-empty"); if (pe) pe.classList.add("hidden");
    updateCounters();
  }

  function updateCounters() {
    const pc = $("#packet-count"); if (pc) pc.textContent = mitm.count + " packets";
    const cp = $("#ctrl-packets"); if (cp) cp.textContent = mitm.count.toString();
  }

  function appendFlow(flow) {
    mitmFlows.map.set(flow.key, flow);
    renderTrafficList();
  }

  function renderTrafficList() {
    const list = $("#traffic-list");
    const empty = $("#traffic-empty");
    const summary = $("#traffic-summary");
    if (!list) return;
    const flows = Array.from(mitmFlows.map.values())
      .filter((f) => !f.hostname || !isPrivateIp(f.dst_ip))
      .sort((a, b) => b.last_seen - a.last_seen);
    const visible = flows.slice(0, 200);
    if (visible.length === 0) {
      empty.classList.remove("hidden");
      list.innerHTML = "";
      if (summary) summary.textContent = "0 destinations · 0 KB";
      return;
    }
    empty.classList.add("hidden");
    const totalBytes = flows.reduce((acc, f) => acc + f.bytes, 0);
    if (summary) {
      summary.textContent = `${flows.length} destination${flows.length === 1 ? "" : "s"} · ${humanBytes(totalBytes)}`;
    }
    list.innerHTML = visible.map((f) => {
      const active = (Date.now() / 1000 - f.last_seen) < 5;
      const dot = active ? "traffic-dot active" : "traffic-dot";
      const host = f.hostname || f.dst_ip;
      const port = f.dst_port ? `:${f.dst_port}` : "";
      const sub = `${f.category} · ${humanBytes(f.bytes)} · ${f.packets} pkt`;
      return `
        <div class="traffic-row" data-flow-key="${escAttr(f.key)}">
          <div class="${dot}"></div>
          <div class="traffic-body">
            <div class="traffic-host">${esc(host)}<span class="traffic-port">${esc(port)}</span></div>
            <div class="traffic-sub">${esc(sub)}</div>
          </div>
          <div class="traffic-meta">
            <span class="proto-badge ${esc(f.protocol)}">${esc(f.protocol)}</span>
            <span class="traffic-ago">${humanAgo(f.last_seen)}</span>
          </div>
        </div>
      `;
    }).join("");
    list.querySelectorAll(".traffic-row").forEach((el) => {
      el.addEventListener("click", () => openFlowDrawer(el.dataset.flowKey));
    });
  }

  function applyArpStats(s) {
    if (!s) return;
    const vc = $("#arp-victim-count"); if (vc) vc.textContent = s.to_victim_count || 0;
    const gc = $("#arp-gateway-count"); if (gc) gc.textContent = s.to_gateway_count || 0;
    const vl = $("#arp-victim-last");
    if (vl && s.to_victim_last) vl.textContent = humanAgo(s.to_victim_last);
    const gl = $("#arp-gateway-last");
    if (gl && s.to_gateway_last) gl.textContent = humanAgo(s.to_gateway_last);
    const total = (s.to_victim_count || 0) + (s.to_gateway_count || 0);
    const cas = $("#ctrl-arp-sends"); if (cas) cas.textContent = total.toString();
  }

  // ==========================================================================
  // Flow drawer
  // ==========================================================================
  function openFlowDrawer(key) {
    const flow = mitmFlows.map.get(key);
    if (!flow) return;
    const drawer = $("#flow-drawer");
    const title = $("#flow-drawer-title");
    const sub = $("#flow-drawer-sub");
    const stats = $("#flow-drawer-stats");
    const tbody = $("#flow-drawer-tbody");
    if (title) title.textContent = flow.hostname || flow.dst_ip;
    if (sub) sub.textContent = `${flow.dst_ip}${flow.dst_port ? ":" + flow.dst_port : ""} · ${flow.protocol} · ${flow.category}`;
    if (stats) {
      stats.innerHTML = `
        <div><b>${flow.packets}</b> packets</div>
        <div><b>${humanBytes(flow.bytes)}</b> total</div>
        <div>first seen <b>${humanAgo(flow.first_seen)}</b></div>
        <div>last seen <b>${humanAgo(flow.last_seen)}</b></div>
      `;
    }
    if (tbody) {
      const arr = (mitmFlows.packets.get(key) || []).slice(-100).reverse();
      tbody.innerHTML = arr.map((p) => {
        const timeStr = new Date(p.ts * 1000).toLocaleTimeString([], {
          hour: "2-digit", minute: "2-digit", second: "2-digit",
        });
        return `
          <tr>
            <td class="mono">${esc(timeStr)}</td>
            <td class="mono">${esc(p.src_ip || p.src_mac || "—")}</td>
            <td class="mono">${esc(p.dst_ip || p.dst_mac || "—")}</td>
            <td><span class="proto-badge ${esc(p.protocol)}">${esc(p.protocol)}</span></td>
            <td class="mono">${p.length}</td>
          </tr>
        `;
      }).join("");
    }
    drawer.classList.remove("hidden");
  }

  function closeFlowDrawer() {
    const d = $("#flow-drawer");
    if (d) d.classList.add("hidden");
  }

  // ==========================================================================
  // MITM — panel wiring (buttons, chips, tabs, drawer)
  // ==========================================================================
  function wireMitmPanel() {
    const stopBtn = $("#mitm-stop");
    if (stopBtn) stopBtn.addEventListener("click", stopMitm);

    const clearBtn = $("#mitm-clear");
    if (clearBtn) clearBtn.addEventListener("click", async () => {
      try { await fetch("/api/mitm/clear", { method: "POST" }); } catch (_) {}
      const tb = $("#packet-tbody"); if (tb) tb.innerHTML = "";
      mitm.count = 0;
      updateCounters();
      const pe = $("#packet-empty"); if (pe) pe.classList.remove("hidden");
      mitmFlows.map.clear();
      mitmFlows.packets.clear();
      renderTrafficList();
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

    document.querySelectorAll(".mitm-tab").forEach((t) => {
      t.addEventListener("click", () => setMitmTab(t.dataset.tab));
    });

    const cModal = $("#mitm-confirm");
    if (cModal) {
      cModal.querySelectorAll("[data-close]").forEach((el) => {
        el.addEventListener("click", closeMitmConfirm);
      });
    }
    const go = $("#mitm-confirm-go");
    if (go) {
      go.addEventListener("click", () => {
        const target = mitm.pendingTarget;
        closeMitmConfirm();
        if (target && target.ip) startMitm(target.ip);
      });
    }

    document.querySelectorAll("[data-flow-close]").forEach((el) => {
      el.addEventListener("click", closeFlowDrawer);
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
  // Wire + boot
  // ==========================================================================
  function wire() {
    const landingBtn = $("#landing-scan");
    if (landingBtn) landingBtn.addEventListener("click", () => startScan(true));

    const scanBtn = $("#btn-scan");
    if (scanBtn) scanBtn.addEventListener("click", () => startScan(false));

    const refreshBtn = $("#btn-refresh");
    if (refreshBtn) refreshBtn.addEventListener("click", async () => {
      await fetchNetwork();
      await fetchDevices();
      toast("Refreshed", "ok");
    });

    const searchInput = $("#search");
    if (searchInput) searchInput.addEventListener("input", (e) => {
      state.search = e.target.value.trim();
      renderGroups();
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closeMitmConfirm();
        closeFlowDrawer();
      }
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

    mitm.pollTimer = setInterval(pollMitmStatus, 4000);
    pollMitmStatus();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();