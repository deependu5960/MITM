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

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const ICON = {
    // Phone
    Phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    // Tablet
    Tablet: '<rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    // Laptop
    Laptop: '<rect x="3" y="5" width="18" height="11" rx="2"/><line x1="2" y1="20" x2="22" y2="20"/><line x1="2" y1="20" x2="22" y2="20"/>',
    // Desktop / Computer / Windows PC
    Computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "Windows PC": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "This Device": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    // Mac
    Mac: '<path d="M16 3c-1 0-2 .5-3 1.5S11 6.5 11 8c0 1.5 1 3 2 4s2.5 1.5 3 1.5c.7 0 1.3-.3 2-.7.6-.4 1-.4 1.5 0 .5.3 1.2.7 2 .7.5 0 1-.1 1.5-.4C24 12 25 9.5 25 7c0-.5-.4-1-1-1-.7 0-1.5.2-2 .8"/>',
    // Router / Network Device
    Router: '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
    "Network Device": '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
    // TV
    TV: '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    // Chromecast / Apple TV
    Chromecast: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M5 12a7 7 0 0 1 7-7"/>',
    "Android TV": '<rect x="2" y="6" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    // Printer / Scanner
    Printer: '<path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2"/>',
    Scanner: '<rect x="3" y="8" width="18" height="10" rx="2"/><path d="M7 8V4h10v4"/><circle cx="12" cy="13" r="2"/>',
    // Speaker / Smart Speaker / Sonos / Echo
    "Smart Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    Speaker: '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "Sonos Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "AirPlay Speaker": '<rect x="5" y="3" width="14" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    // Apple family
    "Apple Device": '<path d="M16 3c-1 0-2 .5-3 1.5S11 6.5 11 8c0 1.5 1 3 2 4s2.5 1.5 3 1.5c.7 0 1.3-.3 2-.7.6-.4 1-.4 1.5 0 .5.3 1.2.7 2 .7.5 0 1-.1 1.5-.4C24 12 25 9.5 25 7c0-.5-.4-1-1-1-.7 0-1.5.2-2 .8"/>',
    // NAS
    NAS: '<rect x="3" y="6" width="18" height="4" rx="1"/><rect x="3" y="14" width="18" height="4" rx="1"/><circle cx="7" cy="8" r=".7"/><circle cx="7" cy="16" r=".7"/>',
    // Console
    Console: '<rect x="2" y="8" width="20" height="10" rx="3"/><circle cx="8" cy="13" r="1.4"/><circle cx="16" cy="13" r="1.4"/>',
    // Camera
    Camera: '<path d="M2 7h3l2-3h10l2 3h3v13H2z"/><circle cx="12" cy="13" r="4"/>',
    // Smart Home
    "Smart Home": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "HomeKit Accessory": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "Matter Device": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    // Raspberry Pi / Server / Virtual Machine
    "Raspberry Pi": '<rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="12" cy="12" r="3"/>',
    Server: '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><circle cx="7" cy="7" r=".8"/><circle cx="7" cy="17" r=".8"/>',
    "Virtual Machine": '<rect x="3" y="4" width="18" height="12" rx="2"/><rect x="6" y="16" width="12" height="4"/>',
    "Linux Device": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    // Generic
    "Mobile Device": '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Device: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    Unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12" y2="17.01"/>',
  };

  const esc = (s) => (s === null || s === undefined) ? "" :
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "Never";
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

  // ---------- Landing → App transition ----------
  function showApp() {
    $("#landing").classList.add("hidden");
    $("#app").classList.remove("hidden");
    window.scrollTo(0, 0);
  }

  // ---------- Rendering ----------
  function renderLanding() {
    const iface = state.iface || {};
    $("#landing-iface").textContent = iface.name || "—";
    $("#landing-ip").textContent = iface.ip || "—";
    $("#landing-cidr").textContent = iface.cidr || "—";

    const btn = $("#landing-scan");
    btn.disabled = state.scanning;
    btn.classList.toggle("loading", state.scanning);
    btn.querySelector("span").textContent = state.scanning ? "Scanning…" : "Start Scanning";

    const foot = $("#landing-foot-text");
    if (state.scanning) foot.textContent = state.stage && state.stage !== "idle" ? state.stage + "…" : "Starting…";
    else if (state.error) foot.textContent = "Last scan failed";
    else foot.textContent = "Ready when you are";
  }

  function renderProgress() {
    const p = $("#progress");
    if (state.scanning) {
      p.classList.remove("hidden");
      $("#progress-fill").style.width = (state.progress || 0) + "%";
      $("#progress-text").textContent = (state.stage && state.stage !== "idle" ? state.stage : "Starting") + "…";
    } else {
      p.classList.add("hidden");
    }
  }

  function renderTopbar() {
    const iface = state.iface || {};
    const dot = $("#top-dot");
    if (state.scanning) dot.className = "dot scanning";
    else if (state.error) dot.className = "dot error";
    else dot.className = "dot online";

    $("#top-net").textContent = iface.ip ? `${iface.name || "iface"} · ${iface.ip}` : "No network";
    $("#top-count").textContent = state.devices.length;
    $("#top-time").textContent = state.lastScan ? fmtTime(state.lastScan) : "never";

    $("#btn-scan").disabled = state.scanning;
    $("#btn-scan-label").textContent = state.scanning ? "Scanning" : "Scan";
  }

  function renderSummary() {
    const self = state.devices.find((d) => d.is_self);
    const router = state.devices.find((d) => d.is_gateway);
    const iface = state.iface || {};

    $("#sum-self").textContent = (self && (self.hostname || self.ip)) || state.localName || "—";
    $("#sum-router").textContent = (router && (router.hostname || router.ip)) || "—";
    $("#sum-cidr").textContent = iface.cidr || "—";
    $("#sum-time").textContent = state.lastScan ? fmtTime(state.lastScan) : "Never";
  }

  function renderTypeFilter() {
    const sel = $("#filter-type");
    const types = Array.from(new Set(state.devices.map((d) => d.type || "Unknown"))).sort();
    const current = state.filterType;
    sel.innerHTML = `<option value="all">All types</option>` +
      types.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("");
    sel.value = types.includes(current) ? current : "all";
    state.filterType = sel.value;
  }

  function buildCard(d) {
    const card = document.createElement("div");
    card.className = "device" +
      (d.is_self ? " self" : "") +
      (d.is_gateway ? " gateway" : "");

    const name = d.hostname || "Unknown Device";
    const nameClass = d.hostname ? "" : "unknown";

    let primaryTag = "";
    let primaryClass = "";
    if (d.is_self) { primaryTag = "This Device"; primaryClass = "self"; }
    else if (d.is_gateway) { primaryTag = "Router"; primaryClass = "gateway"; }

    const vendorLine = d.vendor && d.vendor !== "Unknown"
      ? esc(d.vendor)
      : `<span style="opacity:.6">Vendor unknown</span>`;

    card.innerHTML = `
      <div class="device-head">
        <div class="device-avatar">${svg(icon(d.type), 22)}</div>
        <div class="device-tags">
          ${primaryTag ? `<span class="tag ${primaryClass}">${primaryTag}</span>` : ""}
          <span class="tag type">${esc(d.type || "Unknown")}</span>
        </div>
      </div>
      <div class="device-name ${nameClass}">${esc(name)}</div>
      <div class="device-vendor">${vendorLine}</div>
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
    return card;
  }

  function renderGroups() {
    const pinned = $("#group-pinned");
    const others = $("#group-others");
    const empty = $("#empty");
    const pinnedGrid = $("#grid-pinned");
    const othersGrid = $("#grid-others");

    pinnedGrid.innerHTML = "";
    othersGrid.innerHTML = "";

    // Filter
    let list = state.devices.slice();
    if (state.filterType !== "all") list = list.filter((d) => (d.type || "Unknown") === state.filterType);
    if (state.search) {
      const q = state.search.toLowerCase();
      list = list.filter((d) =>
        [d.hostname, d.ip, d.mac, d.vendor, d.type].some((v) => v && String(v).toLowerCase().includes(q)));
    }

    $("#device-count").textContent = list.length;

    if (list.length === 0) {
      pinned.classList.add("hidden");
      others.classList.add("hidden");
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    // Split: this device + router first, then everything else
    const keyDevices = list
      .filter((d) => d.is_self || d.is_gateway)
      .sort((a, b) => {
        if (a.is_self && !b.is_self) return -1;
        if (b.is_self && !a.is_self) return 1;
        return 0;
      });
    const otherDevices = list.filter((d) => !d.is_self && !d.is_gateway)
      .sort((a, b) => {
        const n = (ip) => (ip || "").split(".").reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
        return n(a.ip) - n(b.ip);
      });

    if (keyDevices.length) {
      pinned.classList.remove("hidden");
      keyDevices.forEach((d) => pinnedGrid.appendChild(buildCard(d)));
    } else {
      pinned.classList.add("hidden");
    }

    if (otherDevices.length) {
      others.classList.remove("hidden");
      $("#others-count").textContent = otherDevices.length;
      otherDevices.forEach((d) => othersGrid.appendChild(buildCard(d)));
    } else {
      others.classList.add("hidden");
    }
  }

  // ---------- Modal ----------
  function openModal(d) {
    const name = d.hostname || "Unknown Device";
    $("#modal-title").textContent = name;
    $("#modal-sub").textContent = d.ip || "";
    $("#modal-icon").innerHTML = svg(icon(d.type), 22);

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

    $("#modal-body").innerHTML = `<div class="detail-grid">` +
      rows.map(([k, v, canCopy]) => {
        const na = v === null || v === undefined || v === "";
        const cls = na ? "na" : "";
        const val = na ? "Not available" : esc(v);
        const copyBtn = canCopy && !na
          ? `<span class="copy" data-copy="${esc(v)}" title="Copy">${svg('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>', 12)}</span>`
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

    $("#modal").classList.remove("hidden");
  }

  function closeModal() { $("#modal").classList.add("hidden"); }

  // ---------- API ----------
  async function fetchNetwork() {
    try {
      const r = await fetch("/api/network");
      const d = await r.json();
      state.iface = d.interface;
      state.localName = d.local_name;
    } catch (_) { }
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
      if (state.error) { banner.textContent = state.error; banner.classList.remove("hidden"); }
      else banner.classList.add("hidden");

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
    try { await fetch("/api/scan", { method: "POST" }); } catch (_) { }
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

  // ---------- Wire ----------
  function wire() {
    $("#landing-scan").addEventListener("click", () => startScan(true));
    $("#btn-scan").addEventListener("click", () => startScan(false));
    $("#btn-refresh").addEventListener("click", async () => {
      await fetchNetwork();
      await fetchDevices();
      toast("Refreshed", "ok");
    });
    $("#search").addEventListener("input", (e) => {
      state.search = e.target.value.trim();
      renderGroups();
    });
    $("#filter-type").addEventListener("change", (e) => {
      state.filterType = e.target.value;
      renderGroups();
    });
    $$("#modal [data-close]").forEach((el) => el.addEventListener("click", closeModal));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
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
  }

  document.addEventListener("DOMContentLoaded", boot);
})();