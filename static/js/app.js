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
    sortKey: "ip",
    sortDir: "asc",
    search: "",
    filterType: "all",
    filterStatus: "all",
    poll: null,
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const ICON = {
    Router: '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
    Computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    Mac: '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "This Device": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    Phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Tablet: '<rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    Printer: '<path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2"/>',
    TV: '<rect x="2" y="7" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    NAS: '<rect x="3" y="6" width="18" height="4" rx="1"/><rect x="3" y="14" width="18" height="4" rx="1"/><circle cx="7" cy="8" r=".6"/><circle cx="7" cy="16" r=".6"/>',
    "Smart Home": '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    Console: '<rect x="2" y="7" width="20" height="11" rx="3"/><circle cx="8" cy="12.5" r="1.2"/><circle cx="16" cy="12.5" r="1.2"/>',
    Camera: '<path d="M2 7h3l2-3h10l2 3h3v13H2z"/><circle cx="12" cy="13" r="4"/>',
    Chromecast: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/>',
    "Apple Device": '<path d="M16 3c-1 0-2 .5-3 1.5S11 6.5 11 8c0 1.5 1 3 2 4s2.5 1.5 3 1.5c.7 0 1.3-.3 2-.7.6-.4 1-.4 1.5 0 .5.3 1.2.7 2 .7.5 0 1-.1 1.5-.4C24 12 25 9.5 25 7c0-.5-.4-1-1-1-.7 0-1.5.2-2 .8"/>',
    Speaker: '<rect x="5" y="3" width="14" height="18" rx="2"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7" r="1"/>',
    "Virtual Machine": '<rect x="3" y="4" width="18" height="12" rx="2"/><rect x="6" y="14" width="12" height="6"/>',
    "Network Device": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
    "Mobile Device": '<rect x="6" y="2" width="12" height="20" rx="2"/>',
    "Android TV": '<rect x="2" y="7" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Raspberry Pi": '<rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="12" cy="12" r="3"/>',
    Unknown: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    Device: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  };

  const esc = (s) => (s === null || s === undefined) ? "" :
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : "Never";
  const fmtRel = (ts) => {
    if (!ts) return "—";
    const d = Math.floor(Date.now() / 1000 - ts);
    if (d < 5) return "just now";
    if (d < 60) return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    return Math.floor(d / 3600) + "h ago";
  };

  const icon = (type) => ICON[type] || ICON.Unknown;

  function toast(msg, kind = "") {
    const el = $("#toast");
    el.textContent = msg;
    el.className = "toast " + kind;
    el.classList.remove("hidden");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.add("hidden"), 3500);
  }

  function copy(text, label) {
    if (!text) { toast("Nothing to copy", "err"); return; }
    navigator.clipboard.writeText(text).then(
      () => toast(label + " copied", "ok"),
      () => toast("Copy failed", "err"),
    );
  }

  // ---- View switching
  function setView(name) {
    $$(".view").forEach((v) => v.classList.add("hidden"));
    const el = document.getElementById("view-" + name);
    if (el) el.classList.remove("hidden");
    $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
  }

  // ---- Sorting/filtering
  function filtered() {
    let out = state.devices.slice();
    if (state.filterType !== "all") out = out.filter((d) => (d.type || "Unknown") === state.filterType);
    if (state.filterStatus !== "all") out = out.filter((d) => (d.status || "") === state.filterStatus);
    if (state.search) {
      const q = state.search.toLowerCase();
      out = out.filter((d) =>
        [d.hostname, d.ip, d.mac, d.vendor, d.type].some((v) => v && String(v).toLowerCase().includes(q)));
    }
    const dir = state.sortDir === "asc" ? 1 : -1;
    const key = state.sortKey;
    out.sort((a, b) => {
      if (key === "ip") {
        const n = (ip) => (ip || "").split(".").reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
        return (n(a.ip) - n(b.ip)) * dir;
      }
      const va = (a[key] ?? "").toString().toLowerCase();
      const vb = (b[key] ?? "").toString().toLowerCase();
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
    return out;
  }

  // ---- Renderers
  function renderProgress() {
    const strip = $("#progress-strip");
    if (state.scanning) {
      strip.classList.remove("hidden");
      $("#progress-fill").style.width = (state.progress || 0) + "%";
      $("#progress-text").textContent = state.stage === "idle" ? "Starting…" : state.stage + "…";
    } else {
      strip.classList.add("hidden");
    }
  }

  function renderSidebar() {
    const dot = $("#side-dot");
    const txt = $("#side-text");
    if (state.scanning) { dot.className = "dot scanning"; txt.textContent = "Scanning"; }
    else if (state.error) { dot.className = "dot error"; txt.textContent = "Error"; }
    else { dot.className = "dot online"; txt.textContent = "Ready"; }
  }

  function renderHeader() {
    const iface = state.iface || {};
    $("#net-name").textContent = iface.name || "No network";
    $("#net-sub").textContent = iface.ip ? `${iface.ip} · ${iface.cidr || ""}` : "—";
  }

  function renderStats() {
    const online = state.devices.filter((d) => d.status === "online").length;
    $("#stat-devices").textContent = state.devices.length;
    $("#stat-devices-sub").textContent = state.devices.length ? "on this network" : "not scanned yet";
    $("#stat-online").textContent = online;
    $("#stat-online-sub").textContent = online ? "reachable" : "—";
    $("#stat-network").textContent = state.iface ? (state.iface.cidr || "—") : "—";
    $("#stat-network-sub").textContent = state.iface ? (state.iface.network || "—") : "—";
    $("#stat-local-ip").textContent = state.iface ? state.iface.ip : "—";
    $("#stat-local-name").textContent = state.localName || "—";
    $("#stat-iface").textContent = state.iface ? state.iface.name : "—";
    $("#stat-last").textContent = fmtTime(state.lastScan);
    $("#stat-last-sub").textContent = state.lastScan ? fmtRel(state.lastScan) : "—";
  }

  function renderMini() {
    const grid = $("#mini-grid");
    const empty = $("#mini-empty");
    grid.innerHTML = "";
    if (state.devices.length === 0) { empty.classList.remove("hidden"); return; }
    empty.classList.add("hidden");
    state.devices.slice(0, 6).forEach((d) => {
      const el = document.createElement("div");
      el.className = "mini-card";
      el.addEventListener("click", () => openModal(d));
      const name = d.hostname || "Unknown Device";
      const unknownClass = d.hostname ? "" : "unknown";
      el.innerHTML = `
        <div class="mini-avatar"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${icon(d.type)}</svg></div>
        <div class="mini-info">
          <div class="mini-name ${unknownClass}">${esc(name)}</div>
          <div class="mini-meta">${esc(d.ip)}${d.vendor && d.vendor !== "Unknown" ? " · " + esc(d.vendor) : ""}</div>
        </div>
      `;
      grid.appendChild(el);
    });
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

  function renderTable() {
    const list = filtered();
    $("#count-pill").textContent = list.length;
    const tbody = $("#device-tbody");
    const empty = $("#devices-empty");
    tbody.innerHTML = "";

    if (list.length === 0) { empty.classList.remove("hidden"); return; }
    empty.classList.add("hidden");

    $$(".device-table thead th").forEach((th) => {
      const ind = th.querySelector(".arrow");
      if (!ind) return;
      ind.textContent = th.dataset.sort === state.sortKey
        ? (state.sortDir === "asc" ? "▲" : "▼") : "";
    });

    const frag = document.createDocumentFragment();
    list.forEach((d) => {
      const tr = document.createElement("tr");
      const name = d.hostname || "Unknown Device";
      const unknownClass = d.hostname ? "" : "unknown";
      const statusCls = d.status === "online" ? "online" : "unknown";
      tr.addEventListener("click", () => openModal(d));
      tr.innerHTML = `
        <td>
          <div class="cell-name">
            <div class="row-avatar"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${icon(d.type)}</svg></div>
            <div class="name-text ${unknownClass}">${esc(name)}</div>
          </div>
        </td>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono">${esc(d.mac || "—")}</td>
        <td class="${d.vendor && d.vendor !== "Unknown" ? "" : "dim"}">${esc(d.vendor || "Unknown")}</td>
        <td><span class="type-badge">${esc(d.type || "Unknown")}</span></td>
        <td><span class="badge ${statusCls}"><span class="dot"></span>${esc(d.status || "unknown")}</span></td>
        <td class="dim">${esc(fmtRel(d.last_seen))}</td>
      `;
      frag.appendChild(tr);
    });
    tbody.appendChild(frag);
  }

  // ---- Modal
  function openModal(d) {
    $("#modal-title").textContent = d.hostname || "Unknown Device";
    const rows = [
      ["Hostname", d.hostname, false],
      ["IP Address", d.ip, true],
      ["MAC Address", d.mac, true],
      ["Vendor", d.vendor, false],
      ["Device Type", d.type, false],
      ["Status", d.status, false],
      ["Last Seen", fmtRel(d.last_seen), false],
      ["Name Source", d.name_source && d.name_source !== "none" ? d.name_source : null, false],
      ["Services", d.services && d.services.length ? d.services.join(", ") : null, false],
      ["Network", state.iface ? state.iface.cidr : null, false],
      ["Interface", state.iface ? state.iface.name : null, false],
    ];
    $("#modal-body").innerHTML = `<div class="detail-grid">` + rows.map(([k, v, copyable]) => {
      const na = (v === null || v === undefined || v === "");
      const cls = na ? "na" : "";
      const val = na ? "Not available" : esc(v);
      const copyBtn = (copyable && !na)
        ? `<span class="copy" data-copy="${esc(v)}" title="Copy">
             <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
           </span>` : "";
      return `<div class="detail-k">${esc(k)}</div><div class="detail-v ${cls}">${val}${copyBtn}</div>`;
    }).join("") + `</div>`;

    $$("#modal-body .copy").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.stopPropagation();
        copy(el.dataset.copy, "Value");
      });
    });
    $("#modal").classList.remove("hidden");
  }

  function closeModal() { $("#modal").classList.add("hidden"); }

  // ---- API
  async function fetchNetwork() {
    try {
      const r = await fetch("/api/network");
      const d = await r.json();
      state.iface = d.interface;
      state.localName = d.local_name;
      renderHeader();
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
      if (state.error) { banner.textContent = state.error; banner.classList.remove("hidden"); }
      else banner.classList.add("hidden");

      const btn = $("#btn-scan");
      btn.disabled = state.scanning;
      $("#btn-scan-label").textContent = state.scanning ? "Scanning…" : "Scan Network";

      renderProgress();
      renderSidebar();
      renderHeader();
      renderStats();
      renderMini();
      renderTypeFilter();
      renderTable();
    } catch (e) {
      toast("Cannot reach server: " + e.message, "err");
    }
  }

  async function startScan() {
    if (state.scanning) return;
    try { await fetch("/api/scan", { method: "POST" }); } catch (_) {}
    state.scanning = true;
    renderProgress();
    renderSidebar();

    clearInterval(state.poll);
    state.poll = setInterval(async () => {
      await fetchDevices();
      if (!state.scanning) {
        clearInterval(state.poll);
        state.poll = null;
        toast(state.devices.length ? `Scan complete — ${state.devices.length} device(s) found.` : "Scan complete — no devices found.", state.devices.length ? "ok" : "");
      }
    }, 700);
  }

  // ---- Wire
  function wire() {
    $$(".nav-item").forEach((n) => n.addEventListener("click", (e) => { e.preventDefault(); setView(n.dataset.view); }));
    $("#btn-scan").addEventListener("click", startScan);
    $("#btn-refresh").addEventListener("click", () => { fetchNetwork(); fetchDevices(); toast("Refreshed", "ok"); });
    $("#btn-view-all").addEventListener("click", () => setView("devices"));
    $("#search").addEventListener("input", (e) => { state.search = e.target.value.trim(); renderTable(); });
    $("#filter-type").addEventListener("change", (e) => { state.filterType = e.target.value; renderTable(); });
    $("#filter-status").addEventListener("change", (e) => { state.filterStatus = e.target.value; renderTable(); });
    $$(".device-table thead th").forEach((th) => {
      th.addEventListener("click", () => {
        const k = th.dataset.sort;
        if (!k) return;
        if (state.sortKey === k) state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
        else { state.sortKey = k; state.sortDir = "asc"; }
        renderTable();
      });
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