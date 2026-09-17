(() => {
  let devices = [];
  let scanning = false;
  let pollTimer = null;

  const $ = (id) => document.getElementById(id);

  const icons = {
    "This device": '<path d="M3 4h18v12H3zM8 20h8M12 16v4"/>',
    "Gateway / Router": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
    "Phone": '<rect x="6" y="2" width="12" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    "Tablet": '<rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18.01"/>',
    "Computer": '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    "Printer": '<path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2"/>',
    "TV / Media": '<rect x="2" y="7" width="20" height="13" rx="2"/><path d="m17 2-5 5-5-5"/>',
    "Device": '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  };

  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function render() {
    const q = $("search").value.trim().toLowerCase();

    let list = devices;
    if (q) {
      list = list.filter((d) =>
        (d.ip || "").toLowerCase().includes(q) ||
        (d.mac || "").toLowerCase().includes(q) ||
        (d.hostname || "").toLowerCase().includes(q) ||
        (d.vendor || "").toLowerCase().includes(q) ||
        (d.type || "").toLowerCase().includes(q)
      );
    }

    $("count-pill").textContent = list.length;

    const grid = $("grid");
    grid.innerHTML = "";

    const loading = $("loading");
    const empty = $("empty");

    if (scanning) {
      loading.classList.remove("hidden");
      empty.classList.add("hidden");
    } else {
      loading.classList.add("hidden");
    }

    if (!scanning && list.length === 0) {
      empty.classList.remove("hidden");
    } else {
      empty.classList.add("hidden");
    }

    for (const d of list) {
      const card = document.createElement("div");
      card.className = "device" +
        (d.is_self ? " self" : "") +
        (d.is_gateway ? " gateway" : "");

      const iconPath = icons[d.type] || icons["Device"];
      const badgeClass = d.is_self ? "self" : d.is_gateway ? "gateway" : "";

      // Friendly name line — this is the "like Wi-Fi list" bit you want
      let title;
      if (d.hostname) {
        title = d.hostname;
      } else if (d.vendor && d.vendor !== "Unknown" && d.vendor !== "Randomized MAC") {
        title = d.vendor + " device";
      } else if (d.type && d.type !== "Device") {
        title = d.type;
      } else {
        title = "Unknown device";
      }

      const subtitle = d.hostname
        ? (d.type || "Device")
        : (d.vendor && d.vendor !== "Unknown" ? d.vendor : "—");

      card.innerHTML = `
      <div class="device-head">
        <div class="device-icon">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none"
               stroke="currentColor" stroke-width="1.8"
               stroke-linecap="round" stroke-linejoin="round">
            ${iconPath}
          </svg>
        </div>
        <span class="device-type ${badgeClass}">${escapeHtml(d.type)}</span>
      </div>

      <div class="device-title">${escapeHtml(title)}</div>
      <div class="device-subtitle">${escapeHtml(subtitle)}</div>

      <div class="device-rows">
        <div class="device-row">
          <span class="k">IP</span>
          <span class="v">${escapeHtml(d.ip)}</span>
        </div>
        <div class="device-row">
          <span class="k">MAC</span>
          <span class="v ${d.mac ? "" : "muted"}">${escapeHtml(d.mac || "unavailable")}</span>
        </div>
      </div>
    `;
      grid.appendChild(card);
    }
  }

  async function fetchInfo() {
    try {
      const r = await fetch("/api/info");
      const data = await r.json();
      $("header-net").textContent = data.network || "unknown";
      $("meta-ip").textContent = data.local_ip || "—";
      $("meta-net").textContent = data.network || "—";
      $("meta-gw").textContent = data.gateway || "—";
    } catch (e) {
      // ignore
    }
  }

  async function fetchDevices() {
    try {
      const r = await fetch("/api/devices");
      const data = await r.json();

      devices = data.devices || [];
      scanning = !!data.scanning;

      if (data.local_ip) $("meta-ip").textContent = data.local_ip;
      if (data.network) {
        $("meta-net").textContent = data.network;
        $("header-net").textContent = data.network;
      }
      if (data.gateway) $("meta-gw").textContent = data.gateway;

      if (data.error) {
        $("error-box").textContent = data.error;
        $("error-box").classList.remove("hidden");
      } else {
        $("error-box").classList.add("hidden");
      }

      // scan button state
      const btn = $("scan-btn");
      const lbl = $("scan-label");
      if (scanning) {
        btn.disabled = true;
        btn.classList.add("spinning");
        lbl.textContent = "Scanning…";
      } else {
        btn.disabled = false;
        btn.classList.remove("spinning");
        lbl.textContent = "Discover Hosts";
      }

      render();
    } catch (e) {
      $("error-box").textContent = "Cannot reach server: " + e.message;
      $("error-box").classList.remove("hidden");
    }
  }

  async function startScan() {
    if (scanning) return;

    try {
      const r = await fetch("/api/scan", { method: "POST" });
      if (r.status === 409) {
        // already running — just resume polling
      }
    } catch (e) {
      // ignore
    }

    scanning = true;
    render();

    clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      await fetchDevices();
      if (!scanning) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    }, 700);
  }

  // Wire events
  $("scan-btn").addEventListener("click", startScan);
  $("search").addEventListener("input", render);

  // Boot
  (async () => {
    await fetchInfo();
    await fetchDevices();

    // If a scan is somehow already running, poll until it finishes
    if (scanning) {
      pollTimer = setInterval(async () => {
        await fetchDevices();
        if (!scanning) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      }, 700);
    }
  })();
})();