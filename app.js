const state = {
  incidents: [
    { id: "SN-2026-405", time: "14:18:42", type: "SQL-инъекция (UNION SELECT)", ip: "185.220.101.44", target: "api-auth-01", severity: "CRITICAL", status: "Открыт" },
    { id: "SN-2026-404", time: "14:12:15", type: "Подбор паролей SSH (BruteForce)", ip: "91.134.188.21", target: "gw-metro-02", severity: "HIGH", status: "Открыт" },
    { id: "SN-2026-403", time: "13:55:09", type: "Межсайтовый скриптинг (XSS)", ip: "45.142.120.77", target: "web-portal", severity: "MEDIUM", status: "Открыт" },
    { id: "SN-2026-402", time: "13:31:50", type: "SQL-инъекция (DROP TABLE)", ip: "194.26.135.12", target: "db-proxy-01", severity: "CRITICAL", status: "Заблокирован" },
    { id: "SN-2026-401", time: "12:48:11", type: "Аномальное сканирование портов", ip: "10.14.8.19", target: "subnet-lab48", severity: "MEDIUM", status: "Закрыт" }
  ],
  wafRules: [
    { ip: "194.26.135.12", reason: "SQL-инъекция (DROP TABLE)", time: "13:32:01", active: true },
    { ip: "185.156.73.54", reason: "SSH_AUTH_FLOOD (BruteForce)", time: "11:15:22", active: true },
    { ip: "77.247.181.162", reason: "Повторные XSS-запросы", time: "10:04:19", active: true },
    { ip: "45.95.147.200", reason: "Сканирование уязвимостей", time: "09:20:45", active: true }
  ],
  cves: [
    { id: "CVE-2026-1142", pkg: "cryptography 42.0.2 (core-worker)", cvss: "8.2 (Высокий)", desc: "Ошибка проверки цепочки X.509 при нестандартном TLS-рукопожатии.", patched: false },
    { id: "CVE-2025-4810", pkg: "openssl 3.1.4 (api-gateway)", cvss: "7.5 (Высокий)", desc: "Потенциальный отказ в обслуживании при разборе некорректных пакетов.", patched: false },
    { id: "CVE-2025-2190", pkg: "nginx 1.24.0 (edge-proxy)", cvss: "5.3 (Средний)", desc: "Раскрытие версии веб-сервера в ответах с кодом 400.", patched: true }
  ],
  traffic: [4200, 4450, 4610, 4520, 4890, 5120, 4780, 4690, 4910, 4820],
  anomalies: [1, 0, 2, 1, 3, 5, 2, 1, 2, 1],
  nextId: 406
};

function nowTime() {
  return new Date().toTimeString().slice(0, 8);
}

function addLog(text, cls = "log-info") {
  const box = document.getElementById("auditLog");
  const div = document.createElement("div");
  div.className = "log-entry";
  div.innerHTML = `<span class="log-time">[${nowTime()}]</span> <span class="${cls}">${text}</span>`;
  box.prepend(div);
}

function renderKPIs() {
  const activeCount = state.incidents.filter(i => i.status === "Открыт").length;
  const blockedCount = state.wafRules.filter(r => r.active).length;
  document.getElementById("kpiActive").textContent = activeCount;
  document.getElementById("kpiBlocked").textContent = blockedCount;
  document.getElementById("archBlockedCount").textContent = blockedCount;
}

function renderIncidents() {
  const q = document.getElementById("searchInput").value.trim().toLowerCase();
  const sev = document.getElementById("severityFilter").value;
  const tbody = document.getElementById("incidentsBody");
  tbody.innerHTML = "";

  state.incidents
    .filter(item => (sev === "ALL" || item.severity === sev))
    .filter(item => !q || `${item.id} ${item.type} ${item.ip} ${item.target}`.toLowerCase().includes(q))
    .forEach(item => {
      const sevClass = item.severity === "CRITICAL" ? "b-crit" : (item.severity === "HIGH" ? "b-high" : "b-med");
      const stClass = item.status === "Открыт" ? "b-high" : (item.status === "Заблокирован" ? "b-ok" : "b-muted");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${item.id}</strong></td>
        <td>${item.time}</td>
        <td>${item.type}</td>
        <td><code>${item.ip}</code></td>
        <td>${item.target}</td>
        <td><span class="badge ${sevClass}">${item.severity}</span></td>
        <td><span class="badge ${stClass}">${item.status}</span></td>
        <td>
          ${item.status === "Открыт" ? `<button class="btn btn-primary btn-sm" onclick="blockIncident('${item.id}')">Блок IP</button>` : ""}
          ${item.status !== "Закрыт" ? `<button class="btn btn-outline btn-sm" onclick="closeIncident('${item.id}')">Закрыть</button>` : `<span class="muted">Архив</span>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  renderKPIs();
}

function renderWaf() {
  const tbody = document.getElementById("wafBody");
  tbody.innerHTML = "";
  state.wafRules.forEach((rule, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${rule.ip}</code></td>
      <td>${rule.reason}</td>
      <td>${rule.time}</td>
      <td><span class="badge ${rule.active ? "b-crit" : "b-ok"}">${rule.active ? "Заблокирован" : "Снято"}</span></td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="toggleWaf(${idx})">${rule.active ? "Разблокировать" : "Активировать"}</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
  renderKPIs();
}

function renderCves() {
  const tbody = document.getElementById("cveBody");
  tbody.innerHTML = "";
  state.cves.forEach((cve, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${cve.id}</strong></td>
      <td>${cve.pkg}</td>
      <td><span class="badge ${cve.patched ? "b-ok" : "b-high"}">${cve.cvss}</span></td>
      <td>${cve.desc}</td>
      <td><span class="badge ${cve.patched ? "b-ok" : "b-crit"}">${cve.patched ? "Устранена" : "Активна"}</span></td>
      <td>
        ${cve.patched ? `<span class="muted">Патч применён</span>` : `<button class="btn btn-primary btn-sm" onclick="patchCve(${idx})">Применить патч</button>`}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function drawChart() {
  const canvas = document.getElementById("trafficChart");
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = "#1e293b";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 4; i++) {
    const y = (H / 5) * i;
    ctx.beginPath(); ctx.moveTo(45, y); ctx.lineTo(W - 16, y); ctx.stroke();
  }

  // Bars for anomalies
  const step = (W - 70) / (state.traffic.length - 1);
  state.anomalies.forEach((val, idx) => {
    const x = 50 + idx * step;
    const bh = Math.min(H - 40, val * 22);
    ctx.fillStyle = "rgba(239, 68, 68, 0.38)";
    ctx.fillRect(x - 10, H - 20 - bh, 20, bh);
  });

  // Line for RPS
  ctx.strokeStyle = "#06b6d4";
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  state.traffic.forEach((val, idx) => {
    const x = 50 + idx * step;
    const y = H - 25 - ((val - 3500) / 2500) * (H - 55);
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Points
  ctx.fillStyle = "#10b981";
  state.traffic.forEach((val, idx) => {
    const x = 50 + idx * step;
    const y = H - 25 - ((val - 3500) / 2500) * (H - 55);
    ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2); ctx.fill();
  });
}

window.blockIncident = function (id) {
  const inc = state.incidents.find(i => i.id === id);
  if (!inc) return;
  inc.status = "Заблокирован";
  if (!state.wafRules.some(r => r.ip === inc.ip)) {
    state.wafRules.unshift({ ip: inc.ip, reason: inc.type, time: nowTime(), active: true });
  }
  addLog(`WAF: IP ${inc.ip} заблокирован по инциденту ${inc.id}`, "log-ok");
  renderIncidents();
  renderWaf();
};

window.closeIncident = function (id) {
  const inc = state.incidents.find(i => i.id === id);
  if (!inc) return;
  inc.status = "Закрыт";
  addLog(`SOC: Инцидент ${inc.id} переведён в статус «Закрыт»`, "log-info");
  renderIncidents();
};

window.toggleWaf = function (idx) {
  state.wafRules[idx].active = !state.wafRules[idx].active;
  const r = state.wafRules[idx];
  addLog(`WAF: Правило для ${r.ip} ${r.active ? "активировано" : "снято"}`, "log-info");
  renderWaf();
};

window.patchCve = function (idx) {
  state.cves[idx].patched = true;
  addLog(`SCA: Применён патч безопасности для ${state.cves[idx].id}`, "log-ok");
  renderCves();
};

// Tabs
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
  });
});

// Controls
document.getElementById("searchInput").addEventListener("input", renderIncidents);
document.getElementById("severityFilter").addEventListener("change", renderIncidents);
document.getElementById("btnClearLog").addEventListener("click", () => {
  document.getElementById("auditLog").innerHTML = "";
});

document.getElementById("btnSimulate").addEventListener("click", () => {
  const ip = `195.211.${Math.floor(Math.random() * 200 + 10)}.${Math.floor(Math.random() * 240 + 5)}`;
  const id = `SN-2026-${state.nextId++}`;
  state.incidents.unshift({
    id, time: nowTime(), type: "SQL-инъекция (' OR '1'='1)", ip,
    target: "api-gateway-prod", severity: "CRITICAL", status: "Открыт"
  });
  state.traffic.shift(); state.traffic.push(5450);
  state.anomalies.shift(); state.anomalies.push(6);
  document.getElementById("kpiRps").textContent = "5 450";
  addLog(`ТРЕВОГА [CRITICAL]: Обнаружена SQL-инъекция с ${ip} (${id})`, "log-crit");
  renderIncidents();
  drawChart();
});

document.getElementById("btnExport").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), ...state }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "securnet-report-2026.json";
  a.click();
  addLog("Экспорт: Выгружен отчёт securnet-report-2026.json", "log-ok");
});

document.getElementById("wafForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const ip = document.getElementById("wafIpInput").value.trim();
  const reason = document.getElementById("wafReasonInput").value.trim();
  if (!ip.includes(".")) return alert("Введите корректный IPv4-адрес");
  state.wafRules.unshift({ ip, reason, time: nowTime(), active: true });
  document.getElementById("wafIpInput").value = "";
  document.getElementById("wafReasonInput").value = "";
  addLog(`WAF: Добавлено ручное правило блокировки для ${ip}`, "log-ok");
  renderWaf();
});

document.getElementById("btnRescanCve").addEventListener("click", () => {
  addLog("SCA: Запущено повторное сканирование зависимостей (уязвимостей без патча: " + state.cves.filter(c => !c.patched).length + ")", "log-info");
});

document.getElementById("btnDrTest").addEventListener("click", () => {
  document.getElementById("drStatusText").textContent = `Последний DR-тест: Успешно (${nowTime()}, целостность 100%)`;
  addLog("DR-тест: Восстановление резервной копии PostgreSQL выполнено успешно", "log-ok");
});

// Init
addLog("Система SecurNet Shield v2.0.1 инициализирована. Сканер активен.", "log-ok");
addLog("Загружен пакет сигнатур sig-2026.11 (SQLi, XSS, BruteForce).", "log-info");
addLog("Обнаружен критический инцидент SN-2026-405 (185.220.101.44).", "log-crit");
renderIncidents();
renderWaf();
renderCves();
drawChart();

setInterval(() => {
  const nextRps = Math.floor(4400 + Math.random() * 800);
  state.traffic.shift(); state.traffic.push(nextRps);
  state.anomalies.shift(); state.anomalies.push(Math.floor(Math.random() * 3));
  document.getElementById("kpiRps").textContent = nextRps.toLocaleString("ru-RU");
  drawChart();
}, 4000);
