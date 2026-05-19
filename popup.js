

const $ = sel => document.querySelector(sel);
let currentTabId = null;

async function init() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab) return;
  currentTabId = tab.id;
  await refresh();

  document.querySelectorAll(".pg-tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".pg-tab").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".pg-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
    });
  });

  $("#refresh").addEventListener("click", refresh);
  $("#reset").addEventListener("click", async () => {
    await browser.runtime.sendMessage({ kind: "reset-tab", tabId: currentTabId });
    await refresh();
  });
}

async function refresh() {
  // forca o content-script a coletar storage agora, para nao depender
  // do agendamento (DOMContentLoaded + 2s + 8s)
  try {
    await browser.tabs.sendMessage(currentTabId, { kind: "collect-now" });
  } catch (_) {
    // aba sem content script (about:, file://, paginas internas)
  }
  // pequena espera para a mensagem chegar no background
  await new Promise(r => setTimeout(r, 200));

  let res;
  try {
    res = await browser.runtime.sendMessage({ kind: "get-report", tabId: currentTabId });
  } catch (e) {
    showEmpty("Não foi possível obter dados.");
    return;
  }
  if (!res || !res.ok) {
    showEmpty("Recarregue a página para coletar dados.");
    return;
  }
  render(res.report);
}

function showEmpty(msg) {
  $("#score-label").textContent = msg;
  $("#score-value").textContent = "--";
  $("#score-grade").textContent = "·";
  $("#page-domain").textContent = "—";
}

function render(r) {
  const sc = r.score;
  $("#score-value").textContent = sc.score;
  $("#score-grade").textContent = sc.grade;
  $("#score-label").textContent = sc.label;
  $("#page-domain").textContent = r.pageDomain || "—";
  const circle = $("#score-circle");
  circle.className = "pg-score-circle grade-" + sc.grade;

  $("#ov-reqs").textContent   = r.requests.total;
  $("#ov-third").textContent  = r.thirdPartyDomains.length;
  $("#ov-cookies").textContent = r.cookies.firstParty + r.cookies.thirdParty;
  const fpTotal = r.fingerprinting.canvas + r.fingerprinting.webgl + r.fingerprinting.audio;
  $("#ov-fp").textContent = fpTotal;

  fillList("#ov-breakdown", sc.breakdown,
    sc.breakdown.length === 0
      ? [{ name: "Nenhuma penalidade aplicada", tagClass: "good", tag: "OK" }]
      : sc.breakdown.map(b => ({
          name: b.label, sub: b.detail,
          tag: b.value + " pts",
          tagClass: b.value <= -10 ? "tracker" : "warn"
        }))
  );

  fillList("#tp-list", r.thirdPartyDomains, r.thirdPartyDomains.map(d => ({
    name: d.domain,
    sub: Object.keys(d.types).join(", "),
    tag: d.knownTracker ? "tracker · " + d.count : d.count + " req",
    tagClass: d.knownTracker ? "tracker" : "warn"
  })), "Nenhum domínio de terceira parte detectado");

  $("#ck-fp").textContent = r.cookies.firstParty;
  $("#ck-tp").textContent = r.cookies.thirdParty;
  $("#ck-ss").textContent = r.cookies.session;
  $("#ck-ps").textContent = r.cookies.persistent;

  fillList("#ck-super", r.supercookies.details, r.supercookies.details.map(s => ({
    name: s.domain + " (" + s.type + ")",
    sub: s.value,
    tag: "supercookie",
    tagClass: "tracker"
  })), "Nenhum supercookie suspeito");

  fillList("#ck-list", r.cookies.list, r.cookies.list.map(c => ({
    name: c.name + " @ " + c.domain,
    tag: (c.party === "third" ? "3ª · " : "1ª · ") + (c.persistent ? "persist" : "sessão"),
    tagClass: c.party === "third" ? "warn" : ""
  })), "Nenhum cookie observado");

  $("#fp-canvas").textContent = r.fingerprinting.canvas;
  $("#fp-webgl").textContent  = r.fingerprinting.webgl;
  $("#fp-audio").textContent  = r.fingerprinting.audio;
  fillList("#fp-events", r.fingerprinting.events, r.fingerprinting.events.slice().reverse().map(e => ({
    name: e.api + "." + e.method,
    sub: shortUrl(e.frame),
    tag: new Date(e.ts).toLocaleTimeString(),
    tagClass: "warn"
  })), "Nenhuma chamada de fingerprinting detectada");

  fillList("#st-local", r.storage.localStorage,
    flattenStorage(r.storage.localStorage),
    "Sem entradas em localStorage"
  );
  fillList("#st-session", r.storage.sessionStorage,
    flattenStorage(r.storage.sessionStorage),
    "Sem entradas em sessionStorage"
  );
  fillList("#st-idb", r.storage.indexedDB, r.storage.indexedDB.flatMap(o =>
    (o.databases || []).map(db => ({
      name: db.name || "(sem nome)",
      sub: o.origin,
      tag: "v" + (db.version || "?"),
      tagClass: "warn"
    }))
  ), "Sem bancos IndexedDB observados");

  fillList("#hj-scripts", r.hijacking.suspiciousScripts,
    r.hijacking.suspiciousScripts.map(s => ({
      name: shortUrl(s.url),
      sub: s.domain,
      tag: "suspeito",
      tagClass: "tracker"
    })),
    "Nenhum script suspeito detectado"
  );
  fillList("#hj-redirs", r.hijacking.crossOriginRedirects,
    r.hijacking.crossOriginRedirects.map(rd => ({
      name: rd.from + " → " + rd.to,
      tag: "redir",
      tagClass: "warn"
    })),
    "Sem redirecionamentos cross-origin"
  );
  fillList("#hj-sync", r.cookieSyncing.events,
    r.cookieSyncing.events.map(e => ({
      name: e.value,
      sub: e.domains.join(" ↔ "),
      tag: "sync",
      tagClass: "tracker"
    })),
    "Sem sinais de cookie syncing"
  );
}

function flattenStorage(arr) {
  const map = new Map();
  for (const s of arr) {
    const cur = map.get(s.origin);
    if (!cur || (s.keys && s.keys.length >= cur.keys.length)) map.set(s.origin, s);
  }
  const out = [];
  for (const [origin, s] of map) {
    if (!s.keys || !s.keys.length) continue;
    for (const k of s.keys.slice(0, 15)) {
      out.push({
        name: k.name,
        sub: origin,
        tag: humanSize(k.size),
        tagClass: "warn"
      });
    }
  }
  return out;
}

function humanSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " kB";
  return (n / (1024 * 1024)).toFixed(1) + " MB";
}

function shortUrl(u) {
  if (!u) return "";
  try {
    const x = new URL(u);
    return x.hostname + (x.pathname.length > 1 ? x.pathname.slice(0, 30) : "");
  } catch (_) { return u.slice(0, 40); }
}

function fillList(sel, sourceArr, items, emptyMsg) {
  const ul = document.querySelector(sel);
  ul.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = emptyMsg || "Nada por aqui ainda";
    ul.appendChild(li);
    return;
  }
  for (const it of items) {
    const li = document.createElement("li");
    const nameEl = document.createElement("div");
    nameEl.className = "name";
    nameEl.innerHTML = "<div>" + escapeHTML(it.name || "") + "</div>" +
      (it.sub ? '<div style="color:var(--text-dim);font-size:10px;margin-top:2px">' +
        escapeHTML(it.sub) + "</div>" : "");
    li.appendChild(nameEl);
    if (it.tag) {
      const tag = document.createElement("span");
      tag.className = "pg-tag" + (it.tagClass ? " " + it.tagClass : "");
      tag.textContent = it.tag;
      li.appendChild(tag);
    }
    ul.appendChild(li);
  }
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  }[c]));
}

init();
