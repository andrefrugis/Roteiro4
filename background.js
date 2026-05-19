
// TLDs compostos mais comuns. Nao e a PSL inteira, mas pega os casos
// frequentes em sites brasileiros e internacionais.
const MULTI_PART_TLDS = new Set([
  "co.uk", "ac.uk", "gov.uk", "org.uk", "ltd.uk",
  "com.br", "org.br", "net.br", "gov.br", "edu.br",
  "com.au", "org.au", "net.au", "edu.au", "gov.au",
  "co.jp", "ne.jp", "ac.jp", "or.jp", "go.jp",
  "co.in", "org.in", "net.in", "gov.in", "ac.in",
  "com.mx", "com.ar", "com.co", "com.tr", "com.sg",
  "co.za", "co.kr", "co.nz", "co.id"
]);

function getRegistrableDomain(hostname) {
  if (!hostname) return "";
  if (/^[\d.]+$/.test(hostname) || hostname.includes(":")) return hostname;
  const parts = hostname.toLowerCase().split(".");
  if (parts.length < 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (parts.length >= 3 && MULTI_PART_TLDS.has(lastTwo)) return lastThree;
  return lastTwo;
}

// Trackers conhecidos (lista curta, ilustrativa). Em producao usaria
// algo como EasyPrivacy ou Disconnect.
const KNOWN_TRACKERS = new Set([
  "google-analytics.com", "googletagmanager.com", "googletagservices.com",
  "hotjar.com", "mixpanel.com", "segment.com", "segment.io", "amplitude.com",
  "mouseflow.com", "fullstory.com", "heap.io", "matomo.cloud", "clarity.ms",
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "adnxs.com", "adsrvr.org", "criteo.com", "criteo.net", "taboola.com",
  "outbrain.com", "rubiconproject.com", "openx.net", "pubmatic.com",
  "advertising.com", "moatads.com", "scorecardresearch.com", "quantserve.com",
  "facebook.com", "facebook.net", "fbcdn.net", "connect.facebook.net",
  "twitter.com", "ads-twitter.com", "t.co", "linkedin.com",
  "tiktok.com", "bytedance.com", "snapchat.com",
  "fingerprint.com", "fpjs.io", "fpcdn.io", "iovation.com", "perimeterx.net",
  "px-cdn.net", "px-client.net", "datadoghq.com"
]);

function blankTabState(url) {
  return {
    url: url || "",
    pageDomain: url ? getRegistrableDomain(new URL(url).hostname) : "",
    startedAt: Date.now(),
    requests: { total: 0, firstParty: 0, thirdParty: 0 },
    thirdPartyDomains: {},
    resourceTypes: {},
    cookies: {
      firstParty: 0, thirdParty: 0, session: 0, persistent: 0, list: []
    },
    supercookies: { etagSuspicion: 0, hstsSuspicion: 0, details: [] },
    fingerprinting: { canvas: 0, webgl: 0, audio: 0, events: [] },
    storage: { localStorage: [], sessionStorage: [], indexedDB: [] },
    hijacking: {
      suspiciousScripts: [],
      crossOriginRedirects: [],
      beefHookSuspected: false
    },
    cookieSyncing: { detected: false, events: [] },
    _paramIndex: {}
  };
}

const state = new Map();

function getOrInitState(tabId, url) {
  if (!state.has(tabId)) state.set(tabId, blankTabState(url));
  return state.get(tabId);
}

const SUSPICIOUS_SCRIPT_PATTERNS = [
  /\/hook\.js(\?|$)/i,
  /beef.*hook/i,
  /\/coinhive(\.min)?\.js/i,
  /\/cryptonight/i,
  /webminerpool/i
];

function isSuspiciousScript(url) {
  return SUSPICIOUS_SCRIPT_PATTERNS.some(rx => rx.test(url));
}

function looksLikeUserId(value) {
  if (typeof value !== "string") return false;
  if (value.length < 12 || value.length > 200) return false;
  return /^[A-Za-z0-9._\-+/=%]+$/.test(value) &&
         /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

function noteParamForSyncing(tabState, paramValue, host) {
  if (!looksLikeUserId(paramValue)) return;
  const idx = tabState._paramIndex;
  if (!idx[paramValue]) idx[paramValue] = new Set();
  idx[paramValue].add(host);
  if (idx[paramValue].size >= 2) {
    const domains = Array.from(idx[paramValue]);
    const already = tabState.cookieSyncing.events.find(e => e.value === paramValue);
    if (!already) {
      tabState.cookieSyncing.detected = true;
      tabState.cookieSyncing.events.push({
        value: paramValue.slice(0, 40) + (paramValue.length > 40 ? "..." : ""),
        domains
      });
    } else {
      already.domains = domains;
    }
  }
}

// Reseta o estado quando o usuario navega para uma nova pagina
browser.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  state.set(details.tabId, blankTabState(details.url));
  updateBadge(details.tabId);
});

// Cada requisicao: classifica em primeira/terceira parte, conta tipo,
// detecta scripts suspeitos e checa cookie syncing
browser.webRequest.onBeforeRequest.addListener(
  details => {
    const { tabId, url, type, originUrl, documentUrl } = details;
    if (tabId < 0) return;

    let ts = state.get(tabId);
    if (!ts) ts = getOrInitState(tabId, documentUrl || originUrl || url);

    ts.resourceTypes[type] = (ts.resourceTypes[type] || 0) + 1;
    ts.requests.total++;

    let host = "";
    try { host = new URL(url).hostname; } catch (_) { return; }
    const reqDomain = getRegistrableDomain(host);

    if (!ts.pageDomain && type === "main_frame") {
      ts.pageDomain = reqDomain;
      ts.url = url;
    }

    const isThird = ts.pageDomain && reqDomain !== ts.pageDomain;

    if (isThird) {
      ts.requests.thirdParty++;
      if (!ts.thirdPartyDomains[reqDomain]) {
        ts.thirdPartyDomains[reqDomain] = {
          count: 0, types: {}, knownTracker: KNOWN_TRACKERS.has(reqDomain)
        };
      }
      ts.thirdPartyDomains[reqDomain].count++;
      ts.thirdPartyDomains[reqDomain].types[type] =
        (ts.thirdPartyDomains[reqDomain].types[type] || 0) + 1;

      if (type === "script" && isSuspiciousScript(url)) {
        ts.hijacking.suspiciousScripts.push({ url, domain: reqDomain });
        if (/hook\.js/i.test(url)) ts.hijacking.beefHookSuspected = true;
      }

      try {
        const u = new URL(url);
        for (const [, v] of u.searchParams) {
          noteParamForSyncing(ts, v, reqDomain);
        }
      } catch (_) {}
    } else {
      ts.requests.firstParty++;
    }

    updateBadge(tabId);
  },
  { urls: ["<all_urls>"] }
);

// Headers: ETag e HSTS suspeitos (cookies sao lidos via cookies.getAll
// no momento de gerar o relatorio, ver buildReport mais abaixo)
browser.webRequest.onHeadersReceived.addListener(
  details => {
    const { tabId, url, responseHeaders } = details;
    if (tabId < 0 || !responseHeaders) return;
    const ts = state.get(tabId);
    if (!ts) return;

    let host = "";
    try { host = new URL(url).hostname; } catch (_) { return; }
    const reqDomain = getRegistrableDomain(host);
    const isThird = ts.pageDomain && reqDomain !== ts.pageDomain;

    for (const h of responseHeaders) {
      const name = h.name.toLowerCase();

      // ETag estavel em terceira parte = possivel supercookie
      if (name === "etag" && isThird && h.value && h.value.length >= 8) {
        ts.supercookies.etagSuspicion++;
        ts.supercookies.details.push({
          type: "ETag",
          domain: reqDomain,
          value: h.value.slice(0, 40)
        });
      }
      if (name === "strict-transport-security" && isThird) {
        ts.supercookies.hstsSuspicion++;
      }
    }
    updateBadge(tabId);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Redirecionamentos cross-origin no main_frame (hijacking)
browser.webRequest.onBeforeRedirect.addListener(
  details => {
    const { tabId, url, redirectUrl, type } = details;
    if (tabId < 0 || type !== "main_frame") return;
    const ts = state.get(tabId);
    if (!ts) return;
    try {
      const from = getRegistrableDomain(new URL(url).hostname);
      const to   = getRegistrableDomain(new URL(redirectUrl).hostname);
      if (from && to && from !== to) {
        ts.hijacking.crossOriginRedirects.push({ from, to });
      }
    } catch (_) {}
    updateBadge(tabId);
  },
  { urls: ["<all_urls>"] }
);

// Mensagens do content-script e do popup
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.kind) return;

  if (msg.kind === "storage-report") {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) return;
    const ts = getOrInitState(tabId, sender.tab.url);
    const { origin, localStorage, sessionStorage, indexedDB } = msg.payload;
    if (localStorage)   ts.storage.localStorage.push({ origin, ...localStorage });
    if (sessionStorage) ts.storage.sessionStorage.push({ origin, ...sessionStorage });
    if (indexedDB)      ts.storage.indexedDB.push({ origin, databases: indexedDB });
    updateBadge(tabId);
    return;
  }

  if (msg.kind === "fingerprint-event") {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) return;
    const ts = getOrInitState(tabId, sender.tab.url);
    const { api, method, frame } = msg.payload;
    if (api === "canvas") ts.fingerprinting.canvas++;
    if (api === "webgl")  ts.fingerprinting.webgl++;
    if (api === "audio")  ts.fingerprinting.audio++;
    ts.fingerprinting.events.push({ api, method, frame, ts: Date.now() });
    if (ts.fingerprinting.events.length > 100) ts.fingerprinting.events.shift();
    updateBadge(tabId);
    return;
  }

  // popup pediu o relatorio - retorna Promise (async)
  if (msg.kind === "get-report") {
    return buildReport(msg.tabId);
  }

  if (msg.kind === "reset-tab") {
    const tabId = msg.tabId;
    if (state.has(tabId)) {
      const url = state.get(tabId).url;
      state.set(tabId, blankTabState(url));
      updateBadge(tabId);
    }
    sendResponse({ ok: true });
    return true;
  }
});

// Monta o relatorio final. Le cookies via API (mais confiavel que so
// observar Set-Cookie, porque pega tambem cookies que ja estavam no jar)
async function buildReport(tabId) {
  const ts = state.get(tabId);
  if (!ts) return { ok: false, reason: "no-state" };

  try {
    const domains = new Set();
    if (ts.pageDomain) domains.add(ts.pageDomain);
    for (const d of Object.keys(ts.thirdPartyDomains)) domains.add(d);

    const seen = new Set();
    const list = [];
    let fp = 0, tp = 0, ss = 0, ps = 0;

    for (const d of domains) {
      let cs = [];
      try { cs = await browser.cookies.getAll({ domain: d }); } catch (_) {}
      for (const c of cs) {
        const key = c.domain + "|" + c.path + "|" + c.name;
        if (seen.has(key)) continue;
        seen.add(key);

        const cleanDomain = c.domain.replace(/^\./, "");
        const reg = getRegistrableDomain(cleanDomain);
        const party = reg === ts.pageDomain ? "first" : "third";
        const persistent = !c.session;

        list.push({
          domain: cleanDomain, name: c.name, party,
          type: persistent ? "persistent" : "session", persistent
        });
        if (party === "first") fp++; else tp++;
        if (persistent) ps++; else ss++;
      }
    }

    ts.cookies.firstParty = fp;
    ts.cookies.thirdParty = tp;
    ts.cookies.session = ss;
    ts.cookies.persistent = ps;
    ts.cookies.list = list;
  } catch (_) {
    // se a API falhar, mantemos o estado capturado por header
  }

  const report = serialize(ts);
  report.score = computePrivacyScore(ts);
  return { ok: true, report };
}

function serialize(ts) {
  const thirdParty = Object.entries(ts.thirdPartyDomains).map(([domain, info]) => ({
    domain, count: info.count, types: info.types, knownTracker: info.knownTracker
  })).sort((a, b) => b.count - a.count);

  return {
    url: ts.url,
    pageDomain: ts.pageDomain,
    requests: ts.requests,
    resourceTypes: ts.resourceTypes,
    thirdPartyDomains: thirdParty,
    cookies: {
      firstParty: ts.cookies.firstParty,
      thirdParty: ts.cookies.thirdParty,
      session: ts.cookies.session,
      persistent: ts.cookies.persistent,
      list: ts.cookies.list.slice(0, 200)
    },
    supercookies: ts.supercookies,
    fingerprinting: {
      canvas: ts.fingerprinting.canvas,
      webgl: ts.fingerprinting.webgl,
      audio: ts.fingerprinting.audio,
      events: ts.fingerprinting.events.slice(-50)
    },
    storage: ts.storage,
    hijacking: ts.hijacking,
    cookieSyncing: ts.cookieSyncing
  };
}

// ---------------------------------------------------------
// Privacy Score - metodologia documentada no README
// ---------------------------------------------------------
function computePrivacyScore(ts) {
  const breakdown = [];
  let total = 0;

  const tpDomains = Object.values(ts.thirdPartyDomains);
  const pDom = Math.min(30, tpDomains.length * 2);
  if (pDom > 0) { total += pDom; breakdown.push({ label: "Domínios de terceira parte", value: -pDom, detail: `${tpDomains.length} domínio(s)` }); }

  const trackers = tpDomains.filter(d => d.knownTracker).length;
  const pTrack = Math.min(15, trackers * 3);
  if (pTrack > 0) { total += pTrack; breakdown.push({ label: "Trackers conhecidos", value: -pTrack, detail: `${trackers} tracker(s)` }); }

  const pTpCookies = Math.min(20, ts.cookies.thirdParty * 2);
  if (pTpCookies > 0) { total += pTpCookies; breakdown.push({ label: "Cookies de terceira parte", value: -pTpCookies, detail: `${ts.cookies.thirdParty} cookie(s)` }); }

  const pPersist = Math.min(5, ts.cookies.persistent * 0.5);
  if (pPersist > 0) { total += pPersist; breakdown.push({ label: "Cookies persistentes", value: -pPersist, detail: `${ts.cookies.persistent} cookie(s)` }); }

  if (ts.supercookies.etagSuspicion > 0) {
    total += 10;
    breakdown.push({ label: "Supercookies (ETag)", value: -10, detail: `${ts.supercookies.etagSuspicion} ocorrência(s)` });
  }

  if (ts.fingerprinting.canvas > 0) { total += 8; breakdown.push({ label: "Canvas fingerprinting", value: -8, detail: `${ts.fingerprinting.canvas} chamada(s)` }); }
  if (ts.fingerprinting.webgl  > 0) { total += 8; breakdown.push({ label: "WebGL fingerprinting",  value: -8, detail: `${ts.fingerprinting.webgl} chamada(s)` }); }
  if (ts.fingerprinting.audio  > 0) { total += 8; breakdown.push({ label: "Audio fingerprinting",  value: -8, detail: `${ts.fingerprinting.audio} chamada(s)` }); }

  if (ts.cookieSyncing.detected) {
    total += 10;
    breakdown.push({ label: "Cookie syncing", value: -10, detail: `${ts.cookieSyncing.events.length} sync(s)` });
  }

  const pSusp = Math.min(30, ts.hijacking.suspiciousScripts.length * 15);
  if (pSusp > 0) { total += pSusp; breakdown.push({ label: "Scripts suspeitos (hooking/miner)", value: -pSusp, detail: `${ts.hijacking.suspiciousScripts.length} script(s)` }); }

  const pRed = Math.min(15, ts.hijacking.crossOriginRedirects.length * 5);
  if (pRed > 0) { total += pRed; breakdown.push({ label: "Redirecionamentos cross-origin", value: -pRed, detail: `${ts.hijacking.crossOriginRedirects.length} redir(s)` }); }

  const tpStorage = ts.storage.localStorage.filter(s => {
    try { return getRegistrableDomain(new URL(s.origin).hostname) !== ts.pageDomain; }
    catch (_) { return false; }
  }).length;
  const pStor = Math.min(10, tpStorage * 2);
  if (pStor > 0) { total += pStor; breakdown.push({ label: "localStorage de terceiros", value: -pStor, detail: `${tpStorage} origem(ns)` }); }

  const score = Math.max(0, Math.round(100 - total));
  let grade = "A", label = "Excelente";
  if (score < 85) { grade = "B"; label = "Bom"; }
  if (score < 70) { grade = "C"; label = "Médio"; }
  if (score < 55) { grade = "D"; label = "Ruim"; }
  if (score < 35) { grade = "F"; label = "Crítico"; }

  return { score, grade, label, breakdown };
}

function updateBadge(tabId) {
  const ts = state.get(tabId);
  if (!ts) return;
  const n = Object.keys(ts.thirdPartyDomains).length;
  const text = n > 0 ? String(n) : "";
  browser.browserAction.setBadgeText({ tabId, text });
  let color = "#16a34a";
  if (n > 5)  color = "#eab308";
  if (n > 15) color = "#dc2626";
  browser.browserAction.setBadgeBackgroundColor({ tabId, color });
}

browser.tabs.onRemoved.addListener(tabId => state.delete(tabId));
