

(function () {
  "use strict";

  // Injeta o script no contexto da pagina
  try {
    const s = document.createElement("script");
    s.src = browser.runtime.getURL("inject.js");
    s.async = false;
    s.onload = () => s.remove();
    (document.head || document.documentElement).appendChild(s);
  } catch (e) {}

  // Eventos de fingerprinting vem do inject.js via postMessage
  window.addEventListener("message", evt => {
    if (evt.source !== window) return;
    const data = evt.data;
    if (!data || data.__pg !== true) return;

    if (data.kind === "fingerprint-event") {
      browser.runtime.sendMessage({
        kind: "fingerprint-event",
        payload: { api: data.api, method: data.method, frame: location.href }
      }).catch(() => {});
    }
  });

  function readStorage(store) {
    const keys = [];
    let totalSize = 0;
    try {
      for (let i = 0; i < store.length; i++) {
        const name = store.key(i);
        const value = store.getItem(name) || "";
        const size = name.length + value.length;
        totalSize += size;
        keys.push({ name, size });
      }
    } catch (_) {}
    return { keys, totalSize, count: keys.length };
  }

  function collectStorage() {
    const origin = location.origin;
    const ls = readStorage(window.localStorage);
    const ss = readStorage(window.sessionStorage);
    browser.runtime.sendMessage({
      kind: "storage-report",
      payload: { origin, localStorage: ls, sessionStorage: ss }
    }).catch(() => {});

    if (window.indexedDB && typeof indexedDB.databases === "function") {
      indexedDB.databases().then(dbs => {
        browser.runtime.sendMessage({
          kind: "storage-report",
          payload: {
            origin,
            indexedDB: dbs.map(d => ({ name: d.name, version: d.version }))
          }
        }).catch(() => {});
      }).catch(() => {});
    }
  }

  // Coleta automatica em alguns momentos para pegar chaves
  // que so sao gravadas apos o load
  function schedule() {
    collectStorage();
    setTimeout(collectStorage, 2000);
    setTimeout(collectStorage, 8000);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", schedule);
  } else {
    schedule();
  }

  // O popup pede uma coleta na hora que e aberto, para garantir
  // que vemos o estado atual e nao o da ultima janela agendada
  browser.runtime.onMessage.addListener((msg) => {
    if (msg && msg.kind === "collect-now") {
      collectStorage();
    }
  });
})();
