"use strict";

const $ = (id) => document.getElementById(id);

// Stato condiviso tra "Anonimizza" e "Ripristina".
let lastSessionId = null;
let lastMapping = null;        // valorizzato solo in modalità zero-knowledge

// ---- HTTP helpers (con API key opzionale) ----
function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  const k = $("apikey").value.trim();
  if (k) h["X-API-Key"] = k;
  return h;
}
async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Errore ${res.status}`);
  return data;
}
const apiJson = (path, body) =>
  fetch(path, { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body) }).then(handle);
const apiForm = (path, fd) =>
  fetch(path, { method: "POST", headers: authHeaders(), body: fd }).then(handle);
const apiGet = (path) => fetch(path, { headers: authHeaders() }).then(handle);
const apiDelete = (path) => fetch(path, { method: "DELETE", headers: authHeaders() }).then(handle);

function setStatus(id, msg, isErr = false) {
  const el = $(id);
  el.textContent = msg || "";
  el.classList.toggle("err", !!isErr);
}
function types(val) {
  const t = val.trim();
  return t ? t.split(",").map((x) => x.trim()).filter(Boolean) : null;
}
async function copyText(text, statusId) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus(statusId, "Copiato negli appunti.");
  } catch (_) {
    setStatus(statusId, "Copia non riuscita (usa Ctrl/Cmd+C).", true);
  }
}

// ---- Tabs ----
function showTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
}
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ============ ANONIMIZZA ============
$("a-run").addEventListener("click", async () => {
  const file = $("a-file").files[0];
  const conf = parseFloat($("a-conf").value) || 0.7;
  const zk = $("a-zk").checked;
  setStatus("a-status", "Elaborazione…");
  try {
    let data;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("confidence", String(conf));
      fd.append("use_ner", $("a-ner").checked ? "true" : "false");
      fd.append("include_values", $("a-values").checked ? "true" : "false");
      fd.append("stateless", zk ? "true" : "false");
      const t = $("a-types").value.trim();
      if (t) fd.append("entity_types", t);
      data = await apiForm("/api/anonymize-file", fd);
    } else {
      const text = $("a-text").value.trim();
      if (!text) { setStatus("a-status", "Inserisci del testo o scegli un file.", true); return; }
      data = await apiJson("/api/anonymize", {
        text, confidence: conf, use_ner: $("a-ner").checked,
        include_values: $("a-values").checked, stateless: zk, entity_types: types($("a-types").value),
      });
    }
    lastSessionId = data.session_id || null;
    lastMapping = data.mapping || null;
    $("a-out").hidden = false;
    $("a-result").textContent = data.anonymized_text || "";
    $("a-count").textContent = (data.entity_count ?? 0) + " entità";
    $("a-valid").textContent = data.validation?.is_valid ? "validazione ✔" : "validazione ✖";
    $("a-sid").textContent = lastSessionId || (lastMapping ? "zero-knowledge (mappa nel browser)" : "—");
    // entità con valori (se richiesto)
    const withVals = (data.entities || []).some((e) => "value" in e);
    $("a-entities").hidden = !withVals;
    if (withVals) $("a-entities-pre").textContent = data.entities.map((e) => `${e.type}: ${e.value}`).join("\n");
    // mappa zero-knowledge
    $("a-mapping").hidden = !lastMapping;
    if (lastMapping) $("a-mapping-pre").textContent = JSON.stringify(lastMapping, null, 2);
    // prepara la scheda Ripristina
    $("r-sid").value = lastSessionId || "";
    $("r-zk-note").hidden = !lastMapping;
    setStatus("a-status", "Fatto. Copia il testo, dallo alla tua AI, poi vai su «Ripristina».");
  } catch (e) {
    setStatus("a-status", e.message, true);
  }
});
$("a-copy").addEventListener("click", () => copyText($("a-result").textContent, "a-status"));
$("a-mapcopy").addEventListener("click", () => copyText($("a-mapping-pre").textContent, "a-status"));

// ============ RIPRISTINA ============
$("r-run").addEventListener("click", async () => {
  const text = $("r-text").value.trim();
  if (!text) { setStatus("r-status", "Incolla la risposta dell'AI.", true); return; }
  setStatus("r-status", "Ripristino…");
  try {
    let body;
    if (lastMapping) {
      body = { text, mapping: lastMapping };          // zero-knowledge
    } else {
      const sid = $("r-sid").value.trim();
      if (!sid) { setStatus("r-status", "Manca l'ID sessione.", true); return; }
      body = { text, session_id: sid };
    }
    const data = await apiJson("/api/rehydrate", body);
    $("r-out").hidden = false;
    $("r-result").textContent = data.rehydrated_text || "";
    $("r-valid").textContent = data.validation?.is_valid ? "validazione ✔" : "validazione ✖ (controlla i placeholder)";
    setStatus("r-status", "Fatto.");
  } catch (e) {
    setStatus("r-status", e.message, true);
  }
});
$("r-copy").addEventListener("click", () => copyText($("r-result").textContent, "r-status"));

// ============ PIPELINE LLM ============
$("p-run").addEventListener("click", async () => {
  const file = $("p-file").files[0];
  const conf = parseFloat($("p-conf").value) || 0.7;
  setStatus("p-status", "Elaborazione (può richiedere qualche secondo)…");
  try {
    let data;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("provider", $("p-provider").value);
      fd.append("model", $("p-model").value.trim());
      fd.append("prompt", $("p-prompt").value);
      fd.append("system_prompt", $("p-system").value);
      fd.append("confidence", String(conf));
      fd.append("use_ner", $("p-ner").checked ? "true" : "false");
      fd.append("max_chunk", $("p-chunk").value || "12000");
      fd.append("stateless", $("p-zk").checked ? "true" : "false");
      const t = $("p-types").value.trim();
      if (t) fd.append("entity_types", t);
      data = await apiForm("/api/process-file", fd);
    } else {
      const text = $("p-text").value.trim();
      if (!text) { setStatus("p-status", "Inserisci del testo o scegli un file.", true); return; }
      data = await apiJson("/api/process", {
        text, provider: $("p-provider").value, model: $("p-model").value.trim() || null,
        prompt: $("p-prompt").value, system_prompt: $("p-system").value || null,
        confidence: conf, use_ner: $("p-ner").checked, max_chunk: parseInt($("p-chunk").value) || 12000,
        stateless: $("p-zk").checked, entity_types: types($("p-types").value),
      });
    }
    $("p-out").hidden = false;
    $("p-final").textContent = data.final_response || "";
    $("p-anon").textContent = data.anonymized_text || "";
    $("p-raw").textContent = data.llm_response_anonymized || "(non disponibile)";
    $("p-valid").textContent = data.validation?.anonymization?.is_valid ? "validazione ✔" : "validazione ✖";
    $("p-sid").textContent = data.session_id || "zero-knowledge / nessuna";
    setStatus("p-status", "Fatto.");
  } catch (e) {
    setStatus("p-status", e.message, true);
  }
});
$("p-provider").addEventListener("change", () => {
  $("p-model").placeholder = $("p-provider").value === "demo" ? "(ignorato dal demo)" : "(default del provider)";
});

// ============ SESSIONI ============
$("s-status").addEventListener("click", async () => {
  const id = $("s-id").value.trim();
  if (!id) { setStatus("s-status-msg", "Inserisci un ID sessione.", true); return; }
  try {
    const data = await apiGet(`/api/session/${encodeURIComponent(id)}`);
    $("s-out").hidden = false;
    $("s-out").textContent = `attiva: ${data.active}\nentità: ${data.entity_count}\nscade tra: ${data.expires_in}s`;
    setStatus("s-status-msg", "");
  } catch (e) {
    $("s-out").hidden = true;
    setStatus("s-status-msg", e.message, true);
  }
});
$("s-del").addEventListener("click", async () => {
  const id = $("s-id").value.trim();
  if (!id) { setStatus("s-status-msg", "Inserisci un ID sessione.", true); return; }
  try {
    await apiDelete(`/api/session/${encodeURIComponent(id)}`);
    $("s-out").hidden = true;
    setStatus("s-status-msg", "Sessione eliminata.");
  } catch (e) {
    setStatus("s-status-msg", e.message, true);
  }
});

// Comodità: Ctrl/Cmd+Invio dentro una textarea avvia l'operazione della scheda.
function submitOnCtrlEnter(textareaId, buttonId) {
  const ta = $(textareaId);
  if (ta) ta.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); $(buttonId).click(); }
  });
}
submitOnCtrlEnter("a-text", "a-run");
submitOnCtrlEnter("r-text", "r-run");
submitOnCtrlEnter("p-text", "p-run");
