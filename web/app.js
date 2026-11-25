// UI for the fuzzy aPAKE walkthrough. All protocol values come from worker.js (Python).

const N = 8;
const state = {
  registered: [1, 0, 1, 0, 1, 0, 1, 0],
  attempt: [1, 0, 1, 0, 1, 0, 1, 1],
  scenario: "honest",
  target: 2,
  group: "demo",
};

const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (value, keep = 6) => {
  const s = String(value);
  return s.length <= keep * 2 + 1 ? s : `${s.slice(0, keep)}…${s.slice(-(keep - 2))}`;
};
const val = (value) => `<span class="val" title="${esc(value)}">${esc(short(value))}</span>`;
const chip = (label, value, title = value) =>
  `<span class="chip"><span class="k">${label}</span><span title="${esc(title)}">${esc(short(value, 7))}</span></span>`;

// ------------------------------------------------------------------ worker

const worker = new Worker("worker.js");
const calls = new Map();
let nextId = 1;
let pythonReady = false;

function call(options) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    calls.set(id, { resolve, reject });
    worker.postMessage({ id, options });
  });
}

function setRuntime(stateName, text) {
  $("#runtime").dataset.state = stateName;
  $("#runtime-text").textContent = text;
}

worker.onmessage = ({ data }) => {
  if (data.type === "status") return setRuntime("loading", data.text);
  if (data.type === "ready") {
    pythonReady = true;
    return setRuntime("ready", `Python ${data.python} · fapake running in your browser`);
  }
  if (data.type === "fatal") {
    setRuntime("error", "Python runtime failed to load");
    return showError(data.error);
  }
  const pending = calls.get(data.id);
  if (!pending) return;
  calls.delete(data.id);
  data.ok ? pending.resolve(data.trace) : pending.reject(new Error(data.error));
};

function showError(message) {
  const box = $("#error");
  box.textContent = message;
  box.hidden = !message;
}

// ------------------------------------------------------------------ controls

function renderBits() {
  for (const which of ["registered", "attempt"]) {
    $(`#bits-${which}`).innerHTML = state[which].map((bit, i) => {
      const diff = which === "attempt" && bit !== state.registered[i];
      return `<button type="button" class="bit${diff ? " diff" : ""}" data-which="${which}" data-i="${i}"
        aria-pressed="${bit === 1}" aria-label="${which} bit ${i + 1}: ${bit}${diff ? " (differs)" : ""}">${bit}</button>`;
    }).join("");
  }
  const d = state.attempt.filter((bit, i) => bit !== state.registered[i]).length;
  $("#distance").innerHTML = d === 0
    ? "Identical passwords."
    : `<b>${d} bit${d > 1 ? "s" : ""}</b> different: ${d <= 1
        ? '<span class="ok">within tolerance</span> (up to 1 wrong bit is allowed)'
        : '<span class="no">beyond tolerance</span> (only 1 wrong bit is allowed)'}`;
}

function renderScenario() {
  const wrap = $("#target-wrap");
  wrap.hidden = state.scenario === "honest";
  const bit = state.target + 1;
  $("#scenario-note").textContent = {
    "honest": "",
    "corrupt-share": `The stored real share at bit ${bit} is overwritten, as if the disk were damaged. Error correction absorbs one bad share, but not one bad share plus a wrong bit.`,
    "cheating-server": `After encrypting, the server swaps in a different pair at bit ${bit} for the transfer. Reconstruction alone would not notice. The client's consistency check does.`,
  }[state.scenario];
}

const randomBits = () => Array.from({ length: N }, () => Math.round(Math.random()));
const distinctPositions = (count) => {
  const all = [...Array(N).keys()].sort(() => Math.random() - 0.5);
  return all.slice(0, count);
};
const flipped = (bits, positions) => bits.map((b, i) => (positions.includes(i) ? 1 - b : b));

function applyPreset(name) {
  if (name === "random") {
    state.registered = randomBits();
    state.attempt = flipped(state.registered, distinctPositions(Math.floor(Math.random() * 3)));
  } else {
    const count = { same: 0, one: 1, two: 2 }[name];
    state.attempt = flipped(state.registered, distinctPositions(count));
  }
}

function wireControls() {
  document.addEventListener("click", (event) => {
    const bit = event.target.closest(".bit");
    if (bit) {
      const list = state[bit.dataset.which];
      list[+bit.dataset.i] ^= 1;
      return changed();
    }
    const preset = event.target.closest("[data-preset]");
    if (preset) {
      applyPreset(preset.dataset.preset);
      return changed();
    }
  });
  for (const name of ["scenario", "group"]) {
    document.querySelectorAll(`input[name=${name}]`).forEach((input) =>
      input.addEventListener("change", () => { state[name] = input.value; changed(); }));
  }
  $("#target").innerHTML = [...Array(N).keys()].map((i) =>
    `<option value="${i}"${i === state.target ? " selected" : ""}>${i + 1}</option>`).join("");
  $("#target").addEventListener("change", (e) => { state.target = +e.target.value; changed(); });
  $("#replay").addEventListener("click", replay);
}

let timer = null;
function changed() {
  renderBits();
  renderScenario();
  clearTimeout(timer);
  timer = setTimeout(update, 120);
}

// ------------------------------------------------------------------ running

let generation = 0;

async function update() {
  const mine = ++generation;
  $("#stages").setAttribute("aria-busy", "true");
  if (pythonReady) {
    setRuntime("busy", state.group === "demo" ? "Computing…"
      : "Computing in the 2048-bit group… (the first run also generates a 3072-bit RSA key)");
  }
  try {
    const trace = await call({ ...state });
    if (mine !== generation) return;
    showError("");
    render(trace);
  } catch (error) {
    if (mine === generation) showError(error.message);
  } finally {
    if (mine === generation) {
      $("#stages").setAttribute("aria-busy", "false");
      if (pythonReady) setRuntime("ready", $("#runtime-text").dataset.ready || "Ready");
    }
  }
}

// ------------------------------------------------------------------ rendering

const KIND_CLASS = { real: "real", decoy: "decoy", corrupted: "bad", altered: "bad" };
const KIND_LABEL = { real: "real share", decoy: "decoy", corrupted: "damaged share", altered: "altered share" };

function render(t) {
  renderRegistration(t);
  renderServer(t);
  renderOT(t);
  renderReconstruction(t);
  renderResult(t);
  replay();

  const ms = Object.values(t.timings_ms).reduce((a, b) => a + b, 0) - (t.timings_ms.ot_key || 0);
  $("#timing").textContent =
    `Last run: ${ms.toFixed(0)} ms of Python in the ${t.params.group.bits}-bit group, OT key ${t.params.ot_key_bits} bits.`;
  const readyText = `Python ready · ${t.params.group.name === "demo" ? "demo group" : "2048-bit group"}`;
  $("#runtime-text").dataset.ready = readyText;
}

function legend(extra = "") {
  return `<div class="legend"><span><i class="real"></i>real share</span><span><i class="decoy"></i>decoy</span>${extra}</div>`;
}

function renderRegistration(t) {
  const r = t.registration;
  const damaged = t.scenario.kind === "corrupt-share";
  const cols = r.stored.map((pair, i) => {
    const realSlot = t.registered[i];
    const cells = pair.map((value, slot) => {
      const isReal = slot === realSlot;
      const bad = damaged && i === t.scenario.target && isReal;
      const cls = bad ? "bad" : isReal ? "real" : "decoy";
      return `<div class="cell ${cls}"><span class="slot">slot ${slot}</span>${val(value)}${bad ? '<span class="flag">damaged</span>' : ""}</div>`;
    }).join("");
    return `<div class="col" style="--i:${i}"><div class="col-head">bit ${i + 1}<b>${realSlot}</b></div>${cells}</div>`;
  }).join("");

  $("#viz-register").innerHTML = `
    <div class="line">
      ${chip("secret k =", r.k)} <span class="arrow">→ 8 shares, any 6 rebuild k →</span>
      ${chip("stored g<sup>k</sup> =", r.g_k)}
      ${chip("stored g<sup>pw</sup> =", r.g_pw)}
    </div>
    <div class="grid8">${cols}</div>
    ${legend(damaged ? '<span><i class="bad"></i>damaged on disk</span>' : "")}`;
}

function renderServer(t) {
  const s = t.server;
  const cheat = t.scenario.kind === "cheating-server";
  const cols = s.randomized.map((pair, i) => {
    const realSlot = t.registered[i];
    const altered = cheat && i === t.scenario.target;
    const damaged = t.scenario.kind === "corrupt-share" && i === t.scenario.target;
    const cells = pair.map((value, slot) => {
      const isReal = slot === realSlot;
      const cls = altered || (damaged && isReal) ? "bad" : isReal ? "real" : "decoy";
      return `<div class="cell ${cls}"><span class="slot">slot ${slot}</span>${val(value)}${altered ? '<span class="flag">altered</span>' : ""}</div>`;
    }).join("");
    return `<div class="col" style="--i:${i}"><div class="col-head">bit ${i + 1}<b>${realSlot}</b></div>
      <div class="mask" title="${esc(s.masks[i])}">× g^r${i + 1} = ${esc(short(s.masks[i], 5))}</div>${cells}</div>`;
  }).join("");

  const bytes = s.cipher.ciphertext.length / 2;
  $("#viz-server").innerHTML = `
    <div class="line">
      ${chip("fresh r =", s.r)} <span class="arrow">→</span>
      ${chip("K = g<sup>k+r</sup> =", s.K)} <span class="arrow">→</span>
      ${chip(`Enc<sub>K</sub>(pairs, g<sup>pw</sup>), ${bytes} bytes:`, s.cipher.ciphertext)}
    </div>
    <div class="grid8">${cols}</div>
    ${legend(cheat ? '<span><i class="bad"></i>changed after encryption</span>' : "")}`;
}

function renderOT(t) {
  const cols = t.ot.map((round, i) => {
    const pair = t.server.randomized[i];
    const cells = pair.map((value, slot) => {
      if (slot !== round.bit) {
        return `<div class="cell untaken"><span class="slot">slot ${slot}</span><span class="val">hidden</span></div>`;
      }
      return `<div class="cell taken ${KIND_CLASS[round.kind]}"><span class="slot">slot ${slot}</span>${val(round.received)}</div>`;
    }).join("");
    const tagClass = KIND_CLASS[round.kind];
    return `<div class="col" style="--i:${i}">
      <div class="col-head">bit ${i + 1}<b>${round.bit}</b></div>
      <div class="ask">client asks for slot <b>${round.bit}</b></div>
      ${cells}
      <div class="got"><span class="tag ${tagClass}">${KIND_LABEL[round.kind]}</span></div>
      <div class="seen" title="${esc(round.v)}">server sees v = ${esc(short(round.v, 4))}</div>
    </div>`;
  }).join("");
  $("#viz-ot").innerHTML = `<div class="grid8 ot">${cols}</div>`;
}

function renderReconstruction(t) {
  const rec = t.reconstruction;
  const bad = new Set(t.ot.filter((r) => r.kind !== "real").map((r) => r.i + 1));
  const winner = rec.winner;
  const tiles = rec.votes.map((vote, i) => {
    const win = winner !== null && vote.candidate === winner;
    const dots = [...Array(N).keys()].map((k) => {
      const on = vote.xs.includes(k + 1);
      return `<span class="${on ? "on" : ""}${on && bad.has(k + 1) ? " bad" : ""}"></span>`;
    }).join("");
    return `<div class="subset${win ? " win" : ""}" style="--i:${i}" title="shares ${vote.xs.join(", ")}">
      <div class="dots">${dots}</div><span>{${vote.xs.join(",")}}</span></div>`;
  }).join("");

  const top = rec.candidates[0];
  const verdict = winner !== null
    ? `<span class="big" style="color:var(--good)">${top.count}/${rec.subsets}</span>
       <span>sets agree on <b class="chip" title="${esc(top.value)}">K′ = ${esc(short(top.value, 7))}</b>${top.value === t.server.K ? ", which is the server's K" : ""}</span>`
    : `<span class="big" style="color:var(--bad)">no majority</span>
       <span>every value has the same number of votes, so the client can't recover K</span>`;

  const shown = rec.candidates.slice(0, 5);
  const rest = rec.candidates.length - shown.length;
  const bars = shown.map((c, i) => `
    <div class="cand${winner === i ? " win" : ""}">
      <span title="${esc(c.value ?? "")}">${c.value === null ? "other value" : esc(short(c.value, 6))}</span>
      <span class="bar"><i style="width:${(100 * c.count / rec.subsets).toFixed(1)}%"></i></span>
      <span class="n">${c.count}</span>
    </div>`).join("");

  $("#viz-reconstruct").innerHTML = `
    <div class="verdict">${verdict}</div>
    <div class="subsets">${tiles}</div>
    <div class="candidates">${bars}${rest > 0 ? `<div class="legend">+ ${rest} more value${rest > 1 ? "s" : ""} with a single vote each</div>` : ""}</div>
    <div class="legend"><span><i style="background:var(--ink)"></i>share used</span><span><i class="bad"></i>used, but not a real share</span></div>`;
}

function renderResult(t) {
  const reasons = t.result.reasons;
  const has = (text) => reasons.some((r) => r.includes(text));
  const rFail = has("reconstruction");
  const dFail = has("decryption");
  const later = rFail || dFail;
  const checks = [
    ["Reconstruct K′ from the 8 received shares", rFail ? "fail" : "pass",
      rFail ? "too many shares were not real" : "a strict majority of subsets agreed"],
    ["Decrypt the server's message with K′", rFail ? "skip" : dFail ? "fail" : "pass",
      dFail ? "K′ is not the server's K" : "AES-GCM authenticates the ciphertext"],
    ["Registered password is within 1 bit of mine", later ? "skip" : has("Hamming") ? "fail" : "pass",
      "compares g^pw from the ciphertext with g^x for all x within distance 1"],
    ["Shares from the transfer match the encrypted ones", later ? "skip" : has("tampered") ? "fail" : "pass",
      has("tampered") ? "the server sent different values than it encrypted" : "catches a server that cheats during OT"],
  ];
  const icon = { pass: "✓", fail: "✗", skip: "–" };
  const list = checks.map(([title, status, detail]) =>
    `<li><span class="mark ${status}" aria-label="${status}">${icon[status]}</span><span>${esc(title)}<small>${status === "skip" ? "not reached" : esc(detail)}</small></span></li>`).join("");

  const match = t.result.match;
  const group = (hex) => hex.match(/.{1,16}/g).join(" ");
  $("#viz-result").innerHTML = `
    <ul class="checks">${list}</ul>
    <div class="keys">
      <div class="key"><span class="who client">client key</span><code>${group(t.result.client_key)}</code></div>
      <div class="eq ${match ? "match" : "nomatch"}" aria-label="${match ? "equal" : "different"}">${match ? "=" : "≠"}</div>
      <div class="key"><span class="who server">server key</span><code>${group(t.result.server_key)}</code></div>
    </div>
    <div class="outcome ${match ? "good" : "bad"}">${match
      ? "Both sides hold the same 256-bit session key. Login succeeded."
      : "The client ends up with a random key that doesn't match the server's, so the login fails, and nobody learns which bits were wrong."}</div>`;
}

function replay() {
  for (const id of ["#viz-register", "#viz-server", "#viz-ot", "#viz-reconstruct"]) {
    const el = $(id);
    el.classList.remove("animate");
    void el.offsetWidth; // restart CSS animations
    el.classList.add("animate");
  }
}

// ------------------------------------------------------------------ self test (?selftest)

async function selfTest() {
  const REG = [1, 0, 1, 0, 1, 0, 1, 0];
  const cases = [
    ["exact", { attempt: REG }],
    ["one-bit-off", { attempt: flipped(REG, [7]) }],
    ["two-bits-off", { attempt: flipped(REG, [0, 5]) }],
    ["damaged-record", { attempt: REG, scenario: "corrupt-share", target: 2 }],
    ["damaged-plus-wrong-bit", { attempt: flipped(REG, [6]), scenario: "corrupt-share", target: 2 }],
    ["cheating-server", { attempt: REG, scenario: "cheating-server", target: 4 }],
    ["secure-one-bit-off", { attempt: flipped(REG, [3]), group: "modp2048" }],
  ];
  const results = [];
  for (const [name, overrides] of cases) {
    const started = performance.now();
    try {
      Object.assign(state, { registered: REG, scenario: "honest", target: 0, group: "demo", ...overrides });
      renderBits();
      renderScenario();
      document.querySelectorAll("input[type=radio]").forEach((input) => {
        input.checked = state[input.name] === input.value;
      });
      const t = await call({ ...state });
      render(t);
      await snapshot(name);
      results.push({
        name, ms: Math.round(performance.now() - started), match: t.result.match, ok: t.result.ok,
        reasons: t.result.reasons, kinds: t.ot.map((r) => r.kind).join(","),
        agree: t.reconstruction.winner === null ? null : t.reconstruction.candidates[0].count,
        tiles: document.querySelectorAll("#viz-reconstruct .subset").length,
        checks: [...document.querySelectorAll("#viz-result .mark")].map((m) => m.className.split(" ")[1]).join(","),
      });
    } catch (error) {
      results.push({ name, error: String(error) });
    }
  }
  await fetch("/__log", { method: "POST", body: JSON.stringify({ selftest: results, errors: window.__errors }) });
}

// Upload a static copy of the rendered page (no scripts, no animations) to the dev server.
async function snapshot(name) {
  $("#stages").setAttribute("aria-busy", "false");
  setRuntime("ready", "Python ready · snapshot");
  const copy = document.documentElement.cloneNode(true);
  copy.querySelectorAll("script").forEach((s) => s.remove());
  copy.querySelectorAll(".animate").forEach((el) => el.classList.remove("animate"));
  copy.querySelectorAll("input[type=radio]").forEach((input) => {
    if (input.checked) input.setAttribute("checked", ""); else input.removeAttribute("checked");
  });
  const select = copy.querySelector("#target");
  select.querySelectorAll("option").forEach((o) => o.toggleAttribute("selected", +o.value === state.target));
  const head = copy.querySelector("head");
  head.insertAdjacentHTML("afterbegin", '<base href="/">');
  await fetch(`/__snapshot/${name}`, { method: "POST", body: "<!doctype html>" + copy.outerHTML });
}

window.__errors = [];
window.addEventListener("error", (e) => window.__errors.push(String(e.message)));
window.addEventListener("unhandledrejection", (e) => window.__errors.push(String(e.reason)));

wireControls();
renderBits();
renderScenario();
if (new URLSearchParams(location.search).has("selftest")) {
  selfTest().then(() => update());
} else {
  update();
}
