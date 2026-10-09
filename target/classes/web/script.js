const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const state = {
  mode: "url",
  history: JSON.parse(localStorage.getItem("qrScanHistory") || "[]"),
  testedUrl: null,
  testedLevel: null
};

window.addEventListener("load", () => {
  setTimeout(() => $("#bootScreen").classList.add("hide"), 1100);
  renderHistory();
  setupReveal();
  setupTilt();
  setupSpace();
});

document.addEventListener("mousemove", e => {
  const glow = $(".cursor-glow");
  glow.style.left = e.clientX + "px";
  glow.style.top = e.clientY + "px";
});

$$(".tab").forEach(btn => btn.addEventListener("click", () => {
  $$(".tab").forEach(x => x.classList.remove("active"));
  btn.classList.add("active");
  state.mode = btn.dataset.mode;
  $("#urlInputArea").classList.toggle("hidden", state.mode !== "url");
  $("#qrInputArea").classList.toggle("hidden", state.mode !== "qr");
}));

$$(".quick-examples button").forEach(btn => btn.addEventListener("click", () => {
  state.mode = "url";
  $$(".tab").forEach(x => x.classList.toggle("active", x.dataset.mode === "url"));
  $("#urlInputArea").classList.remove("hidden");
  $("#qrInputArea").classList.add("hidden");
  $("#targetUrl").value = btn.dataset.url;
  analyze(btn.dataset.url);
}));

$("#qrFile").addEventListener("change", e => {
  const file = e.target.files[0];
  $("#fileName").textContent = file ? file.name : "No image selected";
});

const drop = $("#dropzone");
["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.style.background = "rgba(0,255,179,.09)";
}));
["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.style.background = "";
}));
drop.addEventListener("drop", e => {
  const file = e.dataTransfer.files[0];
  if (!file) return;
  $("#qrFile").files = e.dataTransfer.files;
  $("#fileName").textContent = file.name;
});

$("#openUrlBtn").addEventListener("click", () => {
  if (!state.testedUrl) return;

  const risky = state.testedLevel === "CAUTION" || state.testedLevel === "HIGH RISK";
  if (risky) {
    const proceed = confirm(
      "WARNING: This URL was flagged as " + state.testedLevel +
      ". Opening it may expose you to phishing or other unsafe content.\n\n" +
      "Open the tested URL anyway?"
    );
    if (!proceed) return;
  }

  window.open(state.testedUrl, "_blank", "noopener,noreferrer");
});

$("#analyzeBtn").addEventListener("click", async () => {
  if (state.mode === "url") {
    const value = $("#targetUrl").value.trim();
    if (!value) return showWaiting("INPUT REQUIRED", "Enter a URL before starting analysis.");
    analyze(value);
  } else {
    const file = $("#qrFile").files[0];
    if (!file) return showWaiting("IMAGE REQUIRED", "Upload a QR image before starting analysis.");
    await decodeQR(file);
  }
});

async function decodeQR(file) {
  showWaiting("DECODING", "Reading QR payload locally. No destination is opened.");
  try {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    const max = 1400;
    const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
    canvas.width = Math.floor(bitmap.width * scale);
    canvas.height = Math.floor(bitmap.height * scale);
    canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const image = canvas.getContext("2d").getImageData(0,0,canvas.width,canvas.height);
    const code = window.jsQR ? jsQR(image.data, image.width, image.height) : null;
    if (!code) return showWaiting("QR NOT DETECTED", "No readable QR payload was found. Try a clearer image.");
    $("#targetUrl").value = code.data;
    state.mode = "url";
    $$(".tab").forEach(x => x.classList.toggle("active", x.dataset.mode === "url"));
    $("#urlInputArea").classList.remove("hidden");
    $("#qrInputArea").classList.add("hidden");
    analyze(code.data, true);
  } catch (err) {
    showWaiting("DECODE ERROR", "The image could not be processed in this browser.");
  }
}

function normalizeUrl(raw) {
  let value = raw.trim();
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;
  return new URL(value);
}

function analyze(raw, fromQR=false) {
  let url;
  try { url = normalizeUrl(raw); }
  catch { return showWaiting("INVALID URL", "The supplied target is not a valid web address."); }

  setStatus("ANALYZING", "Running local heuristic checks...");
  $("#analyzeBtn").disabled = true;

  setTimeout(() => {
    const result = scoreURL(url);
    renderResult(url, result, fromQR);
    saveHistory(url.href, result);
    $("#analyzeBtn").disabled = false;
  }, 900);
}

function scoreURL(url) {
  let score = 0, flags = [];
  const host = url.hostname.toLowerCase();
  const full = url.href.toLowerCase();
  const suspiciousWords = ["login","verify","verification","secure","account","update","confirm","password","wallet","claim","bonus","free","urgent","invoice","payment","gift"];
  const shorteners = ["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","shorturl.at","ow.ly"];
  const trustedDemo = ["google.com","github.com","microsoft.com","apple.com","amazon.com","alliance.edu.in"];

  if (url.protocol !== "https:") { score += 18; flags.push("Connection is not using HTTPS."); }
  if (host.includes("xn--")) { score += 25; flags.push("Punycode / IDN hostname detected."); }
  if (host.split(".").length >= 4) { score += 10; flags.push("Deeply nested subdomain structure."); }
  if ((host.match(/-/g) || []).length >= 3) { score += 8; flags.push("Multiple hyphens in hostname."); }
  if (/\d{4,}/.test(host)) { score += 8; flags.push("Unusual numeric sequence in hostname."); }
  if (shorteners.includes(host)) { score += 24; flags.push("URL shortening service hides the final destination."); }
  const hits = suspiciousWords.filter(w => full.includes(w));
  if (hits.length) { score += Math.min(30, hits.length * 7); flags.push("Suspicious keyword(s): " + hits.slice(0,4).join(", ")); }
  if (url.href.length > 120) { score += 10; flags.push("Unusually long URL."); }
  if ((url.href.match(/@/g)||[]).length) { score += 22; flags.push("User-info (@) syntax can obscure the real host."); }
  if ((url.href.match(/%/g)||[]).length >= 5) { score += 10; flags.push("Heavy URL encoding detected."); }
  if (trustedDemo.includes(host)) score = Math.max(0, score - 18);
  score = Math.max(0, Math.min(100, score));

  let level = score < 25 ? "SAFE" : score < 55 ? "CAUTION" : "HIGH RISK";
  return { score, level, flags, host, protocol:url.protocol.replace(":",""), length:url.href.length, suspiciousHits:hits };
}

function renderResult(url, result, fromQR) {
  state.testedUrl = url.href;
  state.testedLevel = result.level;

  const openBtn = $("#openUrlBtn");
  const openNote = $("#openUrlNote");
  openBtn.disabled = false;

  if (result.level === "HIGH RISK") {
    openNote.textContent = "⚠ High-risk target. Opening requires confirmation.";
    openNote.className = "open-url-note danger";
  } else if (result.level === "CAUTION") {
    openNote.textContent = "⚠ Caution target. Review the signals before opening.";
    openNote.className = "open-url-note warning";
  } else {
    openNote.textContent = "Target analyzed successfully. Open it in a new tab for manual verification.";
    openNote.className = "open-url-note";
  }

  setStatus(result.level, result.score < 25 ? "No major heuristic warning was detected." : "One or more phishing indicators need attention.");
  $("#riskScore").textContent = `${result.score}/100`;
  $("#riskBar").style.width = result.score + "%";
  const bar = $("#riskBar");
  const color = result.score < 25 ? "var(--safe)" : result.score < 55 ? "var(--warn)" : "var(--danger)";
  bar.style.background = color; bar.style.boxShadow = `0 0 18px ${color}`;

  const box = $("#verdictBox");
  box.className = "verdict " + (result.score < 25 ? "safe" : result.score < 55 ? "warning" : "danger");
  box.querySelector(".verdict-icon").textContent = result.score < 25 ? "✓" : result.score < 55 ? "!" : "×";
  box.querySelector("b").textContent = result.level;
  box.querySelector("small").textContent = result.score < 25
    ? "Looks relatively low-risk based on local checks. Still verify the destination."
    : result.score < 55
      ? "Proceed carefully. Inspect the domain before entering information."
      : "Stop and verify independently. Do not enter credentials or payment details.";

  const flags = result.flags.length ? result.flags : ["No obvious heuristic red flags found."];
  $("#analysisDetails").innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><small>HOST</small><b>${escapeHtml(result.host)}</b></div>
      <div class="detail-item"><small>PROTOCOL</small><b>${escapeHtml(result.protocol.toUpperCase())}</b></div>
      <div class="detail-item"><small>URL LENGTH</small><b>${result.length} chars</b></div>
      <div class="detail-item"><small>INPUT</small><b>${fromQR ? "QR IMAGE" : "DIRECT URL"}</b></div>
    </div>
    <div style="margin-top:12px">
      <div style="font-size:9px;color:var(--line);margin-bottom:7px">&gt; SIGNALS</div>
      ${flags.map(f => `<div style="font-size:10px;color:var(--muted);padding:5px 0;border-bottom:1px solid rgba(0,255,179,.07)">• ${escapeHtml(f)}</div>`).join("")}
    </div>
    <div style="font-size:8px;color:#477f70;margin-top:12px">Educational heuristic only — a low score is not proof that a website is legitimate.</div>
  `;
}

function setStatus(status, message) {
  $("#statusText").textContent = status;
  $("#statusMessage").textContent = message;
}
function showWaiting(status, message) {
  setStatus(status, message);
  $("#riskScore").textContent = "0/100";
  $("#riskBar").style.width = "0%";
  state.testedUrl = null;
  state.testedLevel = null;
  $("#openUrlBtn").disabled = true;
  $("#openUrlNote").textContent = "The button becomes available after a successful scan.";
  $("#openUrlNote").className = "open-url-note";
}
function saveHistory(url, result) {
  state.history.unshift({url, score:result.score, level:result.level, time:new Date().toLocaleString()});
  state.history = state.history.slice(0,10);
  localStorage.setItem("qrScanHistory", JSON.stringify(state.history));
  renderHistory();
}
function renderHistory() {
  const el = $("#historyList");
  if (!state.history.length) {
    el.innerHTML = `<div class="empty-history"><div>▤</div><p>No previous scans</p><small>Results will appear here.</small></div>`;
    return;
  }
  el.innerHTML = state.history.map(item => {
    const cls = item.score < 25 ? "safe" : item.score < 55 ? "warning" : "danger";
    return `<div class="history-item">
      <div class="h-top"><span>${escapeHtml(item.time)}</span><b class="${cls}">${item.level}</b></div>
      <div class="h-url">${escapeHtml(item.url)}</div>
      <div class="h-risk ${cls}">RISK ${item.score}/100</div>
    </div>`;
  }).join("");
}
$("#clearHistory").addEventListener("click", () => {
  state.history = [];
  localStorage.removeItem("qrScanHistory");
  renderHistory();
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

function setupReveal() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) entry.target.classList.add("visible");
    });
  }, {threshold:.12});
  $$(".reveal").forEach(el => observer.observe(el));
}

function setupTilt() {
  $$(".tilt").forEach(card => {
    card.addEventListener("mousemove", e => {
      if (innerWidth < 800) return;
      const r = card.getBoundingClientRect();
      const x = ((e.clientX-r.left)/r.width-.5)*8;
      const y = ((e.clientY-r.top)/r.height-.5)*-8;
      card.style.transform = `perspective(900px) rotateX(${y}deg) rotateY(${x}deg) translateY(-2px)`;
    });
    card.addEventListener("mouseleave", () => card.style.transform = "");
  });
}

function setupSpace() {
  const c = $("#spaceCanvas"), ctx = c.getContext("2d");
  let w,h,stars=[];
  function resize(){w=c.width=innerWidth;h=c.height=innerHeight;stars=Array.from({length:100},()=>({x:Math.random()*w,y:Math.random()*h,z:Math.random()*1.8+.2,s:Math.random()*1.5+.3}))}
  resize(); addEventListener("resize",resize);
  function draw(){
    ctx.clearRect(0,0,w,h);
    for(const s of stars){
      s.y += s.s*.25;
      if(s.y>h) s.y=0;
      ctx.globalAlpha=.15+s.z*.22;
      ctx.fillStyle="#00ffb3";
      ctx.fillRect(s.x,s.y,s.z,s.z);
    }
    requestAnimationFrame(draw);
  }
  draw();
}
