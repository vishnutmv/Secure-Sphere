
document.addEventListener("DOMContentLoaded", function() {
  const startBtn = document.getElementById("startScanBtn");
  const gaugeCanvas = document.getElementById("speedGauge");
  const speedText = document.getElementById("speedText");

  function drawGauge(speedMbps) {
    if(!gaugeCanvas) return;
    const ctx = gaugeCanvas.getContext("2d");
    const w = gaugeCanvas.width; const h = gaugeCanvas.height;
    ctx.clearRect(0,0,w,h);
    const cx = w/2; const cy = h*0.9;
    const radius = Math.min(w, h) * 0.75;
    ctx.lineWidth = 10;
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.beginPath(); ctx.arc(cx, cy, radius, Math.PI, 2*Math.PI, false); ctx.stroke();
    const pct = Math.max(0, Math.min(1, speedMbps/100));
    const end = Math.PI + pct * Math.PI;
    const grad = ctx.createLinearGradient(0,0,w,0);
    grad.addColorStop(0, "#ff2d95"); grad.addColorStop(0.5, "#00e6ff"); grad.addColorStop(1, "#7f2dff");
    ctx.strokeStyle = grad; ctx.beginPath(); ctx.arc(cx, cy, radius, Math.PI, end, false); ctx.lineWidth = 12; ctx.stroke();
    const angle = Math.PI + pct * Math.PI;
    const nx = cx + Math.cos(angle) * (radius - 20); const ny = cy + Math.sin(angle) * (radius - 20);
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(nx, ny); ctx.lineWidth = 3; ctx.strokeStyle = "rgba(255,255,255,0.9)"; ctx.stroke();
    ctx.beginPath(); ctx.fillStyle = "#fff"; ctx.arc(cx, cy, 4, 0, Math.PI*2); ctx.fill();
    if(speedText) speedText.textContent = speedMbps.toFixed(2) + " Mbps";
  }

  async function measureSpeed() {
    try {
      const size = 500000; const start = performance.now();
      const resp = await fetch("/speedtest?size=" + size, {cache: "no-store"});
      const reader = resp.body.getReader();
      let received = 0;
      while(true) {
        const {done, value} = await reader.read();
        if(done) break;
        received += value.length;
        const elapsed = (performance.now() - start) / 1000;
        const mbps = (received * 8) / (elapsed * 1000 * 1000);
        drawGauge(mbps);
      }
      const totalElapsed = (performance.now() - start) / 1000;
      const mbpsFinal = (received * 8) / (totalElapsed * 1000 * 1000);
      drawGauge(mbpsFinal);
      return mbpsFinal;
    } catch (e) {
      console.error("Speed test failed", e); drawGauge(0); return 0;
    }
  }

  function triggerFlash(level) {
    const overlay = document.getElementById("flashOverlay");
    overlay.style.opacity = 1; overlay.className = "flash-overlay";
    if(/crit|high/i.test(level)) overlay.classList.add("flash-red");
    else if(/medium|moderat/i.test(level)) overlay.classList.add("flash-yellow");
    else overlay.classList.add("flash-green");
    overlay.style.animation = "none"; void overlay.offsetWidth;
    overlay.style.animation = "flashfade 1.2s ease-in-out 3";
    setTimeout(()=>{ overlay.style.animation = ""; overlay.style.opacity = 0; overlay.className = "flash-overlay"; }, 3800);
  }

  function sendDesktopNotification(overallRisk) {
    const phrases = {"Critical":"CRITICAL: Immediate attention required!","High":"HIGH: Vulnerabilities found.","Medium":"MODERATE: Action recommended.","Low":"LOW: No major issues detected."};
    if(!("Notification" in window)) return;
    if(Notification.permission === "granted") new Notification("Secure Sphere – Scan Result", { body: `${overallRisk} • ${phrases[overallRisk] || ''}` });
    else if(Notification.permission !== "denied") Notification.requestPermission().then(perm => { if(perm==="granted") new Notification("Secure Sphere – Scan Result", { body: `${overallRisk} • ${phrases[overallRisk] || ''}` }); });
  }

  if(startBtn) {
    startBtn.addEventListener("click", async function(e) {
      e.preventDefault();
      const form = document.getElementById("scanForm");
      const target = document.querySelector('input[name="target"]').value.trim();
      if(!target){ alert("Enter target first"); return; }
      const speed = await measureSpeed();
      const speedBadge = document.getElementById("speedBadge");
      if(speedBadge) speedBadge.textContent = speed.toFixed(2) + " Mbps";
      let hidden = document.getElementById("speedHidden");
      if(!hidden){ hidden = document.createElement("input"); hidden.type="hidden"; hidden.name="measured_speed"; hidden.id="speedHidden"; form.appendChild(hidden); }
      hidden.value = speed.toFixed(2);
      form.submit();
    });
  }

  const overall = document.querySelector(".overall-badge");
  if(overall) {
    const risk = overall.dataset.risk || overall.textContent.trim();
    triggerFlash(risk);
    sendDesktopNotification(risk);
  }
});
