(() => {
  const timeout = Number(document.body.dataset.sessionTimeout || 0);
  const warning = document.getElementById("session-warning");
  const countdown = document.getElementById("session-countdown");
  if (!timeout || !warning || !countdown) return;
  const pageLoadedAt = Date.now();
  window.setInterval(() => {
    const remaining = Math.ceil(timeout - (Date.now() - pageLoadedAt) / 1000);
    if (remaining <= 0) window.location.assign("/session-expired");
    else if (remaining <= 60) { countdown.textContent = String(remaining); warning.hidden = false; }
  }, 1000);
})();
