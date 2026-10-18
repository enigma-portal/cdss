// Display conversion only. Never reinterpret naive strings or change source data.
(() => {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const formatter = new Intl.DateTimeFormat(undefined, {
      timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
      timeZoneName: "longOffset",
    });
    document.querySelectorAll("time[data-cdss-time]").forEach(element => {
      const iso = element.getAttribute("datetime");
      if (!iso || !iso.endsWith("Z")) return;
      const date = new Date(iso);
      if (!Number.isFinite(date.getTime())) return;
      element.textContent = `${formatter.format(date)} (${zone} local)`;
      // The server-rendered UTC tooltip and canonical datetime remain unchanged.
    });
  } catch (_) {
    // A missing/unsupported Intl implementation leaves the labelled UTC fallback.
  }
})();
