// Live service status for the SENTINEL landing page.
//
// Deliberately simple: one fetch of the keyless /health endpoint, rendered as a
// word + glyph so state never depends on colour alone.
(function () {
  "use strict";

  var cfg = window.SENTINEL_CONFIG || {};
  var pill = document.getElementById("api-status");
  var text = document.getElementById("api-status-text");
  var detail = document.getElementById("api-detail");
  var hint = document.getElementById("api-hint");

  function set(state, message, extra, note) {
    pill.className = "pill " + state;
    text.textContent = message;
    detail.textContent = extra || "";
    hint.textContent = note || "";
  }

  // Wire every configured link once; unconfigured ones stay inert rather than
  // becoming a dead "#" that pretends to be a page.
  function link(id, url, label) {
    var el = document.getElementById(id);
    if (!el) return;
    if (url) {
      el.href = url;
      if (el.hasAttribute("aria-disabled")) el.removeAttribute("aria-disabled");
      if (label) el.textContent = label;
    } else {
      el.setAttribute("aria-disabled", "true");
      el.removeAttribute("href");
      if (label) el.textContent = label;
    }
  }

  link("nav-repo", cfg.repoUrl);
  link("foot-repo", cfg.repoUrl);
  link("foot-docs", cfg.docsUrl);
  link("console-link", cfg.consoleUrl, cfg.consoleUrl ? "Open the console →" : "Console not yet deployed");
  link("cta-console", cfg.consoleUrl, cfg.consoleUrl ? "Open the console" : "Open the console (coming soon)");
  link("cta-api", cfg.apiUrl, cfg.apiUrl ? "API reference" : "API (coming soon)");

  if (!cfg.apiUrl) {
    set("unconfigured", "not deployed", "", "Set apiUrl in config.js once the Cloud Run service exists.");
    return;
  }

  function probe() {
    var controller = new AbortController();
    var timer = setTimeout(function () {
      controller.abort();
    }, cfg.coldStartBudgetMs || 25000);

    set("checking", "checking…", "", "");

    fetch(cfg.apiUrl.replace(/\/$/, "") + "/health", {
      signal: controller.signal,
      cache: "no-store",
    })
      .then(function (response) {
        clearTimeout(timer);
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (body) {
        set(
          "ok",
          "ok",
          "model " + (body.model_version || "?") + " · public read " + (body.public_read ? "on" : "off"),
          "threshold " + (body.threshold != null ? body.threshold : "?")
        );
      })
      .catch(function (error) {
        clearTimeout(timer);
        // An abort means the container was asleep and did not wake inside the
        // budget. That is a cold start, not an outage, so it is not labelled down.
        if (error && error.name === "AbortError") {
          set(
            "cold",
            "waking up",
            "",
            "The service scaled to zero and is starting. It usually answers shortly."
          );
        } else {
          set("down", "unreachable", "", "The API did not answer. It may still be deploying.");
        }
      });
  }

  probe();
  if (cfg.pollIntervalMs) setInterval(probe, cfg.pollIntervalMs);
})();
