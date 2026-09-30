// SENTINEL landing page — deployment configuration.
//
// Every outbound URL lives here so a deploy never requires an HTML edit.
// Leave apiUrl empty until the API is deployed; the status panel then reads
// "not deployed" instead of showing a false failure.
window.SENTINEL_CONFIG = {
  consoleUrl: "https://sentinel-console-nine.vercel.app", // hosted analyst console
  apiUrl: "https://sentinel-api-pearl.vercel.app", // hosted API base URL
  repoUrl: "https://github.com/AbhijitK20/-SENTINEL",
  docsUrl: "https://github.com/AbhijitK20/-SENTINEL/blob/main/docs/DEPLOYMENT.md",

  // A free-tier container that scaled to zero needs to import torch and load
  // the model before /health answers. Probing with a 5s timeout reports a
  // sleeping service as "down", which is exactly wrong on the first click.
  coldStartBudgetMs: 25000,
  pollIntervalMs: 60000,
};
