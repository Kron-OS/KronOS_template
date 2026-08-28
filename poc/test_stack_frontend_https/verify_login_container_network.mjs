// Throwaway verification script (CLAUDE.md §F) -- NOT part of the shipped
// e2e suite. Confirms/refutes a specific hypothesis about the second
// login.spec.ts failure hit while folding poc/test_stack_frontend_https/
// into the real docker/docker-compose.test.yml (Milestone JJJ):
//
//   Hypothesis: the isolated verification stack's OWN host-port remap
//   (host 19443 -> container 8443) broke Keycloak's KC_PROXY_HEADERS
//   X-Forwarded-Port trust (nginx sends $server_port, the CONTAINER port,
//   not the externally-visible one), so Keycloak embedded the wrong port
//   in the `iss`/redirect URLs it returns -- a verification-harness
//   artifact, not a bug in the real (1:1 port-mapped) compose file.
//
// This script bypasses host port publishing entirely: it resolves
// kronos.local straight to the isolated nginx container's own Docker
// bridge IP via Chromium's --host-resolver-rules, so nginx's container
// port (8443/443) IS the externally-observed port, exactly matching the
// real docker-compose.test.yml's 1:1 mapping. If login succeeds here, the
// hypothesis is confirmed and no product code needs to change.
//
// Usage: NGINX_IP=172.25.3.9 node verify_login_container_network.mjs
// Resolved from frontend/node_modules explicitly -- this script lives
// under poc/, outside frontend/'s own module resolution tree.
import playwright from "../../frontend/node_modules/playwright/index.js";
const { chromium } = playwright;

const nginxIp = process.env.NGINX_IP;
if (!nginxIp) {
  console.error("Set NGINX_IP to the isolated nginx container's bridge IP");
  process.exit(1);
}

const browser = await chromium.launch({
  args: [`--host-resolver-rules=MAP kronos.local ${nginxIp}`],
});
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

page.on("console", (msg) => console.log(`[console:${msg.type()}]`, msg.text()));
page.on("requestfailed", (req) =>
  console.log("[requestfailed]", req.url(), req.failure()?.errorText),
);

try {
  console.log("--- goto /login ---");
  await page.goto("https://kronos.local/login");
  await page.waitForSelector("text=Sign in with SSO", { timeout: 15000 });
  console.log("login page ready, url=", page.url());

  await page.click("text=Sign in with SSO");
  await page.waitForSelector("#username", { timeout: 15000 });
  console.log("Keycloak hosted form reached, url=", page.url());

  await page.fill("#username", "case-lead");
  await page.fill("#password", "DevCaseLead#2026");
  await page.click("#kc-login");

  await page.waitForURL("**/cases**", { timeout: 20000 });
  console.log("SUCCESS: landed on", page.url());

  const header = await page.textContent("h1, h2, [data-testid='page-header']").catch(() => null);
  console.log("header text sample:", header);
} catch (err) {
  console.error("FAILURE:", err.message);
  await page.screenshot({ path: "/tmp/verify_login_container_network_failure.png" });
  console.log("current url at failure:", page.url());
  const bodyText = await page.textContent("body").catch(() => "<no body>");
  console.log("body text sample:", bodyText?.slice(0, 500));
  process.exitCode = 1;
} finally {
  await browser.close();
}
