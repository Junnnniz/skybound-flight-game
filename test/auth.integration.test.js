const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Database = require("better-sqlite3");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { after, before, test } = require("node:test");

const root = path.resolve(__dirname, "..");
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "skybound-auth-"));
const databaseFile = path.join(tempDir, "integration.sqlite");
const password = "A-secure-test-password-1";
const changedPassword = "A-different-secure-password-2";

let smtp;
let smtpMessages = [];
let smtpPort;
let server;
let serverOutput = "";
let baseUrl;
let cookie = "";
let csrfToken = "";
let policyVersions;

function captureEmailServer() {
  smtp = net.createServer(socket => {
    socket.setEncoding("utf8");
    socket.write("220 localhost ESMTP\r\n");
    let pending = "";
    let message = "";
    let receivingMessage = false;

    socket.on("data", chunk => {
      pending += chunk;
      let end;
      while ((end = pending.indexOf("\r\n")) !== -1) {
        const line = pending.slice(0, end);
        pending = pending.slice(end + 2);
        if (receivingMessage) {
          if (line === ".") {
            smtpMessages.push(message);
            message = "";
            receivingMessage = false;
            socket.write("250 Message accepted\r\n");
          } else {
            message += `${line.replace(/^\.\./, ".")}\r\n`;
          }
          continue;
        }
        if (/^(EHLO|HELO)\s/i.test(line)) socket.write("250 localhost\r\n");
        else if (/^DATA$/i.test(line)) {
          receivingMessage = true;
          socket.write("354 End data with <CR><LF>.<CR><LF>\r\n");
        } else if (/^QUIT$/i.test(line)) {
          socket.write("221 Bye\r\n");
          socket.end();
        } else {
          socket.write("250 OK\r\n");
        }
      }
    });
  });
}

async function reservePort() {
  const listener = net.createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const { port } = listener.address();
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  return port;
}

function updateCookie(response) {
  for (const header of response.headers.getSetCookie()) {
    if (header.startsWith("skybound.sid=")) cookie = header.split(";", 1)[0];
    if (header.startsWith("skybound.sid=;")) cookie = "";
  }
}

function emailToken(message, route) {
  const decoded = message.replace(/=\r?\n/g, "")
    .replace(/=([0-9a-f]{2})/gi, (_, value) => String.fromCharCode(parseInt(value, 16)));
  return decoded.match(new RegExp(`/${route}\\?token=([A-Za-z0-9_-]+)`))?.[1];
}

async function requestJson(endpoint, method = "GET", body) {
  const headers = {};
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(`${baseUrl}${endpoint}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual"
  });
  updateCookie(response);
  const contentType = response.headers.get("content-type") || "";
  const result = contentType.includes("application/json") ? await response.json() : await response.text();
  return { response, result };
}

async function setCsrf() {
  const { response, result } = await requestJson("/api/auth/csrf");
  assert.equal(response.status, 200);
  csrfToken = result.token;
}

async function waitForServer() {
  const deadline = Date.now() + 15000;
  let lastError;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Server exited early:\n${serverOutput}`);
    try {
      const response = await fetch(`${baseUrl}/api/auth/config`);
      if (response.ok) return response.json();
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Server did not start: ${lastError}\n${serverOutput}`);
}

before(async () => {
  captureEmailServer();
  smtp.listen(0, "127.0.0.1");
  await once(smtp, "listening");
  smtpPort = smtp.address().port;
  const port = await reservePort();
  baseUrl = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    NODE_ENV: "test",
    PORT: String(port),
    PUBLIC_BASE_URL: baseUrl,
    SESSION_SECRET: crypto.randomBytes(48).toString("base64url"),
    DATABASE_FILE: databaseFile,
    SMTP_HOST: "127.0.0.1",
    SMTP_PORT: String(smtpPort),
    SMTP_SECURE: "false",
    SMTP_USER: "",
    SMTP_PASS: "",
    EMAIL_FROM: "Skybound Test <no-reply@example.test>"
  };
  server = spawn(process.execPath, [path.join(root, "server.js")], { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
  server.stdout.on("data", chunk => { serverOutput += chunk.toString(); });
  server.stderr.on("data", chunk => { serverOutput += chunk.toString(); });
  policyVersions = await waitForServer();
});

after(async () => {
  if (server && server.exitCode === null) {
    server.kill();
    await Promise.race([once(server, "exit"), new Promise(resolve => setTimeout(resolve, 3000))]);
  }
  if (smtp) await new Promise(resolve => smtp.close(() => resolve()));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test("serves public policies and protects the game route", async () => {
  const game = await requestJson("/");
  assert.equal(game.response.status, 302);
  assert.equal(game.response.headers.get("location"), "/login");
  for (const route of ["/terms", "/privacy", "/responsible-play"]) {
    const policy = await requestJson(route);
    assert.equal(policy.response.status, 200, `${route}\n${serverOutput}\n${JSON.stringify(policy.result)}`);
    assert.match(policy.result, /DRAFT — NOT READY FOR PUBLIC LAUNCH/);
  }
  assert.equal(policyVersions.emailConfigured, true);
});

test("requires policy confirmations, verifies email, rotates sessions and resets passwords", async () => {
  await setCsrf();
  const email = "account@example.test";
  const missingConfirmations = await requestJson("/api/auth/register", "POST", { email, password });
  assert.equal(missingConfirmations.response.status, 400);

  const registration = await requestJson("/api/auth/register", "POST", {
    email,
    password,
    ageConfirmed: true,
    termsAccepted: true,
    privacyAcknowledged: true,
    termsVersion: policyVersions.termsVersion,
    privacyVersion: policyVersions.privacyVersion
  });
  assert.equal(registration.response.status, 201, serverOutput);
  assert.equal(smtpMessages.length, 1);

  const unverifiedLogin = await requestJson("/api/auth/login", "POST", { email, password });
  assert.equal(unverifiedLogin.response.status, 403);

  const verificationToken = emailToken(smtpMessages[0], "verify");
  assert.ok(verificationToken, `verification email should contain a token:\n${smtpMessages[0]}`);
  const verification = await requestJson("/api/auth/verify", "POST", { token: verificationToken });
  assert.equal(verification.response.status, 200);

  const login = await requestJson("/api/auth/login", "POST", { email, password });
  assert.equal(login.response.status, 200);
  assert.ok(login.result.csrfToken);
  csrfToken = login.result.csrfToken;

  const game = await requestJson("/");
  assert.equal(game.response.status, 200);
  assert.match(game.result, /ROUND #001/);
  const me = await requestJson("/api/auth/me");
  assert.equal(me.response.status, 200);
  assert.equal(me.result.user.email, email);

  const testDatabase = new Database(databaseFile);
  const acceptance = testDatabase
    .prepare("SELECT terms_version, privacy_version, age_confirmed_at FROM account_acceptances WHERE user_id = 1")
    .get();
  testDatabase.close();
  assert.equal(acceptance.terms_version, policyVersions.termsVersion);
  assert.equal(acceptance.privacy_version, policyVersions.privacyVersion);
  assert.ok(acceptance.age_confirmed_at > 0);

  const resetRequest = await requestJson("/api/auth/request-password-reset", "POST", { email });
  assert.equal(resetRequest.response.status, 200);
  assert.equal(smtpMessages.length, 2);
  const resetToken = emailToken(smtpMessages[1], "reset-password");
  assert.ok(resetToken, "reset email should contain a token");

  const passwordReset = await requestJson("/api/auth/reset-password", "POST", {
    token: resetToken,
    password: changedPassword
  });
  assert.equal(passwordReset.response.status, 200);
  const invalidatedSession = await requestJson("/api/auth/me");
  assert.equal(invalidatedSession.response.status, 401);

  await setCsrf();
  const oldPasswordLogin = await requestJson("/api/auth/login", "POST", { email, password });
  assert.equal(oldPasswordLogin.response.status, 401);
  const newPasswordLogin = await requestJson("/api/auth/login", "POST", { email, password: changedPassword });
  assert.equal(newPasswordLogin.response.status, 200);
  csrfToken = newPasswordLogin.result.csrfToken;

  const logout = await requestJson("/api/auth/logout", "POST", {});
  assert.equal(logout.response.status, 200);
  const protectedAfterLogout = await requestJson("/");
  assert.equal(protectedAfterLogout.response.status, 302);
});
