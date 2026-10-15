require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { promisify } = require("node:util");
const Database = require("better-sqlite3");
const express = require("express");
const { rateLimit } = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");
const nodemailer = require("nodemailer");

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const IS_DEVELOPMENT = NODE_ENV === "development";
const BASE_URL = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const configuredSessionSecret = process.env.SESSION_SECRET || "";
const SESSION_SECRET = configuredSessionSecret
  || (IS_DEVELOPMENT ? crypto.randomBytes(48).toString("base64url") : "");
const DATABASE_FILE = path.resolve(process.env.DATABASE_FILE || "./data/skybound.sqlite");
const DATA_DIR = path.dirname(DATABASE_FILE);
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_NAME = IS_PRODUCTION ? "__Host-skybound.sid" : "skybound.sid";
const TERMS_VERSION = "2026-10-16-draft-1";
const PRIVACY_VERSION = "2026-10-16-draft-1";

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}
if (!IS_DEVELOPMENT && SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET in .env to a random value of at least 32 characters outside local development.");
}
if (!/^https?:\/\//i.test(BASE_URL) || (IS_PRODUCTION && !/^https:\/\//i.test(BASE_URL))) {
  throw new Error("PUBLIC_BASE_URL must be an absolute URL; production requires HTTPS.");
}
if (IS_PRODUCTION) {
  if (process.env.LEGAL_REVIEW_APPROVED !== "true") {
    throw new Error("Production launch blocked: obtain local legal review and set LEGAL_REVIEW_APPROVED=true only after approval.");
  }
  const policyFiles = ["terms.html", "privacy.html", "responsible-play.html"]
    .map(file => path.join(__dirname, "public", "policies", file));
  for (const file of policyFiles) {
    const contents = fs.readFileSync(file, "utf8");
    if (contents.includes("DRAFT — NOT READY FOR PUBLIC LAUNCH") || /\{\{[^}]+\}\}/.test(contents)) {
      throw new Error(`Production launch blocked: complete and review ${path.basename(file)} before release.`);
    }
  }
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(DATABASE_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    verified_at INTEGER,
    auth_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS account_acceptances (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    age_confirmed_at INTEGER NOT NULL,
    accepted_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    data TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_tokens_user_purpose ON auth_tokens(user_id, purpose);
  CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
`);

class SqliteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.readSession = database.prepare("SELECT expires_at, data FROM sessions WHERE sid = ?");
    this.writeSession = database.prepare(`
      INSERT INTO sessions (sid, expires_at, data) VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET expires_at = excluded.expires_at, data = excluded.data
    `);
    this.touchSession = database.prepare("UPDATE sessions SET expires_at = ? WHERE sid = ?");
    this.deleteSession = database.prepare("DELETE FROM sessions WHERE sid = ?");
  }

  expiry(sessionData) {
    const cookie = sessionData.cookie || {};
    const expiresAt = cookie.expires ? new Date(cookie.expires).getTime() : Date.now() + (cookie.maxAge || 0);
    if (!Number.isFinite(expiresAt)) throw new Error("Session cookie expiry is invalid.");
    return expiresAt;
  }

  get(sid, callback) {
    try {
      const record = this.readSession.get(sid);
      if (!record) return callback(null, null);
      if (record.expires_at <= Date.now()) {
        this.deleteSession.run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(record.data));
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sessionData, callback) {
    try {
      this.writeSession.run(sid, this.expiry(sessionData), JSON.stringify(sessionData));
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else throw error;
    }
  }

  touch(sid, sessionData, callback) {
    try {
      this.touchSession.run(this.expiry(sessionData), sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else throw error;
    }
  }

  destroy(sid, callback) {
    try {
      this.deleteSession.run(sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else throw error;
    }
  }
}

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const emailFrom = process.env.EMAIL_FROM;
const hasEmailConfig = Boolean(smtpHost && emailFrom && Number.isInteger(smtpPort) && smtpPort > 0
  && (Boolean(smtpUser) === Boolean(smtpPass)));
const transporter = hasEmailConfig
  ? nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: process.env.SMTP_SECURE === "true",
      ...(smtpUser ? { auth: { user: smtpUser, pass: smtpPass } } : {})
    })
  : null;

const app = express();
app.disable("x-powered-by");
if (IS_PRODUCTION && process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "8kb", type: "application/json" }));

app.use(session({
  name: SESSION_NAME,
  secret: SESSION_SECRET,
  store: new SqliteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "lax",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const accountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many attempts. Wait a little and try again." }
});
function sendPolicyPage(res, filename) {
  res.sendFile(filename, { root: path.join(__dirname, "public", "policies") }, error => {
    if (!error || res.headersSent) return;
    console.error(`Unable to serve policy page ${filename}: ${error.message}`);
    res.status(error.statusCode || 500).send("Policy document unavailable.");
  });
}

app.get("/terms", (req, res) => {
  res.set("Cache-Control", "no-store");
  sendPolicyPage(res, "terms.html");
});
app.get("/privacy", (req, res) => {
  res.set("Cache-Control", "no-store");
  sendPolicyPage(res, "privacy.html");
});
app.get("/responsible-play", (req, res) => {
  res.set("Cache-Control", "no-store");
  sendPolicyPage(res, "responsible-play.html");
});

const statements = {
  userByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
  userById: db.prepare("SELECT id, email, verified_at, auth_version FROM users WHERE id = ?"),
  insertUser: db.prepare(`
    INSERT INTO users (email, password_salt, password_hash, created_at)
    VALUES (?, ?, ?, ?)
  `),
  insertAcceptance: db.prepare(`
    INSERT INTO account_acceptances (user_id, terms_version, privacy_version, age_confirmed_at, accepted_at)
    VALUES (?, ?, ?, ?, ?)
  `),
  insertToken: db.prepare(`
    INSERT INTO auth_tokens (token_hash, user_id, purpose, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `),
  deleteUserTokens: db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ?"),
  findToken: db.prepare(`
    SELECT token_hash, user_id, purpose, expires_at
    FROM auth_tokens WHERE token_hash = ? AND purpose = ?
  `),
  deleteToken: db.prepare("DELETE FROM auth_tokens WHERE token_hash = ?"),
  verifyUser: db.prepare("UPDATE users SET verified_at = ? WHERE id = ? AND verified_at IS NULL"),
  replacePassword: db.prepare(`
    UPDATE users SET password_salt = ?, password_hash = ?, auth_version = auth_version + 1
    WHERE id = ?
  `)
};

function purgeExpiredTokens() {
  const now = Date.now();
  db.prepare("DELETE FROM auth_tokens WHERE expires_at <= ?").run(now);
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now);
}

purgeExpiredTokens();
const tokenCleanupTimer = setInterval(() => {
  try {
    purgeExpiredTokens();
  } catch (error) {
    console.error("Expired account token cleanup failed:", error.message);
  }
}, 60 * 60 * 1000);
tokenCleanupTimer.unref();

function apiError(res, status, message) {
  return res.status(status).json({ error: message });
}

function normalizedEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function validEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function timingSafeStringEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireCsrf(req, res, next) {
  const supplied = req.get("x-csrf-token");
  if (!timingSafeStringEqual(supplied, req.session.csrfToken)) {
    return apiError(res, 403, "Your session expired. Refresh the page and try again.");
  }
  next();
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString("base64url")) {
  const derived = await scrypt(password, salt, 64);
  return { salt, hash: derived.toString("base64url") };
}

async function passwordMatches(password, salt, expectedHash) {
  const derived = await scrypt(password, salt, 64);
  const expected = Buffer.from(expectedHash, "base64url");
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

async function sendAccountEmail({ to, subject, text, html }) {
  if (!transporter) {
    const error = new Error("Email delivery is not configured. Set the SMTP values in .env.");
    error.code = "EMAIL_NOT_CONFIGURED";
    throw error;
  }
  await transporter.sendMail({ from: emailFrom, to, subject, text, html });
}

async function sendVerificationEmail(user, token) {
  const url = `${BASE_URL}/verify?token=${encodeURIComponent(token)}`;
  const email = escapeHtml(user.email);
  await sendAccountEmail({
    to: user.email,
    subject: "Verify your Skybound account",
    text: `Verify your Skybound account: ${url}\nThis link expires in 24 hours.`,
    html: `<p>Welcome to Skybound.</p><p><a href="${url}">Verify your email address</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this email sent to ${email}.</p>`
  });
}

async function sendPasswordResetEmail(user, token) {
  const url = `${BASE_URL}/reset-password?token=${encodeURIComponent(token)}`;
  await sendAccountEmail({
    to: user.email,
    subject: "Reset your Skybound password",
    text: `Reset your Skybound password: ${url}\nThis link expires in 24 hours.`,
    html: `<p>We received a request to reset your Skybound password.</p><p><a href="${url}">Choose a new password</a></p><p>This link expires in 24 hours. If you did not request this, ignore this email.</p>`
  });
}

function authPage(res) {
  res.set("Cache-Control", "no-store");
  res.sendFile("public/auth.html", { root: __dirname });
}

app.get("/login", (req, res) => authPage(res));
app.get("/signup", (req, res) => authPage(res));
app.get("/verify", (req, res) => authPage(res));
app.get("/reset-password", (req, res) => authPage(res));
app.get("/auth.js", (req, res) => {
  res.set("Cache-Control", "no-cache");
  res.sendFile("public/auth.js", { root: __dirname });
});
app.get("/game-account.js", (req, res) => {
  res.set("Cache-Control", "no-cache");
  res.sendFile("public/game-account.js", { root: __dirname });
});

app.get("/api/auth/config", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    emailConfigured: Boolean(transporter),
    localVerificationEnabled: IS_DEVELOPMENT && !transporter,
    termsVersion: TERMS_VERSION,
    privacyVersion: PRIVACY_VERSION
  });
});

app.get("/api/auth/csrf", (req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = randomToken();
  req.session.save(error => {
    if (error) return next(error);
    res.set("Cache-Control", "no-store");
    res.json({ token: req.session.csrfToken });
  });
});

app.post("/api/auth/register", accountLimiter, requireCsrf, async (req, res) => {
  const email = normalizedEmail(req.body && req.body.email);
  const password = req.body && req.body.password;
  const termsAccepted = req.body && req.body.termsAccepted === true;
  const privacyAcknowledged = req.body && req.body.privacyAcknowledged === true;
  const ageConfirmed = req.body && req.body.ageConfirmed === true;
  if (!validEmail(email)) return apiError(res, 400, "Enter a valid email address.");
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    return apiError(res, 400, "Use a password between 12 and 128 characters.");
  }
  if (!termsAccepted || !privacyAcknowledged || !ageConfirmed) {
    return apiError(res, 400, "Confirm you are 18 or older and accept the Terms and Privacy Notice to create an account.");
  }
  if (req.body.termsVersion !== TERMS_VERSION || req.body.privacyVersion !== PRIVACY_VERSION) {
    return apiError(res, 400, "The account policies changed. Refresh the page and review them before signing up.");
  }
  if (!transporter && !IS_DEVELOPMENT) return apiError(res, 503, "Account email is not configured yet. Please try again later.");
  if (statements.userByEmail.get(email)) {
    return apiError(res, 409, "An account already exists for that email. Try signing in or resetting your password.");
  }

  const { salt, hash } = await hashPassword(password);
  const now = Date.now();
  const token = randomToken();
  let userId;
  try {
    const createPendingAccount = db.transaction(() => {
      const result = statements.insertUser.run(email, salt, hash, now);
      userId = Number(result.lastInsertRowid);
      statements.insertAcceptance.run(userId, TERMS_VERSION, PRIVACY_VERSION, now, now);
      statements.insertToken.run(hashToken(token), userId, "verify", now + TOKEN_TTL_MS, now);
    });
    createPendingAccount();
    if (transporter) await sendVerificationEmail({ id: userId, email }, token);
  } catch (error) {
    if (userId) {
      db.prepare("DELETE FROM users WHERE id = ?").run(userId);
    } else if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return apiError(res, 409, "An account already exists for that email. Try signing in or resetting your password.");
    }
    console.error("Account registration email failed:", error.message);
    return apiError(res, error.code === "EMAIL_NOT_CONFIGURED" ? 503 : 502,
      "We could not send the verification email. Check the email service configuration and try signing up again.");
  }
  res.status(201).json(transporter
    ? { message: "Account created. Check your inbox for a verification link." }
    : {
        message: "Account created. Open the local verification link below to activate your account.",
        verificationUrl: `${BASE_URL}/verify?token=${encodeURIComponent(token)}`
      });
});

app.post("/api/auth/login", accountLimiter, requireCsrf, async (req, res, next) => {
  const email = normalizedEmail(req.body && req.body.email);
  const password = req.body && req.body.password;
  if (!validEmail(email) || typeof password !== "string" || password.length > 128) {
    return apiError(res, 400, "Enter your email and password.");
  }
  const user = statements.userByEmail.get(email);
  const validPassword = user
    ? await passwordMatches(password, user.password_salt, user.password_hash)
    : await passwordMatches(password, "skybound-invalid-user-salt", Buffer.alloc(64).toString("base64url"));
  if (!user || !validPassword) return apiError(res, 401, "Email or password is incorrect.");
  if (!user.verified_at) return apiError(res, 403, "Verify your email address before signing in.");

  req.session.regenerate(error => {
    if (error) return next(error);
    req.session.userId = user.id;
    req.session.authVersion = user.auth_version;
    req.session.csrfToken = randomToken();
    req.session.save(saveError => {
      if (saveError) return next(saveError);
      res.set("Cache-Control", "no-store");
      res.json({ message: "Signed in.", csrfToken: req.session.csrfToken });
    });
  });
});

app.post("/api/auth/verify", accountLimiter, requireCsrf, (req, res) => {
  const token = req.body && req.body.token;
  if (typeof token !== "string" || token.length > 128) return apiError(res, 400, "This verification link is invalid or expired.");
  const tokenDigest = hashToken(token);
  const record = statements.findToken.get(tokenDigest, "verify");
  if (!record || record.expires_at < Date.now()) return apiError(res, 400, "This verification link is invalid or expired.");
  const now = Date.now();
  const transaction = db.transaction(() => {
    statements.verifyUser.run(now, record.user_id);
    statements.deleteToken.run(tokenDigest);
    statements.deleteUserTokens.run(record.user_id, "verify");
  });
  transaction();
  res.json({ message: "Email verified. You can now sign in." });
});

app.post("/api/auth/resend-verification", accountLimiter, requireCsrf, async (req, res) => {
  const email = normalizedEmail(req.body && req.body.email);
  if (!validEmail(email)) return apiError(res, 400, "Enter a valid email address.");
  if (!transporter && !IS_DEVELOPMENT) return apiError(res, 503, "Account email is not configured yet. Please try again later.");
  const user = statements.userByEmail.get(email);
  let verificationUrl;
  if (user && !user.verified_at) {
    const token = randomToken();
    const now = Date.now();
    statements.deleteUserTokens.run(user.id, "verify");
    statements.insertToken.run(hashToken(token), user.id, "verify", now + TOKEN_TTL_MS, now);
    if (transporter) {
      try {
        await sendVerificationEmail(user, token);
      } catch (error) {
        statements.deleteToken.run(hashToken(token));
        console.error("Verification email resend failed:", error.message);
        return apiError(res, 502, "We could not send the verification email. Try again later.");
      }
    } else {
      verificationUrl = `${BASE_URL}/verify?token=${encodeURIComponent(token)}`;
    }
  }
  res.json({
    message: transporter
      ? "If the account needs verification, a new email has been sent."
      : "If the account needs verification, a local verification link is available below.",
    ...(verificationUrl ? { verificationUrl } : {})
  });
});

app.post("/api/auth/request-password-reset", accountLimiter, requireCsrf, async (req, res) => {
  const email = normalizedEmail(req.body && req.body.email);
  if (!validEmail(email)) return apiError(res, 400, "Enter a valid email address.");
  if (!transporter && !IS_DEVELOPMENT) return apiError(res, 503, "Account email is not configured yet. Please try again later.");
  const user = statements.userByEmail.get(email);
  let resetUrl;
  if (user && user.verified_at) {
    const token = randomToken();
    const now = Date.now();
    statements.deleteUserTokens.run(user.id, "reset");
    statements.insertToken.run(hashToken(token), user.id, "reset", now + TOKEN_TTL_MS, now);
    if (transporter) {
      try {
        await sendPasswordResetEmail(user, token);
      } catch (error) {
        statements.deleteToken.run(hashToken(token));
        console.error("Password reset email failed:", error.message);
        return apiError(res, 502, "We could not send the password reset email. Try again later.");
      }
    } else {
      resetUrl = `${BASE_URL}/reset-password?token=${encodeURIComponent(token)}`;
    }
  }
  res.json({
    message: transporter
      ? "If a verified account uses that email, a password reset link has been sent."
      : "If a verified account uses that email, a local password-reset link is available below.",
    ...(resetUrl ? { resetUrl } : {})
  });
});

app.post("/api/auth/reset-password", accountLimiter, requireCsrf, async (req, res) => {
  const token = req.body && req.body.token;
  const password = req.body && req.body.password;
  if (typeof token !== "string" || token.length > 128) return apiError(res, 400, "This reset link is invalid or expired.");
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    return apiError(res, 400, "Use a password between 12 and 128 characters.");
  }
  const tokenDigest = hashToken(token);
  const record = statements.findToken.get(tokenDigest, "reset");
  if (!record || record.expires_at < Date.now()) return apiError(res, 400, "This reset link is invalid or expired.");
  const { salt, hash } = await hashPassword(password);
  const transaction = db.transaction(() => {
    statements.replacePassword.run(salt, hash, record.user_id);
    statements.deleteUserTokens.run(record.user_id, "reset");
  });
  transaction();
  res.json({ message: "Password updated. Sign in with your new password." });
});

function requireAuth(req, res, next) {
  const userId = req.session.userId;
  const isApiRequest = req.path.startsWith("/api/");
  if (!userId) return isApiRequest ? apiError(res, 401, "Sign in to continue.") : res.redirect(302, "/login");
  const user = statements.userById.get(userId);
  if (!user || !user.verified_at || user.auth_version !== req.session.authVersion) {
    return req.session.destroy(error => {
      if (error) return next(error);
      res.clearCookie(SESSION_NAME, { path: "/", httpOnly: true, sameSite: "lax", secure: IS_PRODUCTION });
      return isApiRequest ? apiError(res, 401, "Sign in to continue.") : res.redirect(302, "/login");
    });
  }
  req.authUser = user;
  next();
}

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ user: { email: req.authUser.email } });
});

app.post("/api/auth/logout", requireCsrf, (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie(SESSION_NAME, { path: "/", httpOnly: true, sameSite: "lax", secure: IS_PRODUCTION });
    res.json({ message: "Signed out." });
  });
});

app.get("/", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile("index.html", { root: __dirname });
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) return apiError(res, 404, "This endpoint does not exist.");
  res.status(404).send("Not found");
});

app.use((error, req, res, next) => {
  console.error("Request failed:", error);
  if (res.headersSent) return next(error);
  if (req.path.startsWith("/api/")) return apiError(res, 500, "The request could not be completed. Please try again.");
  res.status(500).send("The request could not be completed. Please try again.");
});

app.listen(PORT, () => {
  console.log(`Skybound server listening on ${BASE_URL}`);
  if (!configuredSessionSecret && IS_DEVELOPMENT) {
    console.warn("Using a temporary local session secret. Sessions expire when the server restarts.");
  }
  if (!transporter) {
    console.warn(IS_DEVELOPMENT
      ? "SMTP is not configured. Local-only verification and password-reset links are enabled."
      : "SMTP is not configured. Account registration and recovery are unavailable.");
  }
});
