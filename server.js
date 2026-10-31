const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { promisify } = require("node:util");
const express = require("express");
const initializeSqlJs = require("sql.js");

const scrypt = promisify(crypto.scrypt);
const app = express();
const databaseDirectory = process.env.DATABASE_DIR
    ? path.resolve(process.env.DATABASE_DIR)
    : path.join(__dirname, "data");
const databasePath = path.join(databaseDirectory, "users.sqlite");
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const dummySalt = "authentication-timing-salt";

app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));
app.use((request, response, next) => {
    response.set("X-Content-Type-Options", "nosniff");
    response.set("X-Frame-Options", "DENY");
    response.set("Referrer-Policy", "same-origin");
    next();
});

app.get("/health", (request, response) => {
    response.status(200).json({ status: "ok" });
});

let database;

function saveDatabase() {
    fs.writeFileSync(databasePath, Buffer.from(database.export()));
}

function queryOne(sql, parameters = []) {
    const statement = database.prepare(sql);
    try {
        statement.bind(parameters);
        return statement.step() ? statement.getAsObject() : null;
    } finally {
        statement.free();
    }
}

function queryAll(sql, parameters = []) {
    const statement = database.prepare(sql);
    const rows = [];
    try {
        statement.bind(parameters);
        while (statement.step()) {
            rows.push(statement.getAsObject());
        }
        return rows;
    } finally {
        statement.free();
    }
}

function getCookie(request, name) {
    const cookies = request.headers.cookie || "";
    for (const cookie of cookies.split(";")) {
        const separator = cookie.indexOf("=");
        if (separator < 0) continue;
        if (cookie.slice(0, separator).trim() === name) {
            return cookie.slice(separator + 1).trim();
        }
    }
    return "";
}

function setSessionCookie(response, token) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.set(
        "Set-Cookie",
        `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`
    );
}

function clearSessionCookie(response) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.set("Set-Cookie", `session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function requireAuthentication(request, response, next) {
    const token = getCookie(request, "session");
    if (!/^[a-f0-9]{64}$/.test(token)) {
        response.status(401).json({ error: "Faça login para continuar." });
        return;
    }

    const session = queryOne(
        `SELECT users.id, users.username, users.email, users.role
         FROM sessions JOIN users ON users.id = sessions.user_id
         WHERE sessions.token_hash = ? AND sessions.expires_at > ?`,
        [crypto.createHash("sha256").update(token).digest("hex"), Date.now()]
    );

    if (!session) {
        response.status(401).json({ error: "Sua sessão expirou. Faça login novamente." });
        return;
    }

    request.user = session;
    next();
}

async function hashPassword(password, salt) {
    return scrypt(password, salt, 64);
}

function validateEmail(email) {
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post("/api/register", async (request, response) => {
    const body = request.body && typeof request.body === "object" ? request.body : {};
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (body.termsAccepted !== true) {
        response.status(400).json({ error: "É necessário aceitar os termos para criar uma conta." });
        return;
    }
    if (username.length < 2 || username.length > 40) {
        response.status(400).json({ error: "O nome de usuário deve ter entre 2 e 40 caracteres." });
        return;
    }
    if (!validateEmail(email)) {
        response.status(400).json({ error: "Informe um e-mail válido." });
        return;
    }
    if (password.length < 8 || password.length > 128) {
        response.status(400).json({ error: "A senha deve ter entre 8 e 128 caracteres." });
        return;
    }
    if (queryOne("SELECT id FROM users WHERE email = ?", [email])) {
        response.status(409).json({ error: "Este e-mail já está cadastrado." });
        return;
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = await hashPassword(password, salt);
    if (queryOne("SELECT id FROM users WHERE email = ?", [email])) {
        response.status(409).json({ error: "Este e-mail já está cadastrado." });
        return;
    }
    database.run(
        "INSERT INTO users (username, email, password_salt, password_hash, role, created_at, terms_accepted_at) VALUES (?, ?, ?, ?, 'user', ?, ?)",
        [username, email, salt, passwordHash.toString("hex"), new Date().toISOString(), new Date().toISOString()]
    );
    saveDatabase();
    response.status(201).json({ message: "Cadastro realizado. Você já pode entrar." });
});

app.post("/api/login", async (request, response) => {
    const body = request.body && typeof request.body === "object" ? request.body : {};
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (body.termsAccepted !== true) {
        response.status(400).json({ error: "É necessário aceitar os termos para entrar." });
        return;
    }
    if (!email || password.length === 0 || password.length > 128) {
        response.status(400).json({ error: "Informe seu e-mail e sua senha." });
        return;
    }

    const user = queryOne(
        "SELECT id, username, email, password_salt, password_hash, role FROM users WHERE email = ?",
        [email]
    );
    const actualHash = await hashPassword(password, user ? user.password_salt : dummySalt);
    const expectedHash = user ? Buffer.from(user.password_hash, "hex") : Buffer.alloc(64);
    const passwordMatches =
        expectedHash.length === actualHash.length && crypto.timingSafeEqual(expectedHash, actualHash);

    if (!user || !passwordMatches) {
        response.status(401).json({ error: "E-mail ou senha incorretos." });
        return;
    }

    database.run("UPDATE users SET terms_accepted_at = ? WHERE id = ?", [new Date().toISOString(), user.id]);
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + sessionLifetime;
    database.run("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
        crypto.createHash("sha256").update(token).digest("hex"),
        user.id,
        expiresAt
    ]);
    database.run("DELETE FROM sessions WHERE expires_at <= ?", [Date.now()]);
    saveDatabase();
    setSessionCookie(response, token);
    response.json({ username: user.username, role: user.role });
});

app.get("/api/me", requireAuthentication, (request, response) => {
    response.json({
        id: request.user.id,
        username: request.user.username,
        email: request.user.email,
        role: request.user.role
    });
});

app.get("/api/admin/users", requireAuthentication, (request, response) => {
    if (request.user.role !== "admin") {
        response.status(403).json({ error: "Acesso permitido somente ao administrador." });
        return;
    }
    response.json(queryAll(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id"
    ));
});

app.post("/api/logout", requireAuthentication, (request, response) => {
    const token = getCookie(request, "session");
    database.run("DELETE FROM sessions WHERE token_hash = ?", [
        crypto.createHash("sha256").update(token).digest("hex")
    ]);
    saveDatabase();
    clearSessionCookie(response);
    response.json({ message: "Sessão encerrada." });
});

const pages = {
    "/": "index.html",
    "/index.html": "index.html",
    "/cadastrar.html": "cadastrar.html",
    "/termos.html": "termos.html",
    "/recuperar-senha.html": "recuperar-senha.html",
    "/style.css": "style.css"
};
for (const [route, file] of Object.entries(pages)) {
    app.get(route, (request, response) => response.sendFile(path.join(__dirname, file)));
}
app.get("/dashboard.html", (request, response) => {
    response.set("Cache-Control", "no-store");
    response.sendFile(path.join(__dirname, "dashboard.html"));
});

async function start() {
    const adminEmail = (process.env.ADMIN_EMAIL || "admin@gmail.com").trim().toLowerCase();
    const adminPassword = process.env.ADMIN_PASSWORD || "";
    if (!validateEmail(adminEmail) || adminPassword.length < 8 || adminPassword.length > 128) {
        throw new Error("Configure ADMIN_PASSWORD (8 a 128 caracteres) e um ADMIN_EMAIL válido antes de iniciar.");
    }

    fs.mkdirSync(databaseDirectory, { recursive: true });
    const SQL = await initializeSqlJs();
    database = fs.existsSync(databasePath)
        ? new SQL.Database(new Uint8Array(fs.readFileSync(databasePath)))
        : new SQL.Database();
    database.run("PRAGMA foreign_keys = ON");
    database.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
            created_at TEXT NOT NULL,
            terms_accepted_at TEXT
        )
    `);
    const userColumns = queryAll("PRAGMA table_info(users)");
    if (!userColumns.some((column) => column.name === "terms_accepted_at")) {
        database.run("ALTER TABLE users ADD COLUMN terms_accepted_at TEXT");
    }
    database.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        )
    `);

    const existingAdmin = queryOne("SELECT id, role FROM users WHERE email = ?", [adminEmail]);
    if (existingAdmin && existingAdmin.role !== "admin") {
        throw new Error("O e-mail de administrador já está cadastrado como usuário comum.");
    }
    if (!existingAdmin) {
        const salt = crypto.randomBytes(16).toString("hex");
        const passwordHash = await hashPassword(adminPassword, salt);
        database.run(
            "INSERT INTO users (username, email, password_salt, password_hash, role, created_at, terms_accepted_at) VALUES (?, ?, ?, ?, 'admin', ?, NULL)",
            ["Administrador", adminEmail, salt, passwordHash.toString("hex"), new Date().toISOString()]
        );
    }
    saveDatabase();

    const port = Number(process.env.PORT) || 3000;
    const host = process.env.HOST || (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
    app.listen(port, host, () => {
        console.log(`Aplicação disponível em ${host}:${port}`);
        console.log(`Banco SQLite: ${databasePath}`);
    });
}

start().catch((error) => {
    console.error("Não foi possível iniciar o servidor:", error.message);
    process.exitCode = 1;
});
