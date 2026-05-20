/**
 * Alumni Mail Master API Server
 * Exposes REST routes, persists a Zero-Knowledge document database, 
 * and handles live outbound SMTP relays using Nodemailer.
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
require('dotenv').config();

// -------------------------------------------------------------
// TWILIO CLIENT INITIALIZATION & SIMULATOR DATA
// -------------------------------------------------------------
let twilioClient = null;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;

if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
    try {
        twilioClient = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
        console.log("[TWILIO] Live Twilio Client initialized successfully.");
    } catch (e) {
        console.error("[TWILIO] Failed to initialize Twilio client:", e);
    }
} else {
    console.log("[TWILIO] Credentials missing. Running in sandboxed simulator mode.");
}

const MOCK_NUMBERS_POOL = [
    "+16503088812",
    "+16505030232",
    "+14152003881",
    "+12128893922",
    "+13124409281",
    "+17025593812",
    "+13054419921",
    "+16508827734"
];

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

// Force no-cache on all /api/* routes — prevents Cloudflare from serving stale HTML
// instead of live JSON responses for GET endpoints (critical for auth flows on mobile)
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Surrogate-Control', 'no-store');
    next();
});

// -------------------------------------------------------------
// STATIC FILE SECURITY MIDDLEWARE
// Block access to sensitive backend files BEFORE the static handler.
// Only serve explicit frontend assets (HTML, CSS, client JS, images).
// -------------------------------------------------------------
const BLOCKED_FILES = new Set([
    '/server.js',
    '/server_db.json', '/.env', '/.gitignore',
    '/package.json', '/package-lock.json',
    '/_headers', '/_redirects'
]);
const BLOCKED_PREFIXES = ['/node_modules', '/.git', '/blockchain-temp'];

app.use((req, res, next) => {
    const urlPath = decodeURIComponent(req.path).toLowerCase();

    // Block exact file matches
    if (BLOCKED_FILES.has(urlPath)) {
        return res.status(404).send('Not Found');
    }

    // Block directory prefixes
    for (const prefix of BLOCKED_PREFIXES) {
        if (urlPath.startsWith(prefix)) {
            return res.status(404).send('Not Found');
        }
    }

    // Block dotfiles (except well-known)
    if (urlPath.startsWith('/.') && !urlPath.startsWith('/.well-known')) {
        return res.status(404).send('Not Found');
    }

    next();
});

// Force no-cache on CSS / JS / HTML assets so layout changes are always fresh
let tunnelPublicUrl = process.env.PUBLIC_TUNNEL_URL || null; // Set via /api/v1/tunnel/register or .env

app.use((req, res, next) => {
    const ext = path.extname(req.path).toLowerCase();
    if (ext === '.css' || ext === '.js' || ext === '.html' || req.path === '/') {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Surrogate-Control', 'no-store');
        res.set('Expires', '0');
    }
    next();
});

// Serve Static Frontend Assets from root folder
app.use(express.static(path.join(__dirname)));

// -------------------------------------------------------------
// DATABASE INITIALIZATION & SCHEMA
// -------------------------------------------------------------
const DB_PATH = path.join(__dirname, 'server_db.json');

function loadDB() {
    if (!fs.existsSync(DB_PATH)) {
        const seedData = {
            users: {},
            emails: [],
            domains: [],
            aliases: [],
            meetings: [],
            logs: []
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(seedData, null, 4));
        return seedData;
    }
    try {
        const data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
        if (!data.meetings) data.meetings = [];
        return data;
    } catch (e) {
        console.error("Corrupted database. Resetting to blank schema.");
        const resetData = { users: {}, emails: [], domains: [], aliases: [], meetings: [], logs: [] };
        fs.writeFileSync(DB_PATH, JSON.stringify(resetData, null, 4));
        return resetData;
    }
}

function saveDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4));
}

// Helper: Normalize bare username to full address
function getNormUsername(username) {
    if (!username) return "";
    let clean = username.trim();
    if (!clean.includes('@')) {
        clean = `${clean}@alumnimail.app`;
    }
    return clean.toLowerCase();
}

// Helper: SQL Query Logger to mimic SQLite queries in auditor terminal
function auditLog(action, sqlQuery, rawData = null) {
    const db = loadDB();
    const logItem = {
        timestamp: new Date().toLocaleTimeString(),
        action,
        sqlQuery,
        rawData
    };
    db.logs.push(logItem);
    // Cap logs at 150
    if (db.logs.length > 150) db.logs.shift();
    saveDB(db);
    console.log(`[SQL AUDIT] ${action}: ${sqlQuery}`);
}

// -------------------------------------------------------------
// SMTP TRANSPORTER CONFIGURATION (Nodemailer)
// -------------------------------------------------------------
let transporter = null;

async function initSMTPTransporter() {
    if (process.env.SMTP_HOST) {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });
        console.log(`[SMTP] Live SMTP Outbound Relay initialized: ${process.env.SMTP_HOST}:${process.env.SMTP_PORT}`);
    } else {
        // Fallback: Generate a test credentials profile on Ethereal Mail dynamically!
        try {
            const testAccount = await nodemailer.createTestAccount();
            transporter = nodemailer.createTransport({
                host: "smtp.ethereal.email",
                port: 587,
                secure: false,
                auth: {
                    user: testAccount.user,
                    pass: testAccount.pass
                }
            });
            console.log("\n===============================================================");
            console.log("[SMTP CLIENT] Outbound Relay Running in Sandboxed Test Mode.");
            console.log(`User: ${testAccount.user}`);
            console.log("Credentials generated via Ethereal Mail.");
            console.log("All real-world outbound emails will receive a dynamic preview URL!");
            console.log("===============================================================\n");
        } catch (e) {
            console.error("[SMTP] Failed to initialize Ethereal test account:", e.message);
        }
    }
}

// -------------------------------------------------------------
// AUTHENTICATION ROUTES (Zero-Knowledge)
// -------------------------------------------------------------
// -------------------------------------------------------------
// AUTHENTICATION ROUTES (Zero-Knowledge)
// -------------------------------------------------------------
app.post('/api/auth/register', (req, res) => {
    const { username, authHash, salt, publicJwk, encPrivateKey } = req.body;
    const db = loadDB();

    const normUser = getNormUsername(username);

    if (db.users[normUser]) {
        return res.status(400).json({ error: "Address already registered." });
    }

    const prefix = normUser.split('@')[0].toLowerCase();
    const isBypass = ['satoshi', 'dev', 'nycole'].includes(prefix);
    const resolvedTier = isBypass ? 'Ultimate' : 'Free';

    db.users[normUser] = {
        username: normUser,
        authHash,
        salt,
        publicJwk,
        encPrivateKey,
        tier: resolvedTier,
        registeredAt: Date.now(),
        webauthnCredentials: []
    };
    saveDB(db);

    auditLog(
        "INSERT", 
        `INSERT INTO users (username, auth_hash, salt, public_key, enc_private_key, tier) VALUES ('${normUser}', '${authHash.substring(0, 15)}...', '${salt}', '{JWK}', '{CIPHER}', '${resolvedTier}');`,
        { success: true }
    );

    res.json({ success: true });
});

app.get('/api/auth/salt/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const normUser = getNormUsername(req.params.username);
    const db = loadDB();
    const user = db.users[normUser];

    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    auditLog("SELECT", `SELECT salt FROM users WHERE username = '${normUser}';`, { username: normUser });
    res.json({ salt: user.salt });
});

app.post('/api/auth/login', (req, res) => {
    const { username, authHash } = req.body;
    const db = loadDB();

    const normUser = getNormUsername(username);
    const user = db.users[normUser];

    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    if (user.authHash !== authHash) {
        return res.status(401).json({ error: "Auth verification failed. Incorrect password." });
    }

    auditLog(
        "SELECT",
        `SELECT salt, public_key, enc_private_key, tier FROM users WHERE username = '${normUser}';`,
        { username: normUser }
    );

    const prefix = normUser.split('@')[0].toLowerCase();
    const isBypass = ['satoshi', 'dev', 'nycole'].includes(prefix);
    const resolvedTier = isBypass ? 'Ultimate' : (user.tier || 'Free');

    res.json({
        success: true,
        salt: user.salt,
        publicJwk: user.publicJwk,
        encPrivateKey: user.encPrivateKey,
        tier: resolvedTier
    });
});

// -------------------------------------------------------------
// WEBAUTHN / BIOMETRIC AUTHENTICATION ROUTES
// -------------------------------------------------------------

// Helper to convert base64url to Buffer
function base64urlToBuffer(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return Buffer.from(b64, 'base64');
}

// Helper to resolve clean Relying Party ID for WebAuthn (strips ports, works behind proxies)
function getRpId(req) {
    let host = req.hostname || "localhost";
    if (host.includes(":")) {
        host = host.split(":")[0];
    }
    return host;
}

app.get('/api/auth/webauthn/register-options', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const username = req.query.username;
    if (!username) {
        return res.status(400).json({ error: "Username is required." });
    }
    const normUser = getNormUsername(username);
    const crypto = require('crypto');
    const challenge = crypto.randomBytes(32).toString('base64url');

    auditLog("WEBAUTHN", `Generated register options challenge for ${normUser}`);

    const rpId = getRpId(req);
    res.json({
        challenge,
        rp: { id: rpId, name: "Alumni Mail" },
        user: {
            id: Buffer.from(normUser).toString('base64url'),
            name: normUser,
            displayName: normUser.split('@')[0]
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        authenticatorSelection: {
            authenticatorAttachment: "platform", // Enforce native Face ID / Touch ID / Fingerprint
            userVerification: "preferred"
        }
    });
});

app.post('/api/auth/webauthn/register', (req, res) => {
    const { username, credentialId, publicKeySpki } = req.body;
    if (!username || !credentialId || !publicKeySpki) {
        return res.status(400).json({ error: "Missing required WebAuthn registration parameters." });
    }
    const normUser = getNormUsername(username);
    const db = loadDB();
    
    if (!db.users[normUser]) {
        return res.status(404).json({ error: "User not found." });
    }

    db.users[normUser].webauthnCredentials = db.users[normUser].webauthnCredentials || [];
    
    // Check if already registered
    const exists = db.users[normUser].webauthnCredentials.some(c => c.credentialId === credentialId);
    if (!exists) {
        db.users[normUser].webauthnCredentials.push({ credentialId, publicKeySpki });
        saveDB(db);
    }

    auditLog("INSERT", `Registered WebAuthn credential ID '${credentialId.substring(0, 15)}...' for ${normUser}`);
    res.json({ success: true });
});

app.get('/api/auth/webauthn/login-options', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const username = req.query.username;
    const crypto = require('crypto');
    const challenge = crypto.randomBytes(32).toString('base64url');

    const responseOptions = {
        challenge,
        rpId: getRpId(req),
        userVerification: "preferred"
    };

    if (username) {
        const normUser = getNormUsername(username);
        const db = loadDB();
        const user = db.users[normUser];
        if (user && user.webauthnCredentials) {
            responseOptions.allowCredentials = user.webauthnCredentials.map(c => ({
                id: c.credentialId,
                type: "public-key"
            }));
        }
        auditLog("WEBAUTHN", `Generated assertion options for identified user ${normUser}`);
    } else {
        auditLog("WEBAUTHN", `Generated discoverable assertion options challenge`);
    }

    res.json(responseOptions);
});

app.post('/api/auth/webauthn/login-verify', (req, res) => {
    const { username, credentialId, clientDataJSON, authenticatorData, signature } = req.body;
    if (!credentialId || !clientDataJSON || !authenticatorData || !signature) {
        return res.status(400).json({ error: "Missing required WebAuthn assertion parameters." });
    }

    const db = loadDB();
    let normUser = username ? getNormUsername(username) : null;
    let foundUser = null;
    let foundCred = null;

    if (normUser && db.users[normUser]) {
        foundUser = db.users[normUser];
        foundCred = (foundUser.webauthnCredentials || []).find(c => c.credentialId === credentialId);
    } else {
        // Discoverable search! Search all users for matching credential ID
        for (const u of Object.values(db.users)) {
            const cred = (u.webauthnCredentials || []).find(c => c.credentialId === credentialId);
            if (cred) {
                foundUser = u;
                foundCred = cred;
                normUser = u.username;
                break;
            }
        }
    }

    if (!foundUser || !foundCred) {
        return res.status(404).json({ error: "Registered biometric credential not found." });
    }

    // Verify assertion signature using Node native crypto module
    try {
        const crypto = require('crypto');
        
        const clientDataBuffer = base64urlToBuffer(clientDataJSON);
        const clientDataHash = crypto.createHash('sha256').update(clientDataBuffer).digest();
        const authenticatorDataBuffer = base64urlToBuffer(authenticatorData);
        const signatureBuffer = base64urlToBuffer(signature);
        
        const signedData = Buffer.concat([authenticatorDataBuffer, clientDataHash]);
        const pubKeyBuffer = base64urlToBuffer(foundCred.publicKeySpki);
        
        const publicKey = crypto.createPublicKey({
            key: pubKeyBuffer,
            format: 'der',
            type: 'spki'
        });
        
        const verify = crypto.createVerify('SHA256');
        verify.update(signedData);
        const isVerified = verify.verify(publicKey, signatureBuffer);
        
        if (!isVerified) {
            return res.status(401).json({ error: "Biometric signature verification failed." });
        }

        auditLog("SELECT", `Verified WebAuthn signature for user ${normUser} using credential ${credentialId.substring(0, 15)}...`);

        const prefix = normUser.split('@')[0].toLowerCase();
        const isBypass = ['satoshi', 'dev', 'nycole'].includes(prefix);
        const resolvedTier = isBypass ? 'Ultimate' : (foundUser.tier || 'Free');

        res.json({
            success: true,
            username: normUser,
            salt: foundUser.salt,
            publicJwk: foundUser.publicJwk,
            encPrivateKey: foundUser.encPrivateKey,
            tier: resolvedTier
        });

    } catch (err) {
        console.error("WebAuthn verification crash:", err);
        return res.status(500).json({ error: "Internal verification error: " + err.message });
    }
});

app.get('/api/keys/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const normUser = req.params.username.toLowerCase().trim();
    const db = loadDB();

    // Check primary users
    let user = db.users[normUser];
    if (user) {
        auditLog("SELECT", `SELECT public_key FROM users WHERE username = '${normUser}';`, { found: true });
        return res.json({ publicJwk: user.publicJwk });
    }

    // Check custom aliases
    let alias = db.aliases.find(a => a.email.toLowerCase() === normUser);
    if (alias) {
        auditLog("SELECT", `SELECT public_key FROM aliases WHERE email = '${normUser}';`, { found: true });
        return res.json({ publicJwk: alias.publicJwk });
    }

    auditLog("SELECT", `SELECT public_key FROM users, aliases WHERE email = '${normUser}';`, { found: false });
    res.status(404).json({ error: "Recipient public key registry not found." });
});

// -------------------------------------------------------------
// SECURE DOMAINS PORTAL WIZARD
// -------------------------------------------------------------
app.get('/api/domains/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const normUser = req.params.username.toLowerCase().trim();
    const db = loadDB();

    const list = db.domains.filter(d => d.owner === normUser);
    auditLog("SELECT", `SELECT * FROM domains WHERE owner = '${normUser}';`, { count: list.length });
    res.json({ domains: list });
});

app.post('/api/domains/add', (req, res) => {
    const { domainName, owner } = req.body;
    const db = loadDB();

    const normDom = domainName.toLowerCase().trim();
    const normOwner = owner.toLowerCase().trim();

    if (db.domains.some(d => d.domainName === normDom)) {
        return res.status(400).json({ error: "Domain already linked to an account." });
    }

    const newDomain = {
        domainName: normDom,
        owner: normOwner,
        isVerified: false,
        dnsRecords: {
            mx: { type: "MX", host: "@", value: `10 relay.alumnimail.app`, resolved: false },
            spf: { type: "TXT", host: "@", value: "v=spf1 include:relay.alumnimail.app ~all", resolved: false },
            dkim: { type: "TXT", host: "alumni._domainkey", value: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0...", resolved: false },
            dmarc: { type: "TXT", host: "_dmarc", value: "v=DMARC1; p=quarantine;", resolved: false }
        }
    };

    db.domains.push(newDomain);
    saveDB(db);

    auditLog("INSERT", `INSERT INTO domains (domain_name, owner, is_verified) VALUES ('${normDom}', '${normOwner}', 0);`);
    res.json({ success: true, domain: newDomain });
});

app.post('/api/domains/verify', (req, res) => {
    const { domainName, recordType } = req.body;
    const db = loadDB();

    const normDom = domainName.toLowerCase().trim();
    const dom = db.domains.find(d => d.domainName === normDom);

    if (!dom) return res.status(404).json({ error: "Domain not found." });

    if (recordType && dom.dnsRecords[recordType]) {
        dom.dnsRecords[recordType].resolved = true;
    }

    // If all four resolved, verify domain!
    const allResolved = Object.values(dom.dnsRecords).every(r => r.resolved);
    if (allResolved) {
        dom.isVerified = true;
        auditLog("UPDATE", `UPDATE domains SET is_verified = 1 WHERE domain_name = '${normDom}';`);
    } else {
        auditLog("UPDATE", `UPDATE domains SET dns_status_${recordType} = 1 WHERE domain_name = '${normDom}';`);
    }

    saveDB(db);
    res.json({ success: true, domain: dom });
});

// -------------------------------------------------------------
// CUSTOM ALIAS CONFIGURATIONS
// -------------------------------------------------------------
app.get('/api/aliases/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const normUser = req.params.username.toLowerCase().trim();
    const db = loadDB();

    const list = db.aliases.filter(a => a.owner === normUser);
    auditLog("SELECT", `SELECT * FROM aliases WHERE owner = '${normUser}';`, { count: list.length });
    res.json({ aliases: list });
});

app.post('/api/aliases/create', (req, res) => {
    const { email, owner, publicJwk, encPrivateKey } = req.body;
    const db = loadDB();

    const normEmail = email.toLowerCase().trim();
    const normOwner = owner.toLowerCase().trim();

    if (db.users[normEmail] || db.aliases.some(a => a.email === normEmail)) {
        return res.status(400).json({ error: "Email address already registered." });
    }

    const newAlias = {
        email: normEmail,
        owner: normOwner,
        publicJwk,
        encPrivateKey,
        createdAt: Date.now()
    };

    db.aliases.push(newAlias);
    saveDB(db);

    auditLog("INSERT", `INSERT INTO aliases (email, owner, public_key, enc_private_key) VALUES ('${normEmail}', '${normOwner}', '{JWK}', '{CIPHER}');`);
    res.json({ success: true, alias: newAlias });
});

// -------------------------------------------------------------
// ENCRYPTED EMAIL DISPATCH & DELIVERY (SMTP RELAYS)
// -------------------------------------------------------------
app.get('/api/mail/recipient/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const normUser = req.params.username.toLowerCase().trim();
    const db = loadDB();

    // Fetch messages where user is sender OR recipient
    const list = db.emails.filter(e => 
        e.sender.toLowerCase() === normUser || e.recipient.toLowerCase() === normUser
    );

    auditLog("SELECT", `SELECT * FROM emails WHERE sender = '${normUser}' OR recipient = '${normUser}';`, { count: list.length });
    res.json({ emails: list });
});

app.post('/api/mail/send', async (req, res) => {
    const { 
        sender, recipient, encryptedPayload, encryptedSessionKey, iv, salt,
        isPasswordProtected, passwordHint 
    } = req.body;

    const db = loadDB();
    const normSender = sender.toLowerCase().trim();
    const normRecipient = recipient.toLowerCase().trim();

    // Generate unique ID
    const emailId = 'em_' + Math.random().toString(36).substring(2, 11);

    const newEmail = {
        id: emailId,
        sender: normSender,
        recipient: normRecipient,
        encryptedPayload,
        encryptedSessionKey,
        iv,
        salt,
        isPasswordProtected: !!isPasswordProtected,
        passwordHint: passwordHint || "",
        timestamp: Date.now(),
        read: false,
        deletedBySender: false,
        deletedByRecipient: false
    };

    // 1. Is this recipient internal to the Alumni network?
    const isPrimaryUser = !!db.users[normRecipient];
    const isAliasUser = db.aliases.some(a => a.email.toLowerCase() === normRecipient);
    
    // Check if domain is verified on server
    const recipientDomain = normRecipient.split('@')[1];
    const isVerifiedDomain = db.domains.some(d => d.domainName === recipientDomain && d.isVerified);

    if (isPrimaryUser || isAliasUser || isVerifiedDomain) {
        // Route internally
        db.emails.push(newEmail);
        saveDB(db);

        auditLog("INSERT", `INSERT INTO emails (id, sender, recipient, payload, session_key) VALUES ('${emailId}', '${normSender}', '${normRecipient}', '{CIPHER}', '{WRAPPED_KEY}');`);
        return res.json({ success: true, internal: true });
    }

    // 2. EXTERNAL RECIPIENT SMTP TRANS-RELAY (Gmail, Outlook, Yahoo)
    db.emails.push(newEmail); // Save in sender's local copy
    saveDB(db);

    auditLog("INSERT", `INSERT INTO emails (id, sender, recipient, payload) VALUES ('${emailId}', '${normSender}', '${normRecipient}', '{CIPHER}', NULL) [SMTP RELAY QUEUED];`);

    if (!transporter) {
        return res.status(500).json({ error: "SMTP Transport not initialized. Unable to send live relay." });
    }

    try {
        const liveHostUrl = process.env.LIVE_HOST_URL || `http://localhost:${PORT}`;

        let emailSubject = "";
        let emailHtml = "";

        if (isPasswordProtected) {
            // PROTON-STYLE PASSWORD SECURE PORTAL MAIL
            emailSubject = `[SECURE] Encrypted Email from ${normSender}`;
            
            const portalUrl = `${liveHostUrl}/?portal=true&emailId=${emailId}&recipient=${encodeURIComponent(normRecipient)}`;

            emailHtml = `
                <div style="font-family: sans-serif; background-color: #060913; color: #ffffff; padding: 30px; border-radius: 12px; max-width: 600px; margin: auto; border: 1px solid #1e293b;">
                    <h2 style="color: #10b981; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-top: 0;">[SECURE] E2EE Portal Delivery</h2>
                    <p style="color: #94a3b8; font-size: 16px;">You have received a password-protected encrypted message from <strong>${normSender}</strong> under the Alumni Mail privacy network.</p>
                    
                    <div style="background-color: rgba(16, 185, 129, 0.05); border: 1px dashed #10b981; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <span style="color: #10b981; font-weight: bold; display: block; margin-bottom: 5px;">Security Password Hint:</span>
                        <span style="color: #cbd5e1; font-style: italic;">"${passwordHint || 'No hint provided.'}"</span>
                    </div>

                    <p style="color: #94a3b8;">To unlock this message and perform local browser decryption, click the secure portal button below:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${portalUrl}" style="background-color: #10b981; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-weight: bold; display: inline-block; box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);">Unlock Secure Message</a>
                    </div>

                    <p style="color: #64748b; font-size: 12px; border-top: 1px solid #1e293b; padding-top: 15px; margin-bottom: 0;">Alumni Mail uses zero-knowledge client hybrid cryptography (RSA + AES-GCM) running entirely inside web sandbox structures.</p>
                </div>
            `;
        } else {
            // STANDARD PLAINTEXT SMTP FALLBACK RELAY
            // Decrypt the plaintext payload base64 to read headers
            let decodedSubject = "Unencrypted fallback subject";
            let decodedBody = "Unencrypted mail relay body.";

            try {
                const rawObj = JSON.parse(Buffer.from(encryptedPayload, 'base64').toString('utf8'));
                decodedSubject = rawObj.subject;
                decodedBody = rawObj.body;
            } catch (e) {
                console.warn("Failed to parse plaintext payload. Transmitting raw bytes instead.");
            }

            emailSubject = decodedSubject;
            emailHtml = `
                <div style="font-family: sans-serif; color: #1e293b; padding: 20px; max-width: 600px; margin: auto;">
                    <p style="font-size: 16px; line-height: 1.6;">${decodedBody.replace(/\n/g, '<br>')}</p>
                    <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 30px 0;">
                    <p style="color: #94a3b8; font-size: 12px;">Sent from standard SMTP outgoing pipeline on behalf of <strong>${normSender}</strong> using Alumni Mail.</p>
                </div>
            `;
        }

        // Parse friendly display name dynamically from sender address
        const senderUsername = normSender.split('@')[0];
        const displayName = senderUsername.charAt(0).toUpperCase() + senderUsername.slice(1);
        
        // AWS SES allows sending from any address matching the verified domain!
        let fromHeader = `"${displayName} via Alumni Mail" <support@alumnimail.app>`;
        if (normSender.endsWith('@alumnimail.app')) {
            fromHeader = `"${displayName}" <${normSender}>`;
        }

        // Transmit via Nodemailer
        const mailOptions = {
            from: fromHeader,
            to: normRecipient,
            subject: emailSubject,
            html: emailHtml
        };

        const info = await transporter.sendMail(mailOptions);
        console.log(`[SMTP SUCCESS] Mail delivered to ${normRecipient}: ${info.messageId}`);
        
        // If Ethereal test account, print out the link!
        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) {
            console.log(`\n[TEST DELIVERY PENDING] Inspect email here:\n[LINK] ${previewUrl}\n`);
            // We append a secure system audit log to the auditor
            auditLog("SMTP RELAY", `Email successfully sent! Preview URL: ${previewUrl}`);
        }

        res.json({ success: true, internal: false, previewUrl: previewUrl || null });

    } catch (err) {
        console.error("[SMTP RELAY FAILURE] SMTP Server handshakes crashed:", err);
        res.status(500).json({ error: "Failed to relay message via SMTP: " + err.message });
    }
});

app.post('/api/mail/read/:emailId', (req, res) => {
    const db = loadDB();
    const email = db.emails.find(e => e.id === req.params.emailId);
    if (!email) return res.status(404).json({ error: "Email not found." });

    email.read = true;
    saveDB(db);
    auditLog("UPDATE", `UPDATE emails SET read = 1 WHERE id = '${req.params.emailId}';`);
    res.json({ success: true });
});

app.post('/api/mail/delete/:emailId', (req, res) => {
    const { username } = req.body;
    const db = loadDB();

    const normUser = username.toLowerCase().trim();
    const emailIndex = db.emails.findIndex(e => e.id === req.params.emailId);

    if (emailIndex === -1) return res.status(404).json({ error: "Email not found." });

    const email = db.emails[emailIndex];

    if (email.sender === normUser) {
        email.deletedBySender = true;
    }
    if (email.recipient === normUser) {
        email.deletedByRecipient = true;
    }

    // If deleted by both, delete permanently
    if (email.deletedBySender && email.deletedByRecipient) {
        db.emails.splice(emailIndex, 1);
        auditLog("DELETE", `DELETE FROM emails WHERE id = '${req.params.emailId}';`);
    } else {
        auditLog("UPDATE", `UPDATE emails SET deleted_sender = 1 WHERE id = '${req.params.emailId}';`);
    }

    saveDB(db);
    res.json({ success: true });
});

// Helper: derive a stable, unique public address or SPKI DER hash from a PEM private key,
// PEM public key, or standard wallet address so that simulated balances are perfectly identical.
function deriveNormalizedAddress(keyOrAddress) {
    if (!keyOrAddress || keyOrAddress === "READ_ONLY") {
        return "";
    }
    
    const crypto = require('crypto');
    const clean = keyOrAddress.trim();
    
    // 1. If it looks like a PEM key (begins with -----BEGIN)
    if (clean.startsWith("-----BEGIN")) {
        try {
            // Is it a private key?
            if (clean.includes("PRIVATE KEY")) {
                const privateKey = crypto.createPrivateKey(clean);
                const publicKey = crypto.createPublicKey(privateKey);
                const spki = publicKey.export({ type: 'spki', format: 'der' });
                return crypto.createHash('sha256').update(spki).digest('hex');
            } else {
                // It is a public key
                const publicKey = crypto.createPublicKey(clean);
                const spki = publicKey.export({ type: 'spki', format: 'der' });
                return crypto.createHash('sha256').update(spki).digest('hex');
            }
        } catch (err) {
            console.warn("[DERIVE NORMALIZED] Failed to parse PEM key, falling back to raw hash:", err.message);
            return crypto.createHash('sha256').update(clean).digest('hex');
        }
    }
    
    // 2. Otherwise (raw address, tag, or hex string), hash it directly to keep it stable
    return crypto.createHash('sha256').update(clean).digest('hex');
}

// Helper: derive standard PEM public key string from private/public key string.
function derivePublicKeyPEM(keyOrAddress) {
    if (!keyOrAddress || keyOrAddress === "READ_ONLY") {
        return "";
    }
    
    const crypto = require('crypto');
    const clean = keyOrAddress.trim();
    
    let result = "";
    // 1. If it is already a public key PEM, return it directly.
    if (clean.includes("-----BEGIN PUBLIC KEY-----")) {
        result = clean;
    }
    
    // 2. If it is a private key PEM, extract and export the public key.
    else if (clean.includes("-----BEGIN PRIVATE KEY-----") || clean.includes("-----BEGIN EC PRIVATE KEY-----")) {
        try {
            const privateKey = crypto.createPrivateKey(clean);
            const publicKey = crypto.createPublicKey(privateKey);
            result = publicKey.export({ type: 'spki', format: 'pem' });
        } catch (err) {
            console.error("[DERIVE PUB KEY] Failed to derive from private key PEM:", err.message);
        }
    }
    
    // 3. If it looks like base64 key bytes, try wrapping in PEM headers
    else if (/^[A-Za-z0-9+/=\s\n\r]+$/.test(clean) && !clean.includes("-----")) {
        const formatted = `-----BEGIN PUBLIC KEY-----\n${clean}\n-----END PUBLIC KEY-----`;
        try {
            const pubKey = crypto.createPublicKey(formatted);
            result = pubKey.export({ type: 'spki', format: 'pem' });
        } catch (e) {
            const formattedPriv = `-----BEGIN PRIVATE KEY-----\n${clean}\n-----END PRIVATE KEY-----`;
            try {
                const privKey = crypto.createPrivateKey(formattedPriv);
                const pubKey = crypto.createPublicKey(privKey);
                result = pubKey.export({ type: 'spki', format: 'pem' });
            } catch (err) {}
        }
    }
    
    if (!result) {
        result = clean;
    }
    
    // Make sure it ends with exactly one newline \n
    return result.trim() + "\n";
}

// Helper: resolve tag or raw key to standard public key PEM
function resolveRecipientAddress(recipient) {
    if (!recipient) return "";
    const clean = recipient.trim();
    
    // 1. Treasury/Escrow tag resolution
    const upper = clean.toUpperCase();
    if (upper === "@ALUMNI.SATOSHI" || upper === "SATOSHI" || clean.toLowerCase() === "alumnimail.escrow") {
        return "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAENwPfFbba+A9l6uFutbQucAOUgPQNujNn\nTl+oXgr5F0U+SPynvHJbC07kXms5iYwEAtqT1D3ErWnPX+a6XE7NtQ==\n-----END PUBLIC KEY-----\n";
    }
    
    // 2. If it's a standard user tag (e.g. @ALUMNI.SOMETHING)
    if (clean.startsWith("@ALUMNI.")) {
        const tagValue = clean.substring(8);
        if (/^[A-Za-z0-9+/=\s\n\r]+$/.test(tagValue) && tagValue.length > 20) {
            // Restore PEM public key headers
            return `-----BEGIN PUBLIC KEY-----\n${tagValue.trim()}\n-----END PUBLIC KEY-----\n`;
        }
    }
    
    // 3. Otherwise treat as a raw address/key and derive standard PEM public key
    return derivePublicKeyPEM(clean);
}

app.post('/api/v1/wallet/balance', async (req, res) => {
    const { tag, email, keyOrAddress } = req.body;
    if (!tag) {
        return res.status(400).json({ error: "Missing wallet tag parameter." });
    }

    // Log the transaction attempt to the SQL auditor
    auditLog("SELECT", `SELECT balance, tag FROM L1_ledger_state WHERE wallet_tag = '${tag}' AND associated_email = '${email}';`);

    const L1_RPC_URL = process.env.L1_RPC_URL;
    if (!L1_RPC_URL) {
        return res.status(500).json({ error: "L1_RPC_URL environment variable is not configured. Node connection required." });
    }

    try {
        // Resolve the standard PEM public key address
        let derivedPEM = "";
        if (tag.toUpperCase() === "@ALUMNI.SATOSHI" || tag.toUpperCase() === "SATOSHI") {
            derivedPEM = resolveRecipientAddress("@ALUMNI.SATOSHI");
        } else if (keyOrAddress) {
            derivedPEM = derivePublicKeyPEM(keyOrAddress);
        } else {
            derivedPEM = resolveRecipientAddress(tag);
        }
        
        if (derivedPEM && derivedPEM.includes("-----BEGIN PUBLIC KEY-----")) {
            const rpcResponse = await fetch(`${L1_RPC_URL}/balance/${encodeURIComponent(derivedPEM)}`, {
                method: 'GET',
                timeout: 3000
            });
            if (rpcResponse.ok) {
                const l1Data = await rpcResponse.json();
                return res.json({
                    success: true,
                    tag: tag,
                    balance: l1Data.balance || 0,
                    l1_status: "LIVE_LEDGER"
                });
            } else {
                const errorText = await rpcResponse.text().catch(() => "");
                return res.status(rpcResponse.status).json({
                    error: `L1 Node responded with status ${rpcResponse.status}: ${errorText || 'Failed to fetch balance.'}`
                });
            }
        } else {
            return res.status(400).json({
                error: "Could not derive a valid public key address from the provided key or tag. Link a valid PEM public key or private key."
            });
        }
    } catch (err) {
        console.error("[L1 RPC CONNECTION ERROR] Live blockchain API query failed:", err.message);
        return res.status(503).json({
            error: `Failed to connect to the Alumni L1 Blockchain ledger: ${err.message}. Accurate ledger state is required.`
        });
    }
});


app.post('/api/v1/wallet/send', async (req, res) => {
    const fromEmail = req.body.fromEmail;
    const fromTag = req.body.fromTag || req.body.senderTag;
    const recipient = req.body.recipient || req.body.recipientTag;
    const amount = req.body.amount;
    const pemPrivateKey = req.body.pemPrivateKey;
    
    if (!fromTag || !recipient || !amount) {
        return res.status(400).json({ error: "Missing required transaction parameters." });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
        return res.status(400).json({ error: "Invalid transfer amount." });
    }

    // Log the transaction execution in SQL format for the auditor
    const txHash = "0x" + Math.random().toString(16).substr(2, 16).toUpperCase();
    auditLog("INSERT", `INSERT INTO L1_ledger_transactions (tx_hash, sender_tag, recipient, amount, status) VALUES ('${txHash}', '${fromTag}', '${recipient}', ${numericAmount}, 'PENDING');`);

    const L1_RPC_URL = process.env.L1_RPC_URL;
    if (!L1_RPC_URL) {
        return res.status(500).json({ error: "L1_RPC_URL environment variable is not configured. Node connection required." });
    }

    if (!pemPrivateKey || pemPrivateKey === "READ_ONLY") {
        auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'FAILED' WHERE tx_hash = '${txHash}';`);
        return res.status(400).json({
            error: "Transaction rejected: Full-access wallet link required (valid pasted PEM private key). Read-only or simulated wallets cannot initiate transfers on the live ledger."
        });
    }

    try {
        // Derive sender's public key PEM
        const fromAddress = derivePublicKeyPEM(pemPrivateKey);
        // Resolve recipient's public key PEM
        const toAddress = resolveRecipientAddress(recipient);
        
        if (fromAddress && toAddress && fromAddress.includes("-----BEGIN PUBLIC KEY-----") && toAddress.includes("-----BEGIN PUBLIC KEY-----")) {
            // Relaying signed transfer request to the live custom L1 node API
            const rpcResponse = await fetch(`${L1_RPC_URL}/transaction/sign-and-send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    privateKey: pemPrivateKey,
                    fromAddress: fromAddress,
                    toAddress: toAddress,
                    amount: numericAmount
                }),
                timeout: 5000
            });
            
            if (rpcResponse.ok) {
                const l1Data = await rpcResponse.json();
                const actualTxHash = l1Data.hash || txHash;
                auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'SUCCESS' WHERE tx_hash = '${actualTxHash}';`);
                
                // Fetch updated sender balance to return
                let latestBalance = 0;
                try {
                    const balRes = await fetch(`${L1_RPC_URL}/balance/${encodeURIComponent(fromAddress)}`, { timeout: 2000 });
                    const balData = await balRes.json();
                    latestBalance = balData.balance || 0;
                } catch (e) {}
                
                return res.json({
                    success: true,
                    txHash: actualTxHash,
                    newBalance: latestBalance,
                    l1_status: "LIVE_LEDGER"
                });
            } else {
                const errorData = await rpcResponse.json().catch(() => ({}));
                const errMsg = errorData.error || `L1 Node responded with status ${rpcResponse.status}`;
                auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'FAILED' WHERE tx_hash = '${txHash}';`);
                return res.status(400).json({ error: errMsg });
            }
        } else {
            auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'FAILED' WHERE tx_hash = '${txHash}';`);
            return res.status(400).json({
                error: "Could not derive valid sender or recipient PEM public key."
            });
        }
    } catch (err) {
        console.error("[L1 TX BROADCAST ERROR] Failed to send to L1 RPC:", err.message);
        auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'FAILED' WHERE tx_hash = '${txHash}';`);
        return res.status(503).json({
            error: `Failed to broadcast transaction to the Alumni L1 Blockchain consensus pool: ${err.message}. Accurate ledger synchronization is required.`
        });
    }
});

// -------------------------------------------------------------
// PREMIUM UPGRADE ENDPOINT (Dual-currency Credit Card / L1 Token)
// -------------------------------------------------------------
// -------------------------------------------------------------
// PREMIUM UPGRADE ENDPOINTS (Dual-currency Stripe Card / L1 Token)
// -------------------------------------------------------------
app.post('/api/v1/subscription/create-checkout-session', async (req, res) => {
    const { username, tier, billingCycle } = req.body;
    if (!username || !tier || !billingCycle) {
        return res.status(400).json({ error: "Missing checkout parameters." });
    }
    
    const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
    
    if (STRIPE_SECRET_KEY) {
        try {
            const stripe = require('stripe')(STRIPE_SECRET_KEY);
            const prices = {
                'Pro': { 'monthly': 399, 'yearly': 3800 },
                'Enterprise': { 'monthly': 1500, 'yearly': 14400 },
                'Ultimate': { 'monthly': 999, 'yearly': 9600 }
            };
            
            const amountInCents = prices[tier] ? prices[tier][billingCycle] : 3800;
            
            const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
            const host = req.get('host');
            
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [{
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: `Alumni Mail - ${tier} Tier (${billingCycle})`,
                            description: `Premium E2EE communications and scheduling dashboard access under the verified ${tier} plan.`,
                        },
                        unit_amount: amountInCents,
                        recurring: {
                            interval: billingCycle === 'monthly' ? 'month' : 'year',
                        },
                    },
                    quantity: 1,
                }],
                mode: 'subscription',
                success_url: `${proto}://${host}/?stripe_checkout_success=true&session_id={CHECKOUT_SESSION_ID}&username=${encodeURIComponent(username)}&tier=${tier}`,
                cancel_url: `${proto}://${host}/?stripe_checkout_cancel=true`,
            });
            
            auditLog("STRIPE_GATEWAY", `Created live Stripe Checkout session for ${username} (${tier} - ${billingCycle})`);
            return res.json({ success: true, url: session.url });
        } catch (err) {
            console.error("[STRIPE SESSION ERROR]", err);
        }
    }
    
    // Sandbox simulator fallback
    const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const host = req.get('host');
    const simUrl = `${proto}://${host}/checkout-simulator.html?username=${encodeURIComponent(username)}&tier=${tier}&billingCycle=${billingCycle}`;
    
    auditLog("STRIPE_GATEWAY", `Created simulated Stripe Sandbox session for ${username} (${tier} - ${billingCycle})`);
    return res.json({ success: true, url: simUrl });
});

app.post('/api/v1/subscription/upgrade', (req, res) => {
    const { username, tier, paymentMethod, cardDetails, alumniAmount, txHash } = req.body;
    const db = loadDB();
    const normUser = username.toLowerCase().trim();

    if (!db.users[normUser]) {
        return res.status(404).json({ error: "User profile not found." });
    }

    // Set Premium tier
    db.users[normUser].tier = tier;
    db.users[normUser].paymentMethod = paymentMethod;
    if (paymentMethod === 'token') {
        db.users[normUser].subscriptionTxHash = txHash;
        db.users[normUser].subscriptionAlumniAmount = alumniAmount;
    }
    saveDB(db);

    // Dynamic Audit Log for SQL traces
    auditLog(
        "UPDATE",
        `UPDATE users SET tier = '${tier}', payment_method = '${paymentMethod}' WHERE username = '${normUser}';`,
        { username: normUser, tier, paymentMethod }
    );

    if (paymentMethod === 'token') {
        auditLog(
            "INSERT",
            `INSERT INTO L1_ledger_transactions (sender, recipient, amount, payload) VALUES ('${normUser}', 'alumnimail.escrow', ${alumniAmount}, '${tier.toUpperCase()}_UPGRADE');`,
            { txHash }
        );
    }

    res.json({
        success: true,
        tier: tier,
        message: `Account successfully upgraded to ALUMNI ${tier.toUpperCase()} via ${paymentMethod === 'token' ? 'L1 Token Transfer' : 'Credit Card Transaction'}.`
    });
});

// -------------------------------------------------------------
// E2EE ENCRYPTED CALENDAR ENDPOINTS
// -------------------------------------------------------------
app.get('/api/v1/calendar/:username', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const db = loadDB();
    const normUser = req.params.username.toLowerCase().trim();

    const userMeetings = db.meetings.filter(m => m.username === normUser);

    auditLog(
        "SELECT",
        `SELECT id, encrypted_payload, date, time FROM calendar_events WHERE username = '${normUser}';`,
        { count: userMeetings.length }
    );

    res.json({ success: true, meetings: userMeetings });
});

app.post('/api/v1/calendar/add', (req, res) => {
    const { username, meeting } = req.body;
    const db = loadDB();
    const normUser = username.toLowerCase().trim();

    if (!db.users[normUser]) {
        return res.status(404).json({ error: "User profile not found." });
    }

    db.meetings.push({
        id: meeting.id,
        username: normUser,
        encryptedTitle: meeting.encryptedTitle,
        encryptedDesc: meeting.encryptedDesc,
        date: meeting.date,
        time: meeting.time,
        ivTitle: meeting.ivTitle,
        ivDesc: meeting.ivDesc,
        wrappingKey: meeting.wrappingKey
    });

    saveDB(db);

    auditLog(
        "INSERT",
        `INSERT INTO calendar_events (id, username, encrypted_title, encrypted_desc, event_date, event_time, wrapping_key) VALUES ('${meeting.id}', '${normUser}', '${meeting.encryptedTitle.substring(0, 15)}...', '${meeting.encryptedDesc.substring(0, 15)}...', '${meeting.date}', '${meeting.time}', '${meeting.wrappingKey.substring(0, 10)}...');`,
        { meetingId: meeting.id }
    );

    res.json({ success: true });
});

app.get('/api/logs', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const db = loadDB();
    res.json({ logs: db.logs });
});

app.post('/api/logs/nuke', (req, res) => {
    const seedData = { users: {}, emails: [], domains: [], aliases: [], meetings: [], logs: [] };
    saveDB(seedData);
    console.log("[DB] Nuke command completed.");
    res.json({ success: true });
});

// -------------------------------------------------------------
// VIRTUAL PHONE NUMBER / E2EE RELAY ENDPOINTS
// -------------------------------------------------------------
app.get('/api/v1/twilio/status', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ error: "Missing username parameter." });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    res.json({
        success: true,
        virtualNumber: user.virtualNumber || null,
        isSimulated: !twilioClient
    });
});

app.get('/api/v1/twilio/search-numbers', async (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const { areaCode } = req.query;
    
    // Live mode
    if (twilioClient) {
        try {
            let numbers = [];
            const TOLL_FREE_PREFIXES = ['800', '888', '877', '866', '855', '844', '833'];
            if (areaCode && TOLL_FREE_PREFIXES.includes(areaCode)) {
                // Query toll-free numbers from Twilio
                numbers = await twilioClient.availablePhoneNumbers('US').tollFree.list({ limit: 5 });
            } else {
                const searchOpts = { limit: 5 };
                if (areaCode) searchOpts.areaCode = areaCode;
                numbers = await twilioClient.availablePhoneNumbers('US').local.list(searchOpts);
            }
            const formatted = numbers.map(n => n.phoneNumber);
            return res.json({ success: true, numbers: formatted, isSimulated: false });
        } catch (e) {
            console.error("[TWILIO SEARCH ERROR]", e);
            // Fall back to simulator if real search fails due to trial account limits etc.
        }
    }

    // Simulated mode (or fallback)
    let filtered = MOCK_NUMBERS_POOL;
    if (areaCode) {
        filtered = MOCK_NUMBERS_POOL.filter(n => n.startsWith(`+1${areaCode}`));
        // if empty, let's generate some mock numbers dynamically for that area code to be helpful
        if (filtered.length === 0) {
            for (let i = 0; i < 3; i++) {
                const randPart = Math.floor(1000000 + Math.random() * 9000000);
                filtered.push(`+1${areaCode}${randPart}`);
            }
        }
    }
    res.json({ success: true, numbers: filtered.slice(0, 5), isSimulated: true });
});

app.post('/api/v1/twilio/provision-number', async (req, res) => {
    const { username, phoneNumber } = req.body;
    if (!username || !phoneNumber) {
        return res.status(400).json({ error: "Missing parameters." });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    // Premium Check
    const isBypass = ['satoshi', 'dev', 'nycole'].includes(normUser.split('@')[0]);
    if (user.tier !== 'Ultimate' && !isBypass) {
        return res.status(403).json({ error: "Virtual numbers are exclusive to the Ultimate tier." });
    }

    // Live Mode
    if (twilioClient) {
        try {
            // Purchase the number
            const twilioNumber = await twilioClient.incomingPhoneNumbers.create({
                phoneNumber: phoneNumber
            });
            console.log(`[TWILIO] Provisioned live number ${phoneNumber} for ${normUser}`);

            // Auto-configure webhooks if tunnel URL is available
            if (tunnelPublicUrl && twilioNumber.sid) {
                try {
                    await twilioClient.incomingPhoneNumbers(twilioNumber.sid).update({
                        smsUrl: `${tunnelPublicUrl}/api/v1/twilio/inbound-sms`,
                        smsMethod: 'POST',
                        voiceUrl: `${tunnelPublicUrl}/api/v1/twilio/inbound-voice`,
                        voiceMethod: 'POST'
                    });
                    console.log(`[TWILIO] Webhooks configured for ${phoneNumber} → ${tunnelPublicUrl}`);
                } catch (webhookErr) {
                    console.warn('[TWILIO] Webhook auto-config failed (can configure manually):', webhookErr.message);
                }
            }
        } catch (e) {
            console.error("[TWILIO PROVISIONING ERROR]", e);
            console.log("[TWILIO] Provisioning failed on Twilio side. Relaying as simulated provision.");
        }
    }

    user.virtualNumber = phoneNumber;
    if (!user.phoneLogs) {
        user.phoneLogs = [];
    }
    saveDB(db);

    auditLog(
        "UPDATE",
        `UPDATE users SET virtual_phone_number = '${phoneNumber}' WHERE username = '${normUser}';`,
        { username: normUser, virtualNumber: phoneNumber }
    );

    res.json({
        success: true,
        virtualNumber: phoneNumber,
        webhookConfigured: !!(tunnelPublicUrl),
        tunnelUrl: tunnelPublicUrl,
        message: `Secure virtual number ${phoneNumber} successfully provisioned and linked to your E2EE account.`
    });
});


app.post('/api/v1/twilio/release-number', async (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ error: "Missing parameters." });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    const releasedNumber = user.virtualNumber;
    user.virtualNumber = null;
    saveDB(db);

    auditLog(
        "UPDATE",
        `UPDATE users SET virtual_phone_number = NULL WHERE username = '${normUser}';`,
        { username: normUser, releasedNumber }
    );

    res.json({
        success: true,
        message: "Secure virtual number successfully released and unlinked from your E2EE account."
    });
});

app.get('/api/v1/twilio/logs', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ error: "Missing username parameter." });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    res.json({
        success: true,
        logs: user.phoneLogs || []
    });
});

app.post('/api/v1/twilio/simulate-inbound', (req, res) => {
    const { username, from, body, type } = req.body;
    if (!username || !from || !body || !type) {
        return res.status(400).json({ error: "Missing inbound simulation parameters." });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    if (!user.virtualNumber) {
        return res.status(400).json({ error: "No virtual number provisioned for this user." });
    }

    // Add log entry
    if (!user.phoneLogs) {
        user.phoneLogs = [];
    }
    const newLog = {
        id: "msg_" + Math.random().toString(36).substring(2, 9),
        timestamp: Date.now(),
        type: type, // 'sms' or 'voice'
        from: from,
        body: body,
        relayed: true
    };
    user.phoneLogs.unshift(newLog); // newer first
    saveDB(db);

    auditLog(
        "INSERT",
        `INSERT INTO e2ee_phone_relay_logs (user_id, relay_type, from_number, message_body) VALUES ('${normUser}', '${type}', '${from}', '${body.substring(0, 20)}...');`,
        newLog
    );

    res.json({
        success: true,
        log: newLog,
        message: `Simulated inbound E2EE ${type.toUpperCase()} relayed successfully.`
    });
});

// ------------------------------------------------------------------
// TUNNEL MANAGEMENT — register a public tunnel URL so Twilio webhooks
// can reach the local server. Run: npx localtunnel --port 8000
// ------------------------------------------------------------------

// GET /api/v1/tunnel/status — returns the current tunnel URL
app.get('/api/v1/tunnel/status', (req, res) => {
    res.json({
        tunnelUrl: tunnelPublicUrl,
        active: !!tunnelPublicUrl,
        smsWebhook: tunnelPublicUrl ? `${tunnelPublicUrl}/api/v1/twilio/inbound-sms` : null,
        voiceWebhook: tunnelPublicUrl ? `${tunnelPublicUrl}/api/v1/twilio/inbound-voice` : null
    });
});

// POST /api/v1/tunnel/register — set the public tunnel URL
app.post('/api/v1/tunnel/register', async (req, res) => {
    const { url } = req.body;
    if (!url || !url.startsWith('http')) {
        return res.status(400).json({ error: 'Valid public URL required (http:// or https://)' });
    }
    tunnelPublicUrl = url.replace(/\/$/, ''); // strip trailing slash
    console.log(`[TUNNEL] Public URL registered: ${tunnelPublicUrl}`);

    // Auto-update webhooks on ALL provisioned numbers
    if (twilioClient) {
        try {
            const db = loadDB();
            const numbers = await twilioClient.incomingPhoneNumbers.list();
            for (const num of numbers) {
                await twilioClient.incomingPhoneNumbers(num.sid).update({
                    smsUrl: `${tunnelPublicUrl}/api/v1/twilio/inbound-sms`,
                    smsMethod: 'POST',
                    voiceUrl: `${tunnelPublicUrl}/api/v1/twilio/inbound-voice`,
                    voiceMethod: 'POST'
                });
                console.log(`[TUNNEL] Updated webhooks for ${num.phoneNumber}`);
            }
        } catch (e) {
            console.warn('[TUNNEL] Twilio webhook update error:', e.message);
        }
    }

    res.json({
        success: true,
        tunnelUrl: tunnelPublicUrl,
        smsWebhook: `${tunnelPublicUrl}/api/v1/twilio/inbound-sms`,
        voiceWebhook: `${tunnelPublicUrl}/api/v1/twilio/inbound-voice`,
        message: 'Tunnel URL registered and webhooks updated on all active numbers.'
    });
});

// ------------------------------------------------------------------
// TWILIO INBOUND WEBHOOKS — real SMS and Voice relay from Twilio
// ------------------------------------------------------------------

// POST /api/v1/twilio/inbound-sms — Twilio calls this when an SMS arrives
app.post('/api/v1/twilio/inbound-sms', express.urlencoded({ extended: false }), async (req, res) => {
    const from = req.body.From;   // sender's real number
    const to   = req.body.To;     // our virtual number
    const body = req.body.Body || '';

    console.log(`[TWILIO INBOUND SMS] From: ${from} → To: ${to} | Body: ${body.substring(0, 50)}`);

    const db = loadDB();
    // Find the user whose virtualNumber matches `to`
    const normTo = to.trim();
    const matchedUser = Object.values(db.users).find(u => u.virtualNumber === normTo);

    if (matchedUser) {
        if (!matchedUser.phoneLogs) matchedUser.phoneLogs = [];
        const logEntry = {
            id: 'sms_' + Math.random().toString(36).substring(2, 9),
            timestamp: Date.now(),
            type: 'sms',
            from,
            to,
            body,
            relayed: true,
            live: true
        };
        matchedUser.phoneLogs.unshift(logEntry);
        db.users[matchedUser.username || Object.keys(db.users).find(k => db.users[k] === matchedUser)] = matchedUser;
        saveDB(db);
        auditLog('INSERT', `INSERT INTO e2ee_phone_relay_logs (relay_type, from_number, to_number, body) VALUES ('sms', '${from}', '${to}', '${body.substring(0,30)}...');`);
        console.log(`[TWILIO INBOUND SMS] Relayed to E2EE inbox for user with number ${to}`);
    } else {
        console.warn(`[TWILIO INBOUND SMS] No user found for number ${to}`);
    }

    // Respond with empty TwiML (no auto-reply)
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
});

// POST /api/v1/twilio/inbound-voice — Twilio calls this when a voice call arrives
app.post('/api/v1/twilio/inbound-voice', express.urlencoded({ extended: false }), async (req, res) => {
    const from = req.body.From;
    const to   = req.body.To;
    const callSid = req.body.CallSid;

    console.log(`[TWILIO INBOUND CALL] From: ${from} → To: ${to} | SID: ${callSid}`);

    const db = loadDB();
    const normTo = to.trim();
    const matchedUser = Object.values(db.users).find(u => u.virtualNumber === normTo);

    if (matchedUser) {
        if (!matchedUser.phoneLogs) matchedUser.phoneLogs = [];
        const logEntry = {
            id: 'call_' + Math.random().toString(36).substring(2, 9),
            timestamp: Date.now(),
            type: 'voice',
            from,
            to,
            body: `Inbound voice call from ${from}`,
            relayed: true,
            live: true,
            callSid
        };
        matchedUser.phoneLogs.unshift(logEntry);
        saveDB(db);
        auditLog('INSERT', `INSERT INTO e2ee_phone_relay_logs (relay_type, from_number, to_number, call_sid) VALUES ('voice', '${from}', '${to}', '${callSid}');`);
    }

    // TwiML: say a message and hang up (caller gets an announcement)
    res.set('Content-Type', 'text/xml');
    res.send(`<Response>
    <Say voice="alice">This number is protected by Alumni Mail end-to-end encryption. Your message has been securely relayed. Goodbye.</Say>
    <Hangup/>
</Response>`);
});

// POST /api/v1/twilio/send-sms — send an outbound SMS from the user's virtual number
app.post('/api/v1/twilio/send-sms', async (req, res) => {
    const { username, to, body } = req.body;
    if (!username || !to || !body) {
        return res.status(400).json({ error: 'Missing username, to, or body' });
    }
    const db = loadDB();
    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];
    if (!user || !user.virtualNumber) {
        return res.status(400).json({ error: 'No virtual number provisioned for this account.' });
    }

    if (!twilioClient) {
        return res.status(503).json({ error: 'SMS relay not available in sandbox mode. Add Twilio credentials to .env.' });
    }

    try {
        const message = await twilioClient.messages.create({
            body,
            from: user.virtualNumber,
            to
        });
        console.log(`[TWILIO SMS SENT] From: ${user.virtualNumber} → To: ${to} | SID: ${message.sid}`);

        // Log it
        if (!user.phoneLogs) user.phoneLogs = [];
        user.phoneLogs.unshift({
            id: 'out_' + Math.random().toString(36).substring(2, 9),
            timestamp: Date.now(),
            type: 'sms_out',
            from: user.virtualNumber,
            to,
            body,
            relayed: true,
            live: true,
            sid: message.sid
        });
        saveDB(db);

        res.json({ success: true, sid: message.sid, from: user.virtualNumber, to });
    } catch (e) {
        console.error('[TWILIO SEND SMS ERROR]', e);
        res.status(500).json({ error: e.message });
    }
});

// Serve Ethereal test inbox interface or standard root dashboard index
app.get('*', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'index.html'));
});

// -------------------------------------------------------------
// BOOTSTRAPPING HTTP & WEBSOCKET SIGNALLING SERVERS
// -------------------------------------------------------------
const http = require('http');
const ws = require('ws');
const server = http.createServer(app);
const wss = new ws.Server({ server });

wss.on('connection', (socket) => {
    let registeredUser = null;
    
    socket.on('message', (messageRaw) => {
        try {
            const data = JSON.parse(messageRaw);
            const { type } = data;
            
            switch (type) {
                case 'register': {
                    const normUser = getNormUsername(data.username);
                    registeredUser = normUser;
                    activeCalls.set(normUser, socket);
                    socket.send(JSON.stringify({ type: 'registered', status: 'success' }));
                    auditLog("WS_SIGNAL", `User registered for calling signaling: ${normUser}`);
                    break;
                }
                
                case 'call-user': {
                    const targetNorm = getNormUsername(data.target);
                    const callerNorm = registeredUser || getNormUsername(data.caller);
                    const targetSocket = activeCalls.get(targetNorm);
                    
                    if (targetSocket && targetSocket.readyState === ws.OPEN) {
                        targetSocket.send(JSON.stringify({
                            type: 'incoming-call',
                            caller: callerNorm,
                            offer: data.offer,
                            callType: data.callType
                        }));
                        auditLog("WS_SIGNAL", `Relaying call-user offer from ${callerNorm} to ${targetNorm}`);
                    } else {
                        socket.send(JSON.stringify({
                            type: 'call-failed',
                            reason: 'Recipient offline or unreachable on signaling server'
                        }));
                        auditLog("WS_SIGNAL", `Call offer failed: recipient ${targetNorm} is offline`);
                    }
                    break;
                }
                
                case 'call-accepted': {
                    const targetNorm = getNormUsername(data.target);
                    const targetSocket = activeCalls.get(targetNorm);
                    
                    if (targetSocket && targetSocket.readyState === ws.OPEN) {
                        targetSocket.send(JSON.stringify({
                            type: 'call-accepted',
                            answer: data.answer
                        }));
                        auditLog("WS_SIGNAL", `Relaying call-accepted answer to ${targetNorm}`);
                    }
                    break;
                }
                
                case 'webrtc-ice': {
                    const targetNorm = getNormUsername(data.target);
                    const targetSocket = activeCalls.get(targetNorm);
                    
                    if (targetSocket && targetSocket.readyState === ws.OPEN) {
                        targetSocket.send(JSON.stringify({
                            type: 'webrtc-ice',
                            candidate: data.candidate
                        }));
                    }
                    break;
                }
                
                case 'hangup-call': {
                    const targetNorm = getNormUsername(data.target);
                    const targetSocket = activeCalls.get(targetNorm);
                    
                    if (targetSocket && targetSocket.readyState === ws.OPEN) {
                        targetSocket.send(JSON.stringify({
                            type: 'hangup-call'
                        }));
                        auditLog("WS_SIGNAL", `Relaying hangup from ${registeredUser} to ${targetNorm}`);
                    }
                    break;
                }
                
                default:
                    console.warn("Unknown websocket signal type:", type);
            }
        } catch (e) {
            console.error("Failed to parse websocket message payload:", e);
        }
    });
    
    socket.on('close', () => {
        if (registeredUser && activeCalls.get(registeredUser) === socket) {
            activeCalls.delete(registeredUser);
            auditLog("WS_SIGNAL", `User disconnected from calling signaling: ${registeredUser}`);
        }
    });
});

const activeCalls = new Map();

server.listen(PORT, async () => {
    console.log(`\n[SERVER] Alumni Mail backend running live at http://localhost:${PORT}`);
    console.log(`[MOBILE ACCESS] To connect securely on a mobile phone for E2EE cryptography:`);
    console.log(`   Use a secure tunnel: run 'npx localtunnel --port ${PORT}' or use ngrok, then load the HTTPS URL on your phone.\n`);
    await initSMTPTransporter();
});
