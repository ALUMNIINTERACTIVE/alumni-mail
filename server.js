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

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

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
            logs: []
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(seedData, null, 4));
        return seedData;
    }
    try {
        return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    } catch (e) {
        console.error("Corrupted database. Resetting to blank schema.");
        const resetData = { users: {}, emails: [], domains: [], aliases: [], logs: [] };
        fs.writeFileSync(DB_PATH, JSON.stringify(resetData, null, 4));
        return resetData;
    }
}

function saveDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4));
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
app.post('/api/auth/register', (req, res) => {
    const { username, authHash, salt, publicJwk, encPrivateKey } = req.body;
    const db = loadDB();

    const normUser = username.toLowerCase().trim();

    if (db.users[normUser]) {
        return res.status(400).json({ error: "Address already registered." });
    }

    db.users[normUser] = {
        username: normUser,
        authHash,
        salt,
        publicJwk,
        encPrivateKey,
        registeredAt: Date.now()
    };
    saveDB(db);

    auditLog(
        "INSERT", 
        `INSERT INTO users (username, auth_hash, salt, public_key, enc_private_key) VALUES ('${normUser}', '${authHash.substring(0, 15)}...', '${salt}', '{JWK}', '{CIPHER}');`,
        { success: true }
    );

    res.json({ success: true });
});

app.post('/api/auth/login', (req, res) => {
    const { username, authHash } = req.body;
    const db = loadDB();

    const normUser = username.toLowerCase().trim();
    const user = db.users[normUser];

    if (!user) {
        return res.status(404).json({ error: "User profile not found." });
    }

    if (user.authHash !== authHash) {
        return res.status(401).json({ error: "Auth verification failed. Incorrect password." });
    }

    auditLog(
        "SELECT",
        `SELECT salt, public_key, enc_private_key FROM users WHERE username = '${normUser}';`,
        { username: normUser }
    );

    res.json({
        success: true,
        salt: user.salt,
        publicJwk: user.publicJwk,
        encPrivateKey: user.encPrivateKey
    });
});

app.get('/api/keys/:username', (req, res) => {
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
            emailSubject = `🔑 Secure Encrypted Email from ${normSender}`;
            
            const portalUrl = `${liveHostUrl}/?portal=true&emailId=${emailId}&recipient=${encodeURIComponent(normRecipient)}`;

            emailHtml = `
                <div style="font-family: sans-serif; background-color: #060913; color: #ffffff; padding: 30px; border-radius: 12px; max-width: 600px; margin: auto; border: 1px solid #1e293b;">
                    <h2 style="color: #10b981; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-top: 0;">🔒 Secure E2EE Portal Delivery</h2>
                    <p style="color: #94a3b8; font-size: 16px;">You have received a password-protected encrypted message from <strong>${normSender}</strong> under the Alumni Mail privacy network.</p>
                    
                    <div style="background-color: rgba(16, 185, 129, 0.05); border: 1px dashed #10b981; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <span style="color: #10b981; font-weight: bold; display: block; margin-bottom: 5px;">🔑 Security Password Hint:</span>
                        <span style="color: #cbd5e1; font-style: italic;">"${passwordHint || 'No hint provided.'}"</span>
                    </div>

                    <p style="color: #94a3b8;">To unlock this message and perform local browser decryption, click the secure portal button below:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${portalUrl}" style="background-color: #10b981; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-weight: bold; display: inline-block; box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);">🔓 Unlock Secure Message</a>
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
            console.log(`\n📬 [TEST DELIVERY PENDING] Inspect email here:\n👉 ${previewUrl}\n`);
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

app.post('/api/v1/wallet/balance', async (req, res) => {
    const { tag, email } = req.body;
    if (!tag) {
        return res.status(400).json({ error: "Missing wallet tag parameter." });
    }

    // Log the transaction attempt to the SQL auditor
    auditLog("SELECT", `SELECT balance, tag FROM L1_ledger_state WHERE wallet_tag = '${tag}' AND associated_email = '${email}';`);

    const L1_RPC_URL = process.env.L1_RPC_URL;
    
    if (L1_RPC_URL) {
        try {
            // Relaying query to the live custom JSON/HTTP L1 node API
            const rpcResponse = await fetch(`${L1_RPC_URL}/api/wallet/query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tag, email }),
                timeout: 3000
            });
            const l1Data = await rpcResponse.json();
            
            return res.json({
                success: true,
                tag: tag,
                balance: l1Data.balance || 0,
                l1_status: "LIVE_LEDGER"
            });
        } catch (err) {
            console.error("[L1 RPC CONNECTION ERROR] Live blockchain API query failed:", err.message);
        }
    }

    // SIMULATION FALLBACK (Robust demo mode when offline or L1 URL is unset)
    let simulatedBalance = 2500;
    try {
        let numericHash = 0;
        for (let i = 0; i < tag.length; i++) {
            numericHash += tag.charCodeAt(i);
        }
        simulatedBalance = (numericHash * 23) % 25000 + 100;
    } catch (e) {}

    // Emulate node network round-trip handshake latency (120ms)
    await new Promise(resolve => setTimeout(resolve, 120));

    res.json({
        success: true,
        tag: tag,
        balance: simulatedBalance,
        l1_status: "OFFLINE_SIMULATION"
    });
});

app.post('/api/v1/wallet/send', async (req, res) => {
    const { fromEmail, fromTag, recipient, amount } = req.body;
    
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
    
    if (L1_RPC_URL) {
        try {
            // Relaying signed transfer request to the live custom L1 node API
            const rpcResponse = await fetch(`${L1_RPC_URL}/api/wallet/transfer`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from_tag: fromTag,
                    recipient: recipient,
                    amount: numericAmount,
                    tx_hash: txHash
                }),
                timeout: 3000
            });
            const l1Data = await rpcResponse.json();
            
            if (l1Data.success) {
                auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'SUCCESS' WHERE tx_hash = '${txHash}';`);
                return res.json({
                    success: true,
                    txHash: txHash,
                    newBalance: l1Data.newBalance || 0,
                    l1_status: "LIVE_LEDGER"
                });
            } else {
                auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'FAILED' WHERE tx_hash = '${txHash}';`);
                return res.status(400).json({ error: l1Data.error || "Transaction rejected by L1 validator pool." });
            }
        } catch (err) {
            console.error("[L1 TX BROADCAST ERROR] Failed to send to L1 RPC:", err.message);
        }
    }

    // SIMULATION FALLBACK (Simulate block consensus time)
    await new Promise(resolve => setTimeout(resolve, 300));
    auditLog("UPDATE", `UPDATE L1_ledger_transactions SET status = 'SUCCESS' WHERE tx_hash = '${txHash}';`);

    res.json({
        success: true,
        txHash: txHash,
        l1_status: "OFFLINE_SIMULATION"
    });
});

app.get('/api/logs', (req, res) => {
    const db = loadDB();
    res.json({ logs: db.logs });
});

app.post('/api/logs/nuke', (req, res) => {
    const seedData = { users: {}, emails: [], domains: [], aliases: [], logs: [] };
    saveDB(seedData);
    console.log("[DB] Nuke command completed.");
    res.json({ success: true });
});

// Serve Ethereal test inbox interface or standard root dashboard index
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// -------------------------------------------------------------
// BOOTSTRAPPING SERVER
// -------------------------------------------------------------
app.listen(PORT, async () => {
    console.log(`\n🚀 [SERVER] Alumni Mail backend running live at http://localhost:${PORT}`);
    await initSMTPTransporter();
});
