/**
 * Alumni Mail Mock Secure Database
 * Manages schema and persistent state in LocalStorage.
 * Emits audit events to hook into the Database Inspector UI.
 */

class MockDatabase {
    constructor() {
        this.listeners = [];
        this.logListeners = [];
        this.initDatabase();
    }

    initDatabase() {
        if (!localStorage.getItem('alumni_mail_users')) {
            localStorage.setItem('alumni_mail_users', JSON.stringify({}));
        }
        if (!localStorage.getItem('alumni_mail_emails')) {
            localStorage.setItem('alumni_mail_emails', JSON.stringify([]));
        }
        if (!localStorage.getItem('alumni_mail_domains')) {
            localStorage.setItem('alumni_mail_domains', JSON.stringify([]));
        }
        if (!localStorage.getItem('alumni_mail_aliases')) {
            localStorage.setItem('alumni_mail_aliases', JSON.stringify([]));
        }
        this.seedInitialData();
    }

    // Seed some initial accounts if database is empty to allow instant demo
    seedInitialData() {
        const users = JSON.parse(localStorage.getItem('alumni_mail_users'));
        if (Object.keys(users).length === 0) {
            // We don't pre-generate keys here because they require Web Crypto async calls
            // Instead, the app.js will handle key generation and register active demo users.
            this.auditLog("SYSTEM", "Initialized clean database. Ready for user registrations.");
        }
    }

    // --- Subscriptions for reactivity ---
    subscribe(callback) {
        this.listeners.push(callback);
        return () => {
            this.listeners = this.listeners.filter(l => l !== callback);
        };
    }

    notify() {
        this.listeners.forEach(callback => callback());
    }

    // --- Audit Logging for the Security Console ---
    subscribeToLogs(callback) {
        this.logListeners.push(callback);
        return () => {
            this.logListeners = this.logListeners.filter(l => l !== callback);
        };
    }

    auditLog(action, sqlQuery, rawData = null) {
        const timestamp = new Date().toLocaleTimeString();
        const log = { timestamp, action, sqlQuery, rawData };
        this.logListeners.forEach(callback => callback(log));
    }

    // --- User Operations ---
    getUser(username) {
        const users = JSON.parse(localStorage.getItem('alumni_mail_users'));
        const user = users[username.toLowerCase()];
        this.auditLog(
            "SELECT", 
            `SELECT * FROM users WHERE username = '${username.toLowerCase()}';`,
            user ? { username: user.username, publicJwk: "[RSA Public Key]", encPrivateKey: "[AES Encrypted Private Key]" } : null
        );
        return user;
    }

    registerUser(username, authHash, salt, publicJwk, encPrivateKey) {
        const users = JSON.parse(localStorage.getItem('alumni_mail_users'));
        const normalized = username.toLowerCase();
        
        users[normalized] = {
            username: normalized,
            authHash,
            salt,
            publicJwk,
            encPrivateKey
        };

        localStorage.setItem('alumni_mail_users', JSON.stringify(users));
        
        this.auditLog(
            "INSERT",
            `INSERT INTO users (username, auth_hash, salt, public_key, encrypted_private_key) VALUES ('${normalized}', '${authHash.substring(0, 16)}...', '${salt.substring(0, 16)}...', '[RSA_JWK]', '[AES_GCM_CIPHERTEXT]');`,
            { username: normalized }
        );
        
        this.notify();
        return users[normalized];
    }

    // --- Domain & Alias Operations ---
    getDomainsForUser(username) {
        const domains = JSON.parse(localStorage.getItem('alumni_mail_domains'));
        const userDomains = domains.filter(d => d.owner.toLowerCase() === username.toLowerCase());
        this.auditLog("SELECT", `SELECT * FROM domains WHERE owner = '${username.toLowerCase()}';`, userDomains);
        return userDomains;
    }

    addDomain(domainName, username) {
        const domains = JSON.parse(localStorage.getItem('alumni_mail_domains'));
        const normDomain = domainName.toLowerCase().trim();
        
        // Generate mock DNS verification values
        const dkimSelector = "alumni";
        const dkimValue = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0y...";
        
        const newDomain = {
            domainName: normDomain,
            owner: username.toLowerCase(),
            isVerified: false,
            dnsRecords: {
                mx: { type: "MX", host: "@", value: "mail.alumnimail.com", priority: 10, resolved: false },
                spf: { type: "TXT", host: "@", value: "v=spf1 include:alumnimail.com ~all", resolved: false },
                dkim: { type: "TXT", host: `${dkimSelector}._domainkey`, value: dkimValue, resolved: false },
                dmarc: { type: "TXT", host: "_dmarc", value: "v=DMARC1; p=quarantine; pct=100;", resolved: false }
            }
        };

        domains.push(newDomain);
        localStorage.setItem('alumni_mail_domains', JSON.stringify(domains));
        
        this.auditLog(
            "INSERT",
            `INSERT INTO domains (domain_name, owner, is_verified) VALUES ('${normDomain}', '${username.toLowerCase()}', 0);`,
            newDomain
        );
        
        this.notify();
        return newDomain;
    }

    verifyDomainRecord(domainName, recordType) {
        const domains = JSON.parse(localStorage.getItem('alumni_mail_domains'));
        const domain = domains.find(d => d.domainName.toLowerCase() === domainName.toLowerCase());
        
        if (domain && domain.dnsRecords[recordType]) {
            domain.dnsRecords[recordType].resolved = true;
            
            // Check if all verified
            const allVerified = Object.values(domain.dnsRecords).every(rec => rec.resolved === true);
            if (allVerified) {
                domain.isVerified = true;
            }
            
            localStorage.setItem('alumni_mail_domains', JSON.stringify(domains));
            
            this.auditLog(
                "UPDATE",
                `UPDATE domains SET dns_${recordType}_resolved = 1${allVerified ? ", is_verified = 1" : ""} WHERE domain_name = '${domainName.toLowerCase()}';`,
                domain
            );
            
            this.notify();
            return domain;
        }
        return null;
    }

    getAliasesForUser(username) {
        const aliases = JSON.parse(localStorage.getItem('alumni_mail_aliases'));
        const userAliases = aliases.filter(a => a.owner.toLowerCase() === username.toLowerCase());
        this.auditLog("SELECT", `SELECT * FROM aliases WHERE owner = '${username.toLowerCase()}';`, userAliases);
        return userAliases;
    }

    createAlias(email, username, publicJwk, encPrivateKey) {
        const aliases = JSON.parse(localStorage.getItem('alumni_mail_aliases'));
        const normalizedEmail = email.toLowerCase().trim();
        
        const newAlias = {
            email: normalizedEmail,
            owner: username.toLowerCase(),
            publicJwk,
            encPrivateKey
        };

        aliases.push(newAlias);
        localStorage.setItem('alumni_mail_aliases', JSON.stringify(aliases));
        
        this.auditLog(
            "INSERT",
            `INSERT INTO aliases (email, owner, public_key, encrypted_private_key) VALUES ('${normalizedEmail}', '${username.toLowerCase()}', '[RSA_JWK]', '[AES_GCM_CIPHERTEXT]');`,
            { email: normalizedEmail, owner: username.toLowerCase() }
        );
        
        this.notify();
        return newAlias;
    }

    // Find custom alias or user public key to send E2EE mail
    getPublicKey(emailAddress) {
        const norm = emailAddress.toLowerCase().trim();
        
        // 1. Check primary users
        const users = JSON.parse(localStorage.getItem('alumni_mail_users'));
        if (users[norm]) {
            this.auditLog("SELECT", `SELECT public_key FROM users WHERE username = '${norm}';`);
            return users[norm].publicJwk;
        }

        // 2. Check aliases
        const aliases = JSON.parse(localStorage.getItem('alumni_mail_aliases'));
        const alias = aliases.find(a => a.email === norm);
        if (alias) {
            this.auditLog("SELECT", `SELECT public_key FROM aliases WHERE email = '${norm}';`);
            return alias.publicJwk;
        }

        this.auditLog("SELECT", `SELECT public_key FROM users, aliases WHERE email = '${norm}'; -> NOT FOUND`);
        return null;
    }

    // --- Email Operations ---
    getEmailsForUser(emailAddress) {
        const emails = JSON.parse(localStorage.getItem('alumni_mail_emails'));
        const norm = emailAddress.toLowerCase().trim();
        
        // Return emails where user is sender or recipient (handling deleted states)
        const userEmails = emails.filter(e => 
            e.recipient.toLowerCase() === norm || e.sender.toLowerCase() === norm
        );

        this.auditLog(
            "SELECT",
            `SELECT * FROM emails WHERE recipient = '${norm}' OR sender = '${norm}';`,
            `Found ${userEmails.length} messages. Payload bodies are fully encrypted.`
        );

        return userEmails;
    }

    sendEmail({ sender, recipient, encryptedPayload, encryptedSessionKey = null, iv, salt = null, isPasswordProtected = false, passwordHint = "" }) {
        const emails = JSON.parse(localStorage.getItem('alumni_mail_emails'));
        
        const newEmail = {
            id: 'mail-' + Math.random().toString(36).substr(2, 9),
            sender: sender.toLowerCase().trim(),
            recipient: recipient.toLowerCase().trim(),
            encryptedPayload,
            encryptedSessionKey,
            iv,
            salt,
            isPasswordProtected,
            passwordHint,
            timestamp: Date.now(),
            read: false,
            deletedBySender: false,
            deletedByRecipient: false
        };

        emails.push(newEmail);
        localStorage.setItem('alumni_mail_emails', JSON.stringify(emails));

        this.auditLog(
            "INSERT",
            `INSERT INTO emails (id, sender, recipient, encrypted_payload, encrypted_session_key, iv, is_password_protected) VALUES ('${newEmail.id}', '${newEmail.sender}', '${newEmail.recipient}', '${encryptedPayload.substring(0, 16)}...', '${encryptedSessionKey ? encryptedSessionKey.substring(0, 16) : 'NULL'}...', '${iv.substring(0, 10)}...', ${isPasswordProtected ? 1 : 0});`,
            { id: newEmail.id, sender: newEmail.sender, recipient: newEmail.recipient }
        );

        this.notify();
        return newEmail;
    }

    deleteEmail(id, username) {
        const emails = JSON.parse(localStorage.getItem('alumni_mail_emails'));
        const email = emails.find(e => e.id === id);
        const normUser = username.toLowerCase().trim();

        if (email) {
            if (email.sender === normUser) {
                email.deletedBySender = true;
            }
            if (email.recipient === normUser) {
                email.deletedByRecipient = true;
            }

            // If both deleted or if one deleted and it's a one-sided email, we can prune it
            const fullyDeleted = (email.deletedBySender && email.deletedByRecipient);
            
            localStorage.setItem('alumni_mail_emails', JSON.stringify(emails));
            
            this.auditLog(
                "UPDATE",
                `UPDATE emails SET deleted = 1 WHERE id = '${id}';`,
                { id, deletedBySender: email.deletedBySender, deletedByRecipient: email.deletedByRecipient }
            );

            this.notify();
            return true;
        }
        return false;
    }

    // --- Diagnostic Cleans ---
    nukeDatabase() {
        localStorage.removeItem('alumni_mail_users');
        localStorage.removeItem('alumni_mail_emails');
        localStorage.removeItem('alumni_mail_domains');
        localStorage.removeItem('alumni_mail_aliases');
        this.initDatabase();
        this.auditLog("DATABASE NUKE", "TRUNCATE ALL TABLES; All local storage has been wiped clean.");
        this.notify();
    }
}

// Make globally available
window.AlumniMailDB = new MockDatabase();
