/**
 * Alumni Mail Client-Server Database Adapter
 * Refactored to act as a reactive gateway querying the Node.js backend.
 * Uses local memory caching to support synchronous frontend API requirements
 * and implements query tracer long-polling.
 */

function getNormUsername(username) {
    if (!username) return "";
    let clean = username.trim();
    if (!clean.includes('@')) {
        clean = `${clean}@alumnimail.app`;
    }
    return clean.toLowerCase();
}

class MockDatabase {
    constructor() {
        this.listeners = [];
        this.logListeners = [];
        this.seenLogs = new Set();
        
        // Local state cache
        this.cache = {
            users: {},
            emails: [],
            domains: [],
            aliases: [],
            logs: []
        };

        // API Endpoint Configuration (Uses active origin dynamically)
        this.apiBase = window.location.origin;

        // Bootstrapping: fetch initial server state
        this.syncWithServer();

        // Safe self-scheduling loop for reactive real-time logs and updates
        this._isSyncingLogs = false;
        setTimeout(() => {
            this.syncLogs();
        }, 1500);
    }

    async syncWithServer() {
        try {
            // We fetch the shared datasets to sync our local cache
            const logsRes = await fetch(`${this.apiBase}/api/logs`);
            if (logsRes.ok) {
                const data = await logsRes.json();
                this.cache.logs = data.logs;
                // Emit raw log lines to listeners on first fetch and store signatures
                data.logs.forEach(log => {
                    const signature = `${log.timestamp}|${log.action}|${log.sqlQuery}|${typeof log.rawData === 'object' ? JSON.stringify(log.rawData) : log.rawData}`;
                    this.seenLogs.add(signature);
                    this.emitLog(log);
                });
            }
        } catch (e) {
            console.warn("Server offline or loading initial state.", e.message);
        }
    }

    async syncLogs() {
        if (this._isSyncingLogs) return;
        this._isSyncingLogs = true;
        try {
            const res = await fetch(`${this.apiBase}/api/logs`);
            if (res.ok) {
                const data = await res.json();
                const newLogs = [];
                for (const log of data.logs) {
                    const signature = `${log.timestamp}|${log.action}|${log.sqlQuery}|${typeof log.rawData === 'object' ? JSON.stringify(log.rawData) : log.rawData}`;
                    if (!this.seenLogs.has(signature)) {
                        this.seenLogs.add(signature);
                        newLogs.push(log);
                    }
                }

                // Capping the seenLogs Set to prevent memory growth
                if (this.seenLogs.size > 500) {
                    const keys = Array.from(this.seenLogs.keys());
                    const toRemove = keys.slice(0, 200);
                    toRemove.forEach(k => this.seenLogs.delete(k));
                }

                if (newLogs.length > 0) {
                    this.cache.logs = data.logs;
                    newLogs.forEach(log => this.emitLog(log));
                }
            }
        } catch (e) {
            // Suppress errors to avoid cluttering browser developer console
        } finally {
            this._isSyncingLogs = false;
            // Schedule the next poll safely 1.5s after this one finishes
            setTimeout(() => this.syncLogs(), 1500);
        }
    }

    // -------------------------------------------------------------
    // CLIENT EVENT SUBSCRIBERS
    // -------------------------------------------------------------
    subscribe(listener) {
        this.listeners.push(listener);
    }

    subscribeToLogs(listener) {
        this.logListeners.push(listener);
    }

    emit() {
        this.listeners.forEach(l => l());
    }

    emitLog(log) {
        this.logListeners.forEach(l => l(log));
    }

    // Helper: Push custom audit trace to the server logs
    async auditLog(action, sqlQuery) {
        try {
            // We let the server insert logs natively, but client operations
            // can call this helper to log standard transaction actions.
            console.log(`[CLIENT-DB] ${action}: ${sqlQuery}`);
        } catch (e) {
            console.error(e);
        }
    }

    // -------------------------------------------------------------
    // USER AUTHENTICATION ENDPOINTS
    // -------------------------------------------------------------
    getUser(username) {
        // Since app.js does synchronous checks, we fetch from local storage backup
        // or return a mock record until resolved. To ensure login works perfectly,
        // we can dynamically sync the user record to LocalStorage during registration/login.
        const norm = getNormUsername(username);
        const localUsers = JSON.parse(localStorage.getItem('alumni_mail_users') || '{}');
        return localUsers[norm] || null;
    }

    async registerUser(username, authHash, salt, publicJwk, encPrivateKey) {
        const norm = getNormUsername(username);
        
        // Sync local storage copy for synchronous checks in app.js
        const localUsers = JSON.parse(localStorage.getItem('alumni_mail_users') || '{}');
        localUsers[norm] = { username: norm, authHash, salt, publicJwk, encPrivateKey };
        localStorage.setItem('alumni_mail_users', JSON.stringify(localUsers));

        try {
            const res = await fetch(`${this.apiBase}/api/auth/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: norm, authHash, salt, publicJwk, encPrivateKey })
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || "Registration rejected.");
            }
            this.emit();
        } catch (e) {
            console.error("Server register sync failed:", e.message);
        }
    }

    // Helper to cache login state locally
    saveLoggedInUserCache(username, salt, publicJwk, encPrivateKey) {
        const norm = getNormUsername(username);
        const localUsers = JSON.parse(localStorage.getItem('alumni_mail_users') || '{}');
        localUsers[norm] = { username: norm, authHash: "", salt, publicJwk, encPrivateKey };
        localStorage.setItem('alumni_mail_users', JSON.stringify(localUsers));
    }

    // -------------------------------------------------------------
    // SECURE CUSTOM DOMAINS
    // -------------------------------------------------------------
    getDomainsForUser(username) {
        const localDom = JSON.parse(localStorage.getItem('alumni_mail_domains') || '[]');
        return localDom.filter(d => d.owner === getNormUsername(username));
    }

    async addDomain(domainName, owner) {
        const normDom = domainName.toLowerCase().trim();
        const normOwner = getNormUsername(owner);

        // Optimistically update local cache
        const localDom = JSON.parse(localStorage.getItem('alumni_mail_domains') || '[]');
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
        localDom.push(newDomain);
        localStorage.setItem('alumni_mail_domains', JSON.stringify(localDom));

        try {
            await fetch(`${this.apiBase}/api/domains/add`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domainName: normDom, owner: normOwner })
            });
            this.emit();
        } catch (e) {
            console.error(e);
        }
    }

    async verifyDomainRecord(domainName, recordType) {
        const normDom = domainName.toLowerCase().trim();
        
        // Update local storage status
        const localDom = JSON.parse(localStorage.getItem('alumni_mail_domains') || '[]');
        const dom = localDom.find(d => d.domainName === normDom);
        if (dom) {
            dom.dnsRecords[recordType].resolved = true;
            const allResolved = Object.values(dom.dnsRecords).every(r => r.resolved);
            if (allResolved) dom.isVerified = true;
            localStorage.setItem('alumni_mail_domains', JSON.stringify(localDom));
        }

        try {
            const res = await fetch(`${this.apiBase}/api/domains/verify`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domainName: normDom, recordType })
            });
            if (res.ok) {
                const data = await res.json();
                this.emit();
                return data.domain;
            }
        } catch (e) {
            console.error(e);
        }
        return dom;
    }

    // -------------------------------------------------------------
    // ALIAS REGISTRY
    // -------------------------------------------------------------
    getAliasesForUser(username) {
        const norm = getNormUsername(username);
        const localAliases = JSON.parse(localStorage.getItem('alumni_mail_aliases') || '[]');
        return localAliases.filter(a => getNormUsername(a.owner) === norm);
    }

    async createAlias(email, owner, publicJwk, encPrivateKey) {
        const normEmail = email.toLowerCase().trim();
        const normOwner = getNormUsername(owner);

        // Local cache write
        const localAliases = JSON.parse(localStorage.getItem('alumni_mail_aliases') || '[]');
        const newAlias = { email: normEmail, owner: normOwner, publicJwk, encPrivateKey };
        localAliases.push(newAlias);
        localStorage.setItem('alumni_mail_aliases', JSON.stringify(localAliases));

        try {
            await fetch(`${this.apiBase}/api/aliases/create`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: normEmail, owner: normOwner, publicJwk, encPrivateKey })
            });
            this.emit();
        } catch (e) {
            console.error(e);
        }
    }

    getPublicKey(username) {
        // Direct synchronous check fallback.
        // During composition, this checks if a recipient has an active encryption key.
        // We do a local sync on boot, and dynamically resolve external addresses.
        // If not found in LocalStorage, we fall back to querying the cached list.
        const norm = getNormUsername(username);
        
        // Check primary users
        const localUsers = JSON.parse(localStorage.getItem('alumni_mail_users') || '{}');
        if (localUsers[norm]) return localUsers[norm].publicJwk;

        // Check custom aliases
        const localAliases = JSON.parse(localStorage.getItem('alumni_mail_aliases') || '[]');
        const alias = localAliases.find(a => getNormUsername(a.email) === norm);
        if (alias) return alias.publicJwk;

        // Dynamic E2EE Recipient discovery: Hal is seeded by default
        if (norm === 'hal@alumnimail.app') {
            return {
                alg: "RSA-OAEP-256",
                ext: true,
                key_ops: ["encrypt"],
                kty: "RSA",
                n: "u1-E2EE-Seeded-Public-Key-Buffer...",
                e: "AQAB"
            };
        }

        return null;
    }

    // -------------------------------------------------------------
    // ENCRYPTED EMAIL SERVICES
    // -------------------------------------------------------------
    getEmailsForUser(username) {
        const norm = getNormUsername(username);
        const localEmails = JSON.parse(localStorage.getItem('alumni_mail_emails') || '[]');
        return localEmails.filter(e => getNormUsername(e.sender) === norm || getNormUsername(e.recipient) === norm);
    }

    async sendEmail(email) {
        // Write to local emails cache
        const localEmails = JSON.parse(localStorage.getItem('alumni_mail_emails') || '[]');
        const newEmail = {
            id: email.id || 'em_' + Math.random().toString(36).substring(2, 11),
            sender: email.sender,
            recipient: email.recipient,
            encryptedPayload: email.encryptedPayload,
            encryptedSessionKey: email.encryptedSessionKey,
            iv: email.iv,
            salt: email.salt,
            isPasswordProtected: email.isPasswordProtected || false,
            passwordHint: email.passwordHint || "",
            timestamp: Date.now(),
            read: false,
            deletedBySender: false,
            deletedByRecipient: false
        };
        localEmails.push(newEmail);
        localStorage.setItem('alumni_mail_emails', JSON.stringify(localEmails));

        try {
            const res = await fetch(`${this.apiBase}/api/mail/send`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(email)
            });
            if (res.ok) {
                const data = await res.json();
                if (data.previewUrl) {
                    // Display Ethereal inspection logs in the browser alert if sandboxed!
                    setTimeout(() => {
                        alert(`📧 Real email sent out! Since we are running in testing relay mode, you can inspect it here:\n${data.previewUrl}`);
                    }, 500);
                }
                this.emit();
            }
        } catch (e) {
            console.error("API send failed:", e);
        }
    }

    async deleteEmail(emailId, username) {
        // Sync local cache
        const localEmails = JSON.parse(localStorage.getItem('alumni_mail_emails') || '[]');
        const index = localEmails.findIndex(e => e.id === emailId);
        if (index !== -1) {
            localEmails.splice(index, 1);
            localStorage.setItem('alumni_mail_emails', JSON.stringify(localEmails));
        }

        try {
            await fetch(`${this.apiBase}/api/mail/delete/${emailId}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username })
            });
            this.emit();
        } catch (e) {
            console.error(e);
        }
    }

    // -------------------------------------------------------------
    // E2EE CALENDAR DATA INTERFACES
    // -------------------------------------------------------------
    async getMeetingsForUser(username) {
        const norm = getNormUsername(username);
        try {
            const res = await fetch(`${this.apiBase}/api/v1/calendar/${norm}`);
            if (res.ok) {
                const data = await res.json();
                localStorage.setItem(`alumni_meetings_${norm}`, JSON.stringify(data.meetings || []));
                return data.meetings || [];
            }
        } catch (e) {
            console.error("Failed to fetch meetings from server:", e);
        }
        return JSON.parse(localStorage.getItem(`alumni_meetings_${norm}`) || '[]');
    }

    async saveMeeting(username, meeting) {
        const norm = getNormUsername(username);
        const localMeetings = JSON.parse(localStorage.getItem(`alumni_meetings_${norm}`) || '[]');
        localMeetings.push(meeting);
        localStorage.setItem(`alumni_meetings_${norm}`, JSON.stringify(localMeetings));

        try {
            await fetch(`${this.apiBase}/api/v1/calendar/add`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: norm, meeting })
            });
            this.emit();
        } catch (e) {
            console.error("Failed to sync meeting to server:", e);
        }
    }

    // -------------------------------------------------------------
    // BILLING & SUBSCRIPTIONS
    // -------------------------------------------------------------
    async upgradeUserTier(username, tier, paymentMethod, cardDetails, alumniAmount, txHash) {
        const norm = getNormUsername(username);
        try {
            const res = await fetch(`${this.apiBase}/api/v1/subscription/upgrade`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: norm, tier, paymentMethod, cardDetails, alumniAmount, txHash })
            });
            if (res.ok) {
                const data = await res.json();
                localStorage.setItem(`user_tier_${norm}`, tier);
                this.emit();
                return data;
            } else {
                const err = await res.json();
                throw new Error(err.error || "Upgrade transaction rejected.");
            }
        } catch (e) {
            console.error("Failed to post upgrade request:", e);
            throw e;
        }
    }

    // -------------------------------------------------------------
    // USER DATA SYNCHRONIZATION
    // -------------------------------------------------------------
    async syncUserData(username) {
        const norm = getNormUsername(username);
        this.apiBase = window.location.origin;

        try {
            // 1. Fetch emails
            const mailRes = await fetch(`${this.apiBase}/api/mail/recipient/${encodeURIComponent(norm)}`);
            if (mailRes.ok) {
                const mailData = await mailRes.json();
                localStorage.setItem('alumni_mail_emails', JSON.stringify(mailData.emails || []));
            }

            // 2. Fetch custom domains
            const domRes = await fetch(`${this.apiBase}/api/domains/${encodeURIComponent(norm)}`);
            if (domRes.ok) {
                const domData = await domRes.json();
                localStorage.setItem('alumni_mail_domains', JSON.stringify(domData.domains || []));
            }

            // 3. Fetch aliases
            const aliasRes = await fetch(`${this.apiBase}/api/aliases/${encodeURIComponent(norm)}`);
            if (aliasRes.ok) {
                const aliasData = await aliasRes.json();
                localStorage.setItem('alumni_mail_aliases', JSON.stringify(aliasData.aliases || []));
            }

            this.emit();
            this.auditLog("SYNC", `Synchronized emails, domains, and aliases from server for ${norm}`);
        } catch (e) {
            console.error("Failed to sync user data from server:", e.message);
        }
    }

    // -------------------------------------------------------------
    // SYSTEM RESET
    // -------------------------------------------------------------
    async nukeDatabase() {
        localStorage.removeItem('alumni_mail_users');
        localStorage.removeItem('alumni_mail_emails');
        localStorage.removeItem('alumni_mail_domains');
        localStorage.removeItem('alumni_mail_aliases');
        
        // Dynamic clean
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && (key.startsWith('alumni_meetings_') || key.startsWith('user_tier_') || key.startsWith('biometric_'))) {
                localStorage.removeItem(key);
                i--;
            }
        }
        
        try {
            await fetch(`${this.apiBase}/api/logs/nuke`, { method: "POST" });
            this.emit();
        } catch (e) {
            console.error(e);
        }
    }
}

// Make globally available
window.AlumniMailDB = new MockDatabase();
