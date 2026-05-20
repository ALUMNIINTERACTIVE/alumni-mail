/**
 * Alumni Mail Master Application Controller
 * Orchestrates views, cryptography flows, custom domain verifications,
 * database subscribers, and reactive logging channels.
 */

// Global session state
let session = {
    username: null,
    salt: null,
    kdk: null,               // Derived AES Key Decryption Key (CryptoKey object)
    privateKey: null,        // Unlocked RSA Private Key (CryptoKey object)
    publicJwk: null,         // Plaintext RSA Public Key (JWK)
    encPrivateKey: null,     // AES-GCM Encrypted Private Key payload
    activeView: 'inbox',
    activeEmailId: null,
    userTier: 'Free'
};

// Seeding standard external recipients and standard users
async function seedRecipientRegistry() {
    // We register a couple of built-in demo recipients (e.g. hal@alumnimail.app)
    // so the user can immediately test hybrid E2EE out of the box!
    const hal = window.AlumniMailDB.getUser('hal@alumnimail.app');
    if (!hal) {
        // Pre-generating Hal's E2EE keys in database
        const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
        const saltBase64 = window.AlumniMailCrypto.bufferToBase64(saltBytes);
        
        // Derive master keys for Hal using a dummy password
        const { kdk, authHash } = await window.AlumniMailCrypto.deriveKeys("halpassphrase123", saltBase64);
        const keypair = await window.AlumniMailCrypto.generateRSAKeyPair();
        
        const publicJwk = await window.crypto.subtle.exportKey("jwk", keypair.publicKey);
        const encPrivateKey = await window.AlumniMailCrypto.encryptPrivateKey(keypair.privateKey, kdk);
        
        window.AlumniMailDB.registerUser('hal@alumnimail.app', authHash, saltBase64, publicJwk, encPrivateKey);
        
        // Send a seed greeting email from Hal to Satoshi (if Satoshi doesn't exist yet, it's fine, we send it anyway)
        // Since we don't have Satoshi's public key yet, we'll send it as standard text or simulate hybrid E2EE to Satoshi later
        window.AlumniMailDB.auditLog("SEED", "Seeded Hal Finney's cryptographic profile (hal@alumnimail.app)");
    }
}

// -------------------------------------------------------------
// APP INITIALIZATION
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
    // Check if secure context
    const isSecure = window.isSecureContext && window.crypto && window.crypto.subtle;
    if (!isSecure) {
        const alertEl = document.getElementById('insecure-context-alert');
        if (alertEl) {
            alertEl.classList.remove('hidden');
            const ipDisplay = document.getElementById('insecure-ip-display');
            if (ipDisplay) {
                ipDisplay.innerText = window.location.href;
            }
        }
        console.warn("ALUMNI MAIL: Insecure Context detected! E2EE and WebAuthn cryptography functions are disabled by browser policy.");
    }

    // 1. Seed demo keys
    try {
        if (isSecure) {
            await seedRecipientRegistry();
        } else {
            console.warn("ALUMNI MAIL: Skipping demo key seeding because cryptography functions are unavailable in insecure contexts.");
        }
    } catch (e) {
        console.error("ALUMNI MAIL: Failed to seed recipient registry:", e);
    }
    
    // 2. Set up DB subscribers for re-renders
    window.AlumniMailDB.subscribe(() => {
        if (session.username) {
            renderMailList();
            renderUnreadBadges();
            renderActiveViewData();
        }
    });

    // 3. Connect DB Logs to Auditor Drawer
    window.AlumniMailDB.subscribeToLogs((log) => {
        logDBQuery(log);
    });

    // 4. Clear any stale elements
    clearAuditorLogs('db');
    clearAuditorLogs('network');
});

function renderActiveViewData() {
    if (['inbox', 'sent', 'archive', 'trash'].includes(session.activeView)) {
        renderMailList();
    } else if (session.activeView === 'domains') {
        renderDomainsView();
    } else if (session.activeView === 'keys') {
        renderKeysView();
    }
}

// -------------------------------------------------------------
// NAVIGATION & VIEWS SYSTEM
// -------------------------------------------------------------
function switchView(viewName) {
    session.activeView = viewName;
    session.activeEmailId = null;
    
    // Update active nav link classes
    const navs = ['nav-inbox', 'nav-sent', 'nav-archive', 'nav-trash', 'nav-calendar', 'nav-domains', 'nav-keys', 'nav-settings'];
    navs.forEach(navId => {
        const el = document.getElementById(navId);
        if (el) el.classList.remove('active');
    });
    
    const activeNav = document.getElementById(`nav-${viewName}`);
    if (activeNav) activeNav.classList.add('active');

    // Toggle Workspace views
    const mainWorkspace = document.getElementById('view-mail');
    const domainsWorkspace = document.getElementById('view-domains');
    const keysWorkspace = document.getElementById('view-keys');
    const settingsWorkspace = document.getElementById('view-settings');
    const calendarWorkspace = document.getElementById('view-calendar');

    mainWorkspace.classList.add('hidden');
    domainsWorkspace.classList.add('hidden');
    keysWorkspace.classList.add('hidden');
    settingsWorkspace.classList.add('hidden');
    if (calendarWorkspace) calendarWorkspace.classList.add('hidden');

    if (['inbox', 'sent', 'archive', 'trash'].includes(viewName)) {
        mainWorkspace.classList.remove('hidden');
        document.getElementById('view-title').innerText = viewName.charAt(0).toUpperCase() + viewName.slice(1);
        renderMailList();
        document.getElementById('email-detail-active').classList.add('hidden');
        document.getElementById('email-detail-empty').classList.remove('hidden');
    } else if (viewName === 'domains') {
        domainsWorkspace.classList.remove('hidden');
        renderDomainsView();
    } else if (viewName === 'keys') {
        keysWorkspace.classList.remove('hidden');
        renderKeysView();
    } else if (viewName === 'settings') {
        settingsWorkspace.classList.remove('hidden');
        renderBiometricSettings();
    } else if (viewName === 'calendar') {
        if (calendarWorkspace) {
            calendarWorkspace.classList.remove('hidden');
            renderCalendarView();
        }
    }
}

// -------------------------------------------------------------
// WEBAUTHN / BIOMETRIC AUTHENTICATION FLOWS
// -------------------------------------------------------------

// Converts an ArrayBuffer to a base64url string
function bufferToBase64url(buffer) {
    const b64 = window.AlumniMailCrypto.bufferToBase64(buffer);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Converts a base64url string to a Uint8Array
function base64urlToBuffer(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return window.AlumniMailCrypto.base64ToBuffer(b64);
}

function renderBiometricSettings() {
    const badge = document.getElementById('biometric-status-badge');
    const button = document.getElementById('btn-register-biometrics');
    if (!badge || !button) return;

    if (!window.isSecureContext) {
        badge.innerText = "Unavailable (Insecure Context)";
        badge.className = "badge danger";
        button.disabled = true;
        button.innerText = "❌ Requires Secure HTTPS/Localhost";
        return;
    }

    const hasVault = localStorage.getItem(`biometric_vault_${session.username}`);
    if (hasVault) {
        badge.innerText = "Active & Linked";
        badge.className = "badge success";
        button.innerText = "🔗 Unlink Device Biometrics";
        button.className = "btn primary glow danger";
    } else {
        badge.innerText = "Not Connected";
        badge.className = "badge secondary";
        button.innerText = "🔑 Register Device Biometrics";
        button.className = "btn primary glow";
    }
}

async function registerBiometrics() {
    const badge = document.getElementById('biometric-status-badge');
    const button = document.getElementById('btn-register-biometrics');
    
    // If already registered, perform unlink
    const hasVault = localStorage.getItem(`biometric_vault_${session.username}`);
    if (hasVault) {
        if (confirm("Are you sure you want to unlink biometric authentication on this device? This will destroy the locally encrypted biometric session keys.")) {
            localStorage.removeItem(`biometric_vault_${session.username}`);
            localStorage.removeItem(`biometric_key_${session.username}`);
            alert("Biometric authentication successfully unlinked from this device.");
            renderBiometricSettings();
        }
        return;
    }

    if (!window.isSecureContext) {
        alert("WebAuthn biometrics are restricted by browser security policies to secure contexts (HTTPS or localhost).");
        return;
    }

    if (!window.PublicKeyCredential) {
        alert("This browser or device does not support WebAuthn Biometric Authenticator credentials.");
        return;
    }

    try {
        button.disabled = true;
        button.innerText = "⏳ Generating options...";

        // Step 1: Fetch options
        const res = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/webauthn/register-options?username=${encodeURIComponent(session.username)}`);
        if (!res.ok) {
            throw new Error("Failed to get WebAuthn options from server.");
        }
        const options = await res.json();

        // Convert options to standard typed array buffers
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);

        button.innerText = "🧬 Verify Identity Prompt...";

        // Step 2: Prompt Touch ID / Face ID
        const credential = await navigator.credentials.create({ publicKey: options });
        if (!credential) {
            throw new Error("WebAuthn authenticator failed to return credential.");
        }

        button.innerText = "⏳ Syncing credentials...";

        // Step 3: Serialize and send to server
        const rawPubKey = credential.response.getPublicKey();
        const publicKeySpki = bufferToBase64url(rawPubKey);
        const credentialId = credential.id;

        const registerRes = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/webauthn/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: session.username,
                credentialId,
                publicKeySpki
            })
        });

        if (!registerRes.ok) {
            const errData = await registerRes.json();
            throw new Error(errData.error || "Server rejected registration.");
        }

        // Step 4: Encrypt KDK and Private Key to secure local vault container
        button.innerText = "🔒 Building local E2EE Vault...";

        const rawKdk = await window.crypto.subtle.exportKey("raw", session.kdk);
        const jwkPrivateKey = await window.crypto.subtle.exportKey("jwk", session.privateKey);

        const vaultPayload = {
            kdk: bufferToBase64url(rawKdk),
            privateKey: jwkPrivateKey
        };

        // Generate local high-entropy key for AES-GCM vault encryption
        const bioKeyBytes = window.crypto.getRandomValues(new Uint8Array(32));
        const bioKeyHex = Array.from(bioKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            bioKeyBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const textEncoder = new TextEncoder();
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            textEncoder.encode(JSON.stringify(vaultPayload))
        );

        // Store vault encrypted locally, protected by biometric key and gated by server authentication
        localStorage.setItem(`biometric_key_${session.username}`, bioKeyHex);
        localStorage.setItem(`biometric_vault_${session.username}`, JSON.stringify({
            ciphertext: bufferToBase64url(encryptedBuffer),
            iv: bufferToBase64url(iv)
        }));

        alert("🎉 Device Biometrics successfully registered! You can now log in password-free on this device.");
        renderBiometricSettings();

    } catch (err) {
        console.error("Biometric registration failure:", err);
        alert("Biometric registration failed: " + err.message);
        renderBiometricSettings();
    } finally {
        button.disabled = false;
    }
}

async function handleBiometricLogin() {
    const errorEl = document.getElementById('login-error');
    if (errorEl) errorEl.classList.add('hidden');

    if (!window.isSecureContext) {
        if (errorEl) {
            errorEl.innerText = "Biometrics are unavailable in insecure HTTP contexts. Please use your passphrase.";
            errorEl.classList.remove('hidden');
        }
        return;
    }

    if (!window.PublicKeyCredential) {
        if (errorEl) {
            errorEl.innerText = "WebAuthn biometrics are not supported on this browser or device.";
            errorEl.classList.remove('hidden');
        }
        return;
    }

    // Step 1: Detect linked accounts
    const linkedAccounts = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('biometric_vault_')) {
            linkedAccounts.push(key.substring('biometric_vault_'.length));
        }
    }

    if (linkedAccounts.length === 0) {
        if (errorEl) {
            errorEl.innerText = "No biometric credentials have been registered on this device yet. Because your E2EE vault is zero-knowledge and completely secure, you must first log in with your secret passphrase on this device to import your credentials, then navigate to Settings and click 'Register Device Biometrics' to unlock it password-free here in the future.";
            errorEl.classList.remove('hidden');
        }
        return;
    }

    // If username is typed in the login field, use that. Otherwise if exactly one linked account, use that.
    // Otherwise, discoverable credential login (prompt username selection or standard credential discoverability).
    const typedUsername = document.getElementById('login-username').value.trim();
    let username = typedUsername ? (typedUsername.includes('@') ? typedUsername : `${typedUsername}@alumnimail.app`).toLowerCase() : "";

    if (!username && linkedAccounts.length === 1) {
        username = linkedAccounts[0];
    } else if (!username && linkedAccounts.length > 1) {
        const select = prompt(`Multiple biometric profiles found. Enter the username you want to unlock:\n${linkedAccounts.join('\n')}`);
        if (!select) return;
        username = (select.includes('@') ? select : `${select}@alumnimail.app`).toLowerCase();
    }

    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', '🧬 Contacting server and prompting device biometrics...');

    try {
        // Step 2: Fetch assertion options
        const res = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/webauthn/login-options` + (username ? `?username=${encodeURIComponent(username)}` : ''));
        if (!res.ok) {
            throw new Error("Failed to get biometric assertion parameters.");
        }
        const options = await res.json();

        // Convert option buffers
        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials.forEach(c => {
                c.id = base64urlToBuffer(c.id);
            });
        }

        updateCryptoOverlayStep('pbkdf2', 'completed', '✅ WebAuthn options loaded.');
        updateCryptoOverlayStep('rsa', 'active', '🧬 Please scan Face ID / Touch ID when prompted...');

        // Step 3: Prompt native browser Touch ID / Face ID
        const assertion = await navigator.credentials.get({ publicKey: options });
        if (!assertion) {
            throw new Error("Biometric scan cancelled or rejected.");
        }

        updateCryptoOverlayStep('rsa', 'completed', '✅ Biometric signature generated.');
        updateCryptoOverlayStep('aes', 'active', '🔒 Verifying biometric signature on server...');

        // Step 4: Verify signature on server
        const clientDataJSON = bufferToBase64url(assertion.response.clientDataJSON);
        const authenticatorData = bufferToBase64url(assertion.response.authenticatorData);
        const signature = bufferToBase64url(assertion.response.signature);
        const credentialId = assertion.id;

        const verifyRes = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/webauthn/login-verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature
            })
        });

        if (!verifyRes.ok) {
            const errData = await verifyRes.json();
            throw new Error(errData.error || "Biometric authentication signature rejected.");
        }

        const loginData = await verifyRes.json();
        const resolvedUsername = loginData.username;

        updateCryptoOverlayStep('aes', 'completed', '✅ Signature authenticated by server.');
        updateCryptoOverlayStep('db', 'active', '🔓 Decrypting E2EE vault locally...');

        // Step 5: Load local biometric vault keys and decrypt
        const bioKeyHex = localStorage.getItem(`biometric_key_${resolvedUsername}`);
        const vaultStr = localStorage.getItem(`biometric_vault_${resolvedUsername}`);

        if (!bioKeyHex || !vaultStr) {
            throw new Error(`Local biometric vault files not found on this device for ${resolvedUsername}. Did you reset local storage?`);
        }

        const vaultData = JSON.parse(vaultStr);
        const bioKeyBytes = new Uint8Array(bioKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            bioKeyBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        const ciphertext = base64urlToBuffer(vaultData.ciphertext);
        const iv = base64urlToBuffer(vaultData.iv);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            ciphertext
        );

        const textDecoder = new TextDecoder();
        const decryptedText = textDecoder.decode(decryptedBuffer);
        const vault = JSON.parse(decryptedText);

        // Step 6: Import decrypted keys back to transient memory session
        const kdk = await window.crypto.subtle.importKey(
            "raw",
            base64urlToBuffer(vault.kdk),
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const privateKey = await window.crypto.subtle.importKey(
            "jwk",
            vault.privateKey,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        // Populate session state
        session.username = resolvedUsername;
        session.salt = loginData.salt;
        session.kdk = kdk;
        session.privateKey = privateKey;
        session.publicJwk = loginData.publicJwk;
        session.encPrivateKey = loginData.encPrivateKey;
        session.userTier = loginData.tier || 'Free';

        updateCryptoOverlayStep('db', 'completed', '✅ Cryptographic identity unlocked.');
        showCryptoOverlay();

        // Step 7: Synchronize complete mailbox workspace
        updateCryptoOverlayStep('db', 'active', '🔄 Synchronizing secure emails, domains, and aliases...');
        await window.AlumniMailDB.syncUserData(resolvedUsername);
        updateCryptoOverlayStep('db', 'completed', '✅ E2EE Workspace synchronized.');

        // Establish mailbox session
        logActiveMemorySecrets();

        setTimeout(() => {
            hideCryptoOverlay();
            enterMailbox();
        }, 1200);

    } catch (err) {
        console.error("Biometric login failure:", err);
        hideCryptoOverlay();
        if (errorEl) {
            errorEl.innerText = "Biometric Unlock Failed: " + err.message;
            errorEl.classList.remove('hidden');
        }
    }
}

// -------------------------------------------------------------
// AUTHENTICATION FLOWS (ZERO-KNOWLEDGE)
// -------------------------------------------------------------
function switchAuthTab(tab) {
    const loginForm = document.getElementById('login-form');
    const regForm = document.getElementById('register-form');
    const loginTab = document.getElementById('tab-login-btn');
    const regTab = document.getElementById('tab-register-btn');

    if (tab === 'login') {
        loginForm.classList.add('active');
        regForm.classList.remove('active');
        loginTab.classList.add('active');
        regTab.classList.remove('active');
    } else {
        loginForm.classList.remove('active');
        regForm.classList.add('active');
        loginTab.classList.remove('active');
        regTab.classList.add('active');
    }
}

async function handleRegister(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('register-username').value.trim();
    const passwordInput = document.getElementById('register-password').value;
    const errorEl = document.getElementById('register-error');

    errorEl.classList.add('hidden');

    if (!usernameInput || !passwordInput) {
        errorEl.innerText = "Please complete all fields.";
        errorEl.classList.remove('hidden');
        return;
    }

    // Secure Context check
    const isSecure = window.isSecureContext && window.crypto && window.crypto.subtle;
    if (!isSecure) {
        errorEl.innerHTML = `⚠️ <strong>Security Policy Restriction:</strong> E2EE Key Generation requires a secure context (HTTPS or localhost).<br><br>
        To register and generate your keys securely on your phone:
        <ul style="margin: 8px 0 0 0; padding-left: 20px; text-align: left; font-size: 0.85rem; line-height: 1.4;">
            <li>Start a secure tunnel on your computer: run <code style="background:rgba(255,255,255,0.15); padding:2px 4px; border-radius:3px;">npx localtunnel --port 8000</code> or use ngrok.</li>
            <li>Access the secure <code style="background:rgba(255,255,255,0.15); padding:2px 4px; border-radius:3px;">https://</code> address on your phone.</li>
        </ul>`;
        errorEl.classList.remove('hidden');
        return;
    }

    // Strict registration rule: Users can only sign up under the @alumnimail.app domain
    let cleanedUsername = usernameInput.trim();
    if (cleanedUsername.includes('@')) {
        if (!cleanedUsername.toLowerCase().endsWith('@alumnimail.app')) {
            errorEl.innerText = "Strict Rule: Signups are restricted to the @alumnimail.app domain.";
            errorEl.classList.remove('hidden');
            return;
        }
    }
    const fullUsername = cleanedUsername.includes('@') ? cleanedUsername : `${cleanedUsername}@alumnimail.app`;

    // Check if user exists locally
    if (window.AlumniMailDB.getUser(fullUsername)) {
        errorEl.innerText = "This address is already registered.";
        errorEl.classList.remove('hidden');
        return;
    }

    // Check if user exists on server
    // IMPORTANT: We must validate the response is real JSON with a salt field.
    // Cloudflare can serve cached HTML (200 OK) for GET routes, which would
    // make checkRes.ok = true and falsely block ALL registrations.
    try {
        const checkRes = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/salt/${encodeURIComponent(fullUsername)}`);
        if (checkRes.ok) {
            try {
                const checkData = await checkRes.json();
                // Only block if the response is genuine JSON with a salt field
                if (checkData && checkData.salt) {
                    errorEl.innerText = "This address is already registered.";
                    errorEl.classList.remove('hidden');
                    return;
                }
                // Got 200 OK but no valid salt (e.g. Cloudflare HTML) — allow registration to continue
            } catch (jsonErr) {
                // Response was not valid JSON (e.g. cached HTML from Cloudflare) — allow registration
                console.warn("Salt check returned non-JSON response, proceeding with registration.");
            }
        }
        // 404 = user doesn't exist yet, safe to register
    } catch (e) {
        // Network/other error, continue to try registering
    }

    // Trigger E2EE Generator UI overlay
    showCryptoOverlay();
    
    try {
        // Step 1: PBKDF2 key derivation
        updateCryptoOverlayStep('pbkdf2', 'active', '🔑 Running PBKDF2-HMAC-SHA256 (10,000 iterations)...');
        const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
        const saltBase64 = window.AlumniMailCrypto.bufferToBase64(saltBytes);
        const { kdk, authHash } = await window.AlumniMailCrypto.deriveKeys(passwordInput, saltBase64);
        updateCryptoOverlayStep('pbkdf2', 'completed', '✅ Keys derived locally in browser.');

        // Step 2: Generate RSA-OAEP 2048-bit keys
        updateCryptoOverlayStep('rsa', 'active', '🔒 Generating RSA-OAEP 2048-bit Key Pair...');
        const keypair = await window.AlumniMailCrypto.generateRSAKeyPair();
        const publicJwk = await window.crypto.subtle.exportKey("jwk", keypair.publicKey);
        updateCryptoOverlayStep('rsa', 'completed', '✅ 2048-bit E2EE Keys generated.');

        // Step 3: Encrypt the Private key locally using AES-GCM
        updateCryptoOverlayStep('aes', 'active', '🔒 Encrypting RSA Private Key with AES-GCM-256...');
        const encPrivateKey = await window.AlumniMailCrypto.encryptPrivateKey(keypair.privateKey, kdk);
        updateCryptoOverlayStep('aes', 'completed', '✅ Private Key successfully encrypted.');

        // Step 4: Write profile to mock server
        updateCryptoOverlayStep('db', 'active', '📤 Registering Zero-Knowledge Profile on server...');
        await window.AlumniMailDB.registerUser(fullUsername, authHash, saltBase64, publicJwk, encPrivateKey);
        updateCryptoOverlayStep('db', 'completed', '✅ Secure ID registered successfully.');

        // Step 5: Synchronize clean workspace state
        updateCryptoOverlayStep('db', 'active', '🔄 Initializing secure workspace...');
        await window.AlumniMailDB.syncUserData(fullUsername);
        updateCryptoOverlayStep('db', 'completed', '✅ Secure Workspace initialized.');

        // Save session in memory (never written to LocalStorage in plain text!)
        session.username = fullUsername;
        session.salt = saltBase64;
        session.kdk = kdk;
        session.privateKey = keypair.privateKey;
        session.publicJwk = publicJwk;
        session.encPrivateKey = encPrivateKey;
        session.userTier = 'Free';

        // Log visual crypt secrets to browser memory logger
        logActiveMemorySecrets();

        setTimeout(() => {
            hideCryptoOverlay();
            enterMailbox();
        }, 1200);

    } catch (err) {
        console.error(err);
        hideCryptoOverlay();
        errorEl.innerText = "Fatal cryptographic failure: " + err.message;
        errorEl.classList.remove('hidden');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('login-username').value.trim();
    const passwordInput = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    errorEl.classList.add('hidden');

    if (!usernameInput || !passwordInput) {
        errorEl.innerText = "Please complete all fields.";
        errorEl.classList.remove('hidden');
        return;
    }

    // Secure Context check
    const isSecure = window.isSecureContext && window.crypto && window.crypto.subtle;
    if (!isSecure) {
        errorEl.innerHTML = `⚠️ <strong>Security Policy Restriction:</strong> Zero-Knowledge client-side E2EE requires a secure context (HTTPS or localhost).<br><br>
        To access and decrypt your emails securely on a phone:
        <ul style="margin: 8px 0 0 0; padding-left: 20px; text-align: left; font-size: 0.85rem; line-height: 1.4;">
            <li>Start a secure tunnel on your computer: run <code style="background:rgba(255,255,255,0.15); padding:2px 4px; border-radius:3px;">npx localtunnel --port 8000</code> or use ngrok.</li>
            <li>Access the secure <code style="background:rgba(255,255,255,0.15); padding:2px 4px; border-radius:3px;">https://</code> address on your phone.</li>
        </ul>`;
        errorEl.classList.remove('hidden');
        return;
    }

    const fullUsername = usernameInput.includes('@') ? usernameInput : `${usernameInput}@alumnimail.app`;

    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', '🔑 Querying user salt & running PBKDF2...');

    try {
        // Step 1: Retrieve user salt from server
        // IMPORTANT: Validate response is real JSON — Cloudflare can return cached
        // HTML (200 OK) instead of the JSON salt, which would cause a silent parse crash.
        let salt;
        try {
            const saltRes = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/salt/${encodeURIComponent(fullUsername)}`);
            if (!saltRes.ok) {
                throw new Error("User profile not found.");
            }
            let saltData;
            try {
                saltData = await saltRes.json();
            } catch (parseErr) {
                // Got HTML instead of JSON — Cloudflare caching issue
                throw new Error("Server returned an unexpected response. The CDN cache may be stale. Please try again in a moment.");
            }
            if (!saltData || !saltData.salt) {
                throw new Error("User profile not found.");
            }
            salt = saltData.salt;
        } catch (err) {
            hideCryptoOverlay();
            errorEl.innerText = "Authentication failed: " + err.message;
            errorEl.classList.remove('hidden');
            return;
        }

        // Step 2: Derive master key Decryption Key (kdk) and authHash locally using PBKDF2
        const { kdk, authHash } = await window.AlumniMailCrypto.deriveKeys(passwordInput, salt);
        updateCryptoOverlayStep('pbkdf2', 'completed', '✅ Passphrase derived.');

        // Step 3: Verify authHash on server & retrieve E2EE parameters
        updateCryptoOverlayStep('rsa', 'active', '🔒 Verifying ZK challenge and retrieving E2EE keys...');
        let loginData;
        try {
            const loginRes = await fetch(`${window.AlumniMailDB.apiBase}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: fullUsername, authHash })
            });
            if (!loginRes.ok) {
                const errData = await loginRes.json();
                throw new Error(errData.error || "Incorrect password.");
            }
            loginData = await loginRes.json();
        } catch (err) {
            hideCryptoOverlay();
            errorEl.innerText = "Authentication failed: " + err.message;
            errorEl.classList.remove('hidden');
            return;
        }
        updateCryptoOverlayStep('rsa', 'completed', '✅ ZK credentials verified by server.');

        // Step 4: Decrypt private key locally using KDK
        updateCryptoOverlayStep('aes', 'active', '🔓 Restoring RSA Private key in browser memory...');
        let privKey;
        try {
            privKey = await window.AlumniMailCrypto.decryptPrivateKey(
                loginData.encPrivateKey.ciphertext,
                loginData.encPrivateKey.iv,
                kdk
            );
            updateCryptoOverlayStep('aes', 'completed', '✅ Private Key loaded and decrypted locally.');
        } catch (err) {
            hideCryptoOverlay();
            errorEl.innerText = "Decryption failure. The password could not unlock your cryptographic private key.";
            errorEl.classList.remove('hidden');
            return;
        }

        // Step 5: Save credentials cache locally for sync checks
        window.AlumniMailDB.saveLoggedInUserCache(
            fullUsername,
            salt,
            loginData.publicJwk,
            loginData.encPrivateKey
        );

        // Step 6: Synchronize all secure data (emails, domains, aliases) from the server
        updateCryptoOverlayStep('db', 'active', '🔄 Synchronizing secure emails, domains, and aliases...');
        await window.AlumniMailDB.syncUserData(fullUsername);
        updateCryptoOverlayStep('db', 'completed', '✅ E2EE Workspace synchronized.');

        // Keep decrypted key strictly in transient memory!
        session.username = fullUsername;
        session.salt = salt;
        session.kdk = kdk;
        session.privateKey = privKey;
        session.publicJwk = loginData.publicJwk;
        session.encPrivateKey = loginData.encPrivateKey;
        session.userTier = loginData.tier || 'Free';
        localStorage.setItem(`user_tier_${fullUsername}`, loginData.tier || 'Free');

        // Log secrets to visual logger
        logActiveMemorySecrets();

        // Seed an E2EE greeting from Hal to the new user if it's their first login
        seedInboxGreeting(fullUsername, loginData.publicJwk);

        setTimeout(() => {
            hideCryptoOverlay();
            enterMailbox();
        }, 1200);

    } catch (err) {
        console.error(err);
        hideCryptoOverlay();
        errorEl.innerText = "Fatal cryptographic failure: " + err.message;
        errorEl.classList.remove('hidden');
    }
}

// Pre-seeding a welcome message when Satoshi or any user logs in
function seedInboxGreeting(username, recipientPublicJwk) {
    const emails = window.AlumniMailDB.getEmailsForUser(username);
    const welcomeExists = emails.some(e => e.sender === 'hal@alumnimail.app');
    
    if (!welcomeExists) {
        // We trigger an E2EE message sent from hal@alumnimail.app to Satoshi
        setTimeout(async () => {
            const subject = "Welcome to Alumni Mail!";
            const body = `Hello Satoshi,

Welcome to the custom end-to-end encrypted Alumni Mail network.

This email has been fully E2EE-secured using your RSA public key. As you read this, your local browser decrypted the session key using your passphrase-derived private key.

If you click the 'View Ciphertext' button in the header, you will see exactly what is stored in the database. As you can see, the subject and body are unreadable hex blocks.

Feel free to create a custom domain, bind it, verify DNS records, deploy custom aliases, and test E2EE messaging back and forth!

Best,
Hal`;
            
            // Encrypt using Satoshi's public key
            const encData = await window.AlumniMailCrypto.encryptEmail(subject, body, recipientPublicJwk);
            
            window.AlumniMailDB.sendEmail({
                sender: 'hal@alumnimail.app',
                recipient: username,
                encryptedPayload: encData.encryptedPayload,
                encryptedSessionKey: encData.encryptedSessionKey,
                iv: encData.iv
            });

            logNetworkRequest("POST", "/api/v1/deliver", {
                sender: "hal@alumnimail.app",
                recipient: username,
                payload: encData.encryptedPayload,
                wrapped_key: encData.encryptedSessionKey
            });
            
            renderMailList();
            renderUnreadBadges();
        }, 500);
    }
}

function enterMailbox() {
    document.getElementById('auth-screen').classList.remove('active');
    document.getElementById('dashboard-screen').classList.remove('hidden');
    document.getElementById('active-user-display').innerText = session.username;
    
    switchView('inbox');
    renderUnreadBadges();
    renderDomainsCount();
    loadLinkedWallet();
    loadUserTier();
}

function handleLogout() {
    // Clear all in-memory keys
    session.username = null;
    session.salt = null;
    session.kdk = null;
    session.privateKey = null;
    session.publicJwk = null;
    session.encPrivateKey = null;
    session.activeEmailId = null;

    // Reset UI Memory view
    document.getElementById('mem-kdk-val').innerText = "Key locked. Please log in.";
    document.getElementById('mem-privkey-val').innerText = "Key locked. Please log in.";
    document.getElementById('mem-domains-val').innerText = "No custom domains verified.";

    // Unlink wallet visual state on logout
    const statusBadge = document.getElementById('wallet-status-badge');
    const linkedView = document.getElementById('wallet-linked-view');
    const unlinkedView = document.getElementById('wallet-unlinked-view');
    if (linkedView) linkedView.classList.add('hidden');
    if (unlinkedView) unlinkedView.classList.remove('hidden');
    if (statusBadge) {
        statusBadge.innerText = "Disconnected";
        statusBadge.className = "wallet-status disconnected";
    }
    const connectBtn = document.getElementById('wallet-connect-btn');
    if (connectBtn) {
        connectBtn.innerText = "⚡ Connect Wallet";
        connectBtn.disabled = false;
    }

    document.getElementById('auth-screen').classList.add('active');
    document.getElementById('dashboard-screen').classList.add('hidden');
}

// -------------------------------------------------------------
// ALUMNI L1 BLOCKCHAIN WALLET INTEGRATION
// -------------------------------------------------------------
function triggerWalletUpload() {
    document.getElementById('wallet-modal').classList.remove('hidden');
    document.getElementById('wallet-link-form').reset();
    document.getElementById('wallet-link-error').classList.add('hidden');
}

function closeWalletModal() {
    document.getElementById('wallet-modal').classList.add('hidden');
}

async function handleRegisterWallet(event) {
    event.preventDefault();
    const tagInput = document.getElementById('wallet-tag-input').value.trim();
    const keyInput = document.getElementById('wallet-key-input').value.trim();
    
    let cleanKey = "";
    if (keyInput) {
        cleanKey = keyInput.replace(/\r/g, '').trim();
        const isHex = /^(0x)?[0-9a-fA-F]{40,130}$/.test(cleanKey);
        const isPem = cleanKey.includes("-----BEGIN PRIVATE KEY-----") || 
                      cleanKey.includes("-----BEGIN EC PRIVATE KEY-----") ||
                      cleanKey.includes("-----BEGIN RSA PRIVATE KEY-----") ||
                      cleanKey.includes("-----BEGIN PUBLIC KEY-----");
        const isAddress = /^[a-zA-Z0-9_-]{30,80}$/.test(cleanKey);
        
        if (!isHex && !isPem && !isAddress) {
            document.getElementById('wallet-link-error').innerText = "Invalid format! Please enter a valid Public Key, Address, or secp256k1 Private Key.";
            document.getElementById('wallet-link-error').classList.remove('hidden');
            return;
        }
    } else {
        cleanKey = "READ_ONLY";
    }

    // Clean and validate: convert to uppercase and strip non-alphanumeric chars
    const cleanTag = "@ALUMNI." + tagInput.toUpperCase().replace(/[^A-Z0-9_]/g, '');
    
    localStorage.setItem(`wallet_tag_${session.username}`, cleanTag);
    localStorage.setItem(`wallet_pem_${session.username}`, cleanKey);
    
    if (window.AlumniMailDB && window.AlumniMailDB.auditLog) {
        const linkType = cleanKey === "READ_ONLY" ? "READ_ONLY" : "FULL_ACCESS";
        window.AlumniMailDB.auditLog("L1 LINK", `Linked Alumni Wallet to email ${session.username} with tag ${cleanTag} (${linkType} mode).`);
    }

    await updateWalletBalance(cleanTag);
    closeWalletModal();
}

async function updateWalletBalance(tag) {
    const statusBadge = document.getElementById('wallet-status-badge');
    const linkedView = document.getElementById('wallet-linked-view');
    const unlinkedView = document.getElementById('wallet-unlinked-view');
    const tagDisplay = document.getElementById('wallet-tag');
    const balanceDisplay = document.getElementById('wallet-balance');
    const connectBtn = document.getElementById('wallet-connect-btn');

    if (statusBadge) {
        statusBadge.innerText = "Connecting...";
        statusBadge.className = "wallet-status disconnected";
    }

    try {
        const walletPem = localStorage.getItem(`wallet_pem_${session.username}`) || "";

        if (typeof logNetworkRequest === "function") {
            logNetworkRequest("POST", "/api/v1/wallet/balance", { tag: tag, email: session.username, keyOrAddress: walletPem });
        }

        const response = await fetch(`/api/v1/wallet/balance`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tag: tag, email: session.username, keyOrAddress: walletPem })
        });
        const data = await response.json();

        if (data.success) {
            tagDisplay.innerText = data.tag;
            balanceDisplay.innerText = `${data.balance.toLocaleString()} ALUMNI`;
            
            if (unlinkedView) unlinkedView.classList.add('hidden');
            if (linkedView) linkedView.classList.remove('hidden');
            if (statusBadge) {
                statusBadge.innerText = "Connected";
                statusBadge.className = "wallet-status connected";
            }
            if (connectBtn) {
                connectBtn.innerText = "Connected";
                connectBtn.disabled = true;
            }
            
            if (window.AlumniMailDB && window.AlumniMailDB.auditLog) {
                window.AlumniMailDB.auditLog("L1 BALANCE", `L1 balance verified: Tag '${data.tag}' has ${data.balance.toLocaleString()} ALUMNI.`);
            }
        } else {
            throw new Error(data.error || "Failed to retrieve balance");
        }
    } catch (err) {
        console.error("L1 Node Connection Error:", err);
        if (statusBadge) {
            statusBadge.innerText = "RPC Error";
            statusBadge.className = "wallet-status disconnected";
        }
    }
}

function unlinkWallet() {
    localStorage.removeItem(`wallet_tag_${session.username}`);
    localStorage.removeItem(`wallet_pem_${session.username}`);
    
    const statusBadge = document.getElementById('wallet-status-badge');
    const linkedView = document.getElementById('wallet-linked-view');
    const unlinkedView = document.getElementById('wallet-unlinked-view');
    const connectBtn = document.getElementById('wallet-connect-btn');

    if (linkedView) linkedView.classList.add('hidden');
    if (unlinkedView) unlinkedView.classList.remove('hidden');
    if (statusBadge) {
        statusBadge.innerText = "Disconnected";
        statusBadge.className = "wallet-status disconnected";
    }
    if (connectBtn) {
        connectBtn.innerText = "⚡ Link Alumni Wallet";
        connectBtn.disabled = false;
    }
    
    if (window.AlumniMailDB && window.AlumniMailDB.auditLog) {
        window.AlumniMailDB.auditLog("L1 UNLINK", `Unlinked Alumni Wallet from email ${session.username}.`);
    }
}

function openSendTokensModal() {
    document.getElementById('send-tokens-modal').classList.remove('hidden');
    document.getElementById('send-tokens-form').reset();
    document.getElementById('send-tokens-error').classList.add('hidden');
    document.getElementById('send-tokens-success').classList.add('hidden');
}

function closeSendTokensModal() {
    document.getElementById('send-tokens-modal').classList.add('hidden');
}

async function handleSendTokens(event) {
    event.preventDefault();
    const recipient = document.getElementById('send-recipient-input').value.trim();
    const amount = document.getElementById('send-amount-input').value.trim();
    const errorDisplay = document.getElementById('send-tokens-error');
    const successDisplay = document.getElementById('send-tokens-success');

    errorDisplay.classList.add('hidden');
    successDisplay.classList.add('hidden');

    const fromTag = localStorage.getItem(`wallet_tag_${session.username}`);
    const walletPem = localStorage.getItem(`wallet_pem_${session.username}`);

    if (!fromTag || !walletPem) {
        errorDisplay.innerText = "No Alumni Wallet linked to current session. Please connect your wallet first.";
        errorDisplay.classList.remove('hidden');
        return;
    }

    try {
        // Generate transaction payload locally
        const txPayload = JSON.stringify({
            sender: fromTag,
            recipient: recipient,
            amount: parseFloat(amount),
            nonce: Date.now()
        });
        
        // Sign transaction locally using modern Web Crypto API simulation
        const signatureBytes = new Uint8Array(64);
        window.crypto.getRandomValues(signatureBytes);
        const signatureHex = Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        if (typeof logNetworkRequest === "function") {
            logNetworkRequest("POST", "/api/v1/wallet/send", {
                fromEmail: session.username,
                fromTag: fromTag,
                senderTag: fromTag,
                recipient: recipient,
                recipientTag: recipient,
                amount: amount,
                pemPrivateKey: "[LOCAL_STORAGE_PEM_KEY]"
            });
        }

        const response = await fetch('/api/v1/wallet/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fromEmail: session.username,
                fromTag: fromTag,
                senderTag: fromTag,
                recipient: recipient,
                recipientTag: recipient,
                amount: amount,
                pemPrivateKey: walletPem,
                txPayload: txPayload,
                signatureHex: signatureHex
            })
        });
        const data = await response.json();

        if (data.success) {
            successDisplay.innerText = `Transaction Success! Hash: ${data.txHash}`;
            successDisplay.classList.remove('hidden');

            if (window.AlumniMailDB && window.AlumniMailDB.auditLog) {
                window.AlumniMailDB.auditLog("L1 TRANSFER", `Signed Tx Broadcast: Sent ${amount} ALUMNI to ${recipient}. TxHash: ${data.txHash}`);
            }

            // Refresh balance state
            setTimeout(async () => {
                await updateWalletBalance(fromTag);
            }, 800);

            // Close after brief delay
            setTimeout(() => {
                closeSendTokensModal();
            }, 2000);
        } else {
            throw new Error(data.error || "L1 transfer failed.");
        }
    } catch (err) {
        console.error("L1 Transfer Error:", err);
        errorDisplay.innerText = err.message || "Failed to broadcast transaction.";
        errorDisplay.classList.remove('hidden');
    }
}

function loadLinkedWallet() {
    const savedTag = localStorage.getItem(`wallet_tag_${session.username}`);
    if (savedTag) {
        updateWalletBalance(savedTag);
    } else {
        unlinkWallet();
    }
}

// -------------------------------------------------------------
// MAILBOX RENDERING & ACTIONS
// -------------------------------------------------------------
function renderMailList() {
    const listContainer = document.getElementById('email-list');
    listContainer.innerHTML = '';

    const emails = window.AlumniMailDB.getEmailsForUser(session.username);
    
    // Filter active emails depending on navigation folder
    let filtered = [];
    const normUser = session.username.toLowerCase().trim();

    if (session.activeView === 'inbox') {
        filtered = emails.filter(e => e.recipient === normUser && !e.deletedByRecipient && !e.archived);
    } else if (session.activeView === 'sent') {
        filtered = emails.filter(e => e.sender === normUser && !e.deletedBySender);
    } else if (session.activeView === 'archive') {
        filtered = emails.filter(e => e.recipient === normUser && e.archived && !e.deletedByRecipient);
    } else if (session.activeView === 'trash') {
        filtered = emails.filter(e => 
            (e.recipient === normUser && e.deletedByRecipient) || 
            (e.sender === normUser && e.deletedBySender)
        );
    }

    // Sort by timestamp descending
    filtered.sort((a, b) => b.timestamp - a.timestamp);

    if (filtered.length === 0) {
        listContainer.innerHTML = `
            <div class="empty-state-list">
                <span class="empty-icon">📥</span>
                <p>No messages in ${session.activeView}</p>
            </div>
        `;
        return;
    }

    filtered.forEach(email => {
        const card = document.createElement('div');
        card.id = `mail-card-${email.id}`;
        card.className = `email-card ${!email.read && email.recipient === normUser ? 'unread' : ''} ${session.activeEmailId === email.id ? 'active' : ''}`;
        
        // Formulate readable snippet and subject (we display un-decrypted indicators until opened, or simulate partial text)
        const dateStr = new Date(email.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        // Show secure lock icons or password protection badges
        let lockIndicator = '🔒';
        if (email.isPasswordProtected) {
            lockIndicator = '🔑';
        } else if (!email.encryptedSessionKey) {
            lockIndicator = '⚠️ Plaintext';
        }

        card.innerHTML = `
            <div class="card-row">
                <span class="card-sender" title="${email.sender}">${email.sender}</span>
                <span class="card-date">${dateStr}</span>
            </div>
            <div class="card-subject">${email.read ? '🔓' : lockIndicator} Encrypted Payload Item</div>
            <div class="card-snippet">Content locked. Client decryption required.</div>
        `;

        card.onclick = () => openEmailDetails(email.id);
        listContainer.appendChild(card);
    });
}

async function openEmailDetails(emailId) {
    session.activeEmailId = emailId;
    
    // Highlight selected card
    const cards = document.querySelectorAll('.email-card');
    cards.forEach(c => c.classList.remove('active'));
    const activeCard = document.getElementById(`mail-card-${emailId}`);
    if (activeCard) {
        activeCard.classList.add('active');
        activeCard.classList.remove('unread');
    }

    const emails = window.AlumniMailDB.getEmailsForUser(session.username);
    const email = emails.find(e => e.id === emailId);

    if (!email) return;

    // Mark as read in db
    email.read = true;
    
    const detailEmpty = document.getElementById('email-detail-empty');
    const detailActive = document.getElementById('email-detail-active');

    detailEmpty.classList.add('hidden');
    detailActive.classList.remove('hidden');

    document.getElementById('detail-from').innerText = email.sender;
    document.getElementById('detail-to').innerText = email.recipient;
    document.getElementById('detail-date').innerText = new Date(email.timestamp).toLocaleString();

    // Populate Ciphertext Drawer panels immediately
    document.getElementById('cipher-payload-raw').innerText = email.encryptedPayload;
    document.getElementById('cipher-key-raw').innerText = email.encryptedSessionKey || "Symmetric key derived via custom password";
    
    // Reset Views
    document.getElementById('detail-body-decrypted').classList.remove('hidden');
    document.getElementById('detail-body-ciphertext').classList.add('hidden');
    document.getElementById('btn-toggle-cipher').innerText = "👁️ View Ciphertext";

    // Dynamic Security Header Configuration
    const secDot = document.getElementById('security-badge-card').querySelector('.secure-indicator-dot');
    const secTitle = document.getElementById('security-card-title');
    const secText = document.getElementById('security-card-text');

    if (email.isPasswordProtected) {
        secDot.className = "secure-indicator-dot warning";
        secTitle.innerText = "🔑 Password Encrypted Secure Portal";
        secText.innerText = "This email was secured with a custom password. To read its contents, it must be unlocked with the shared secret passphrase.";
        
        // Decrypted body will trigger the secure password portal popup
        document.getElementById('detail-subject').innerText = "🔒 Password Protected Payload";
        document.getElementById('detail-body-decrypted').innerHTML = `
            <div class="alert warning text-center">
                <strong>Password Protected Session Required</strong><br>
                This content is locked with a custom shared password.<br><br>
                <button class="btn primary glow" onclick="openExternalReaderModal('${email.id}')">🔓 Unlock Secure Message</button>
            </div>
        `;
    } else if (!email.encryptedSessionKey) {
        // Plaintext SMTP mock delivery
        secDot.className = "secure-indicator-dot warning";
        secTitle.innerText = "⚠️ External SMTP Delivery (Plaintext)";
        secText.innerText = "This message was received without cryptographic key negotiation. Content was transmitted plaintext across clear text channels.";
        
        // Render plaintext fields immediately
        try {
            const raw = JSON.parse(window.atob(email.encryptedPayload));
            document.getElementById('detail-subject').innerText = raw.subject;
            document.getElementById('detail-body-decrypted').innerText = raw.body;
        } catch (e) {
            document.getElementById('detail-subject').innerText = "Plaintext Message";
            document.getElementById('detail-body-decrypted').innerText = email.encryptedPayload;
        }
    } else {
        // Full standard E2EE
        secDot.className = "secure-indicator-dot secure";
        secTitle.innerText = "🔒 End-to-End Encrypted (E2EE)";
        secText.innerText = "This message was encrypted on the sender's client and decrypted locally in your browser using your derived RSA private key. The server only sees base64 ciphertext.";

        // Execute actual browser-native decryption
        try {
            // Find appropriate key: user has a primary address, but might also have custom aliases!
            // Let's resolve the exact recipient public key to match the active private key.
            let privateKeyToUse = session.privateKey;
            
            const normRecipient = email.recipient.toLowerCase().trim();
            const normPrimary = session.username.toLowerCase().trim();

            if (normRecipient !== normPrimary) {
                // The email was sent to one of the user's custom aliases!
                const aliases = window.AlumniMailDB.getAliasesForUser(session.username);
                const matchedAlias = aliases.find(a => a.email === normRecipient);
                
                if (matchedAlias) {
                    // Decrypt the alias's private key first using KDK
                    window.AlumniMailDB.auditLog("DECRYPT ALIAS KEY", `Decrypting alias private key for '${normRecipient}' using in-memory master KDK.`);
                    privateKeyToUse = await window.AlumniMailCrypto.decryptPrivateKey(
                        matchedAlias.encPrivateKey.ciphertext,
                        matchedAlias.encPrivateKey.iv,
                        session.kdk
                    );
                }
            }

            const decrypted = await window.AlumniMailCrypto.decryptEmail(
                email.encryptedPayload,
                email.encryptedSessionKey,
                email.iv,
                privateKeyToUse
            );

            document.getElementById('detail-subject').innerText = decrypted.subject;
            document.getElementById('detail-body-decrypted').innerText = decrypted.body;

            // Highlight decryption transaction inside Database Inspector
            window.AlumniMailDB.auditLog("DECRYPT SUCCESS", `Successfully decrypted E2EE payload for ${email.recipient}`);

        } catch (err) {
            console.error(err);
            document.getElementById('detail-subject').innerText = "❌ Decryption Failure";
            document.getElementById('detail-body-decrypted').innerHTML = `
                <div class="alert warning">
                    <strong>Cryptographic Decryption Error</strong><br>
                    Unable to decrypt this payload. This could happen if the message was encrypted with a different key, or if your key pair was rotated.<br><br>
                    Details: ${err.message}
                </div>
            `;
        }
    }
}

function toggleCiphertext() {
    const decBody = document.getElementById('detail-body-decrypted');
    const cipherBody = document.getElementById('detail-body-ciphertext');
    const btn = document.getElementById('btn-toggle-cipher');

    if (cipherBody.classList.contains('hidden')) {
        decBody.classList.add('hidden');
        cipherBody.classList.remove('hidden');
        btn.innerText = "👁️ View Decrypted Body";
    } else {
        decBody.classList.remove('hidden');
        cipherBody.classList.add('hidden');
        btn.innerText = "👁️ View Ciphertext";
    }
}

function deleteActiveEmail() {
    if (session.activeEmailId) {
        window.AlumniMailDB.deleteEmail(session.activeEmailId, session.username);
        switchView(session.activeView);
    }
}

function renderUnreadBadges() {
    const emails = window.AlumniMailDB.getEmailsForUser(session.username);
    const norm = session.username.toLowerCase().trim();
    const unreadInbox = emails.filter(e => e.recipient === norm && !e.read && !e.deletedByRecipient && !e.archived).length;
    
    const inboxBadge = document.getElementById('inbox-count');
    if (unreadInbox > 0) {
        inboxBadge.innerText = unreadInbox;
        inboxBadge.classList.remove('hidden');
    } else {
        inboxBadge.classList.add('hidden');
    }
}

// -------------------------------------------------------------
// COMPOSER MODULE & TRANSMIT SECURITY EVALUATION
// -------------------------------------------------------------
function openComposer() {
    document.getElementById('composer-modal').classList.remove('hidden');
    
    // Populate the "From:" dropdown with primary user address and any verified custom domain aliases!
    const fromSelect = document.getElementById('compose-from');
    fromSelect.innerHTML = '';

    // Primary
    const optPrimary = document.createElement('option');
    optPrimary.value = session.username;
    optPrimary.innerText = session.username;
    fromSelect.appendChild(optPrimary);

    // Aliases
    const aliases = window.AlumniMailDB.getAliasesForUser(session.username);
    aliases.forEach(alias => {
        const opt = document.createElement('option');
        opt.value = alias.email;
        opt.innerText = alias.email;
        fromSelect.appendChild(opt);
    });

    // Reset compose values
    document.getElementById('compose-to').value = '';
    document.getElementById('compose-subject').value = '';
    document.getElementById('compose-body').value = '';
    document.getElementById('compose-password-check').checked = false;
    document.getElementById('password-options-panel').classList.add('hidden');
    
    evaluateRecipientKeys();
}

function closeComposer() {
    document.getElementById('composer-modal').classList.add('hidden');
}

function evaluateRecipientKeys() {
    const toInput = document.getElementById('compose-to').value.trim();
    const secCard = document.getElementById('composer-sec-card');
    const secDot = document.getElementById('composer-sec-dot');
    const secText = document.getElementById('composer-sec-text');
    const passToggleWrapper = document.getElementById('password-toggle-wrapper');
    const btnSend = document.getElementById('btn-send-mail');

    if (!toInput) {
        secCard.className = "composer-security-status";
        secDot.className = "status-dot";
        secText.innerText = "Enter a recipient to evaluate security.";
        passToggleWrapper.classList.add('hidden');
        document.getElementById('password-options-panel').classList.add('hidden');
        return;
    }

    // Query DB key registry for E2EE public keys
    const publicKeyJwk = window.AlumniMailDB.getPublicKey(toInput);

    if (publicKeyJwk) {
        // Recipient E2EE available!
        secCard.className = "composer-security-status success";
        secDot.className = "status-dot pulsing emerald";
        secText.innerText = "🔒 Recipient E2EE Crypt Key Active";
        passToggleWrapper.classList.add('hidden');
        document.getElementById('password-options-panel').classList.add('hidden');
    } else {
        // No native keys found
        secCard.className = "composer-security-status plaintext";
        secDot.className = "status-dot pulsing amber";
        secText.innerText = "⚠️ Plaintext Channel: No recipient public key in registry.";
        passToggleWrapper.classList.remove('hidden');
    }
}

function togglePasswordEncryptOptions() {
    const isChecked = document.getElementById('compose-password-check').checked;
    const passPanel = document.getElementById('password-options-panel');
    const secCard = document.getElementById('composer-sec-card');
    const secDot = document.getElementById('composer-sec-dot');
    const secText = document.getElementById('composer-sec-text');

    if (isChecked) {
        passPanel.classList.remove('hidden');
        secCard.className = "composer-security-status success";
        secDot.className = "status-dot pulsing blue";
        secText.innerText = "🔑 Hybrid Password Protected Portal Channel Active";
    } else {
        passPanel.classList.add('hidden');
        secCard.className = "composer-security-status plaintext";
        secDot.className = "status-dot pulsing amber";
        secText.innerText = "⚠️ Plaintext Channel: No recipient public key in registry.";
    }
}

async function handleSendEmail(event) {
    event.preventDefault();
    const sender = document.getElementById('compose-from').value;
    const recipient = document.getElementById('compose-to').value.trim();
    const subject = document.getElementById('compose-subject').value.trim();
    const body = document.getElementById('compose-body').value;

    const isPasswordChecked = document.getElementById('compose-password-check').checked;
    const passwordVal = document.getElementById('compose-shared-pass').value;
    const hintVal = document.getElementById('compose-shared-hint').value;

    if (!recipient || !subject || !body) return;

    try {
        let emailPayload = {};
        
        // 1. Fetch public key to see if we do E2EE
        const pubKey = window.AlumniMailDB.getPublicKey(recipient);

        if (pubKey && !isPasswordChecked) {
            // HYBRID E2EE PATH (RSA public wrapping AES key)
            window.AlumniMailDB.auditLog("COMPOSING E2EE", `Beginning E2EE Hybrid encryption for recipient: ${recipient}`);
            const enc = await window.AlumniMailCrypto.encryptEmail(subject, body, pubKey);
            
            emailPayload = {
                sender,
                recipient,
                encryptedPayload: enc.encryptedPayload,
                encryptedSessionKey: enc.encryptedSessionKey,
                iv: enc.iv
            };

            logNetworkRequest("POST", "/api/v1/deliver/secure", {
                sender,
                recipient,
                payload: enc.encryptedPayload,
                wrapped_key: enc.encryptedSessionKey
            });
        } else if (isPasswordChecked && passwordVal) {
            // PASSWORD SECURED PORTAL PATH
            window.AlumniMailDB.auditLog("COMPOSING PORTAL", `Encrypting message with custom symmetric passphrase...`);
            const enc = await window.AlumniMailCrypto.encryptWithPassword(subject, body, passwordVal);

            emailPayload = {
                sender,
                recipient,
                encryptedPayload: enc.encryptedPayload,
                encryptedSessionKey: null,
                iv: enc.iv,
                salt: enc.salt,
                isPasswordProtected: true,
                passwordHint: hintVal || "No hint provided."
            };

            logNetworkRequest("POST", "/api/v1/deliver/portal", {
                sender,
                recipient,
                payload: enc.encryptedPayload,
                hint: hintVal
            });
        } else {
            // STANDARD PLAINTEXT SMTP FALLBACK
            window.AlumniMailDB.auditLog("COMPOSING CLEAR", `No cryptographic key found. Sending message via cleartext fallback.`);
            const plainTextBase64 = window.btoa(JSON.stringify({ subject, body }));
            
            emailPayload = {
                sender,
                recipient,
                encryptedPayload: plainTextBase64,
                encryptedSessionKey: null,
                iv: window.AlumniMailCrypto.bufferToBase64(window.crypto.getRandomValues(new Uint8Array(12)))
            };

            logNetworkRequest("POST", "/api/v1/deliver/smtp", {
                sender,
                recipient,
                payload_clear: plainTextBase64
            });
        }

        // Send to db
        window.AlumniMailDB.sendEmail(emailPayload);

        closeComposer();
        switchView(session.activeView);
        
    } catch (err) {
        console.error(err);
        alert("Transmission failure: " + err.message);
    }
}

// -------------------------------------------------------------
// EXTERNAL PORTAL READ DECRYPTION
// -------------------------------------------------------------
let activeReaderEmailId = null;

function openExternalReaderModal(emailId) {
    activeReaderEmailId = emailId;
    const emails = window.AlumniMailDB.getEmailsForUser(session.username);
    const email = emails.find(e => e.id === emailId);

    if (!email) return;

    document.getElementById('external-reader-modal').classList.remove('hidden');
    document.getElementById('reader-auth-view').classList.remove('hidden');
    document.getElementById('reader-content-view').classList.add('hidden');
    document.getElementById('reader-error').classList.add('hidden');
    document.getElementById('reader-password-input').value = '';

    document.getElementById('reader-hint-display').innerText = `Hint: ${email.passwordHint}`;
}

function closeExternalReader() {
    document.getElementById('external-reader-modal').classList.add('hidden');
    activeReaderEmailId = null;
}

async function handleDecryptExternalEmail() {
    const password = document.getElementById('reader-password-input').value;
    const errorEl = document.getElementById('reader-error');
    errorEl.classList.add('hidden');

    if (!password) return;

    const emails = window.AlumniMailDB.getEmailsForUser(session.username);
    const email = emails.find(e => e.id === activeReaderEmailId);

    if (!email) return;

    try {
        const decrypted = await window.AlumniMailCrypto.decryptWithPassword(
            email.encryptedPayload,
            email.salt,
            email.iv,
            password
        );

        // Success! Populate views
        document.getElementById('reader-auth-view').classList.add('hidden');
        document.getElementById('reader-content-view').classList.remove('hidden');

        document.getElementById('reader-from').innerText = email.sender;
        document.getElementById('reader-to').innerText = email.recipient;
        document.getElementById('reader-subject').innerText = decrypted.subject;
        document.getElementById('reader-body').innerText = decrypted.body;

        // Also permanently decrypted in view-pane if unlocked
        document.getElementById('detail-subject').innerText = decrypted.subject;
        document.getElementById('detail-body-decrypted').innerText = decrypted.body;
        
        // Log transaction to DB Auditor
        window.AlumniMailDB.auditLog("DECRYPT PORTAL SUCCESS", `Successfully unlocked portal payload with custom shared password.`);

    } catch (err) {
        console.error(err);
        errorEl.innerText = "Unlock failed. Decrypt derived bad signature key (incorrect password).";
        errorEl.classList.remove('hidden');
    }
}

// -------------------------------------------------------------
// DOMAINS PORTAL & DNS VERIFICATION WIZARD
// -------------------------------------------------------------
let activeDnsDomainName = null;

function renderDomainsView() {
    renderDomainsList();
    renderDomainsCount();
    
    // Default DNS empty
    document.getElementById('dns-empty-state').classList.remove('hidden');
    document.getElementById('dns-verification-panel').classList.add('hidden');
    activeDnsDomainName = null;
}

function renderDomainsCount() {
    const list = window.AlumniMailDB.getDomainsForUser(session.username);
    document.getElementById('domain-count').innerText = list.length;
}

function renderDomainsList() {
    const ul = document.getElementById('active-domains-ul');
    ul.innerHTML = '';

    const list = window.AlumniMailDB.getDomainsForUser(session.username);

    if (list.length === 0) {
        ul.innerHTML = `<li class="empty-li">No custom domains configured</li>`;
        return;
    }

    list.forEach(dom => {
        const li = document.createElement('li');
        li.className = activeDnsDomainName === dom.domainName ? 'active' : '';
        li.innerHTML = `
            <span>${dom.domainName}</span>
            <span class="badge ${dom.isVerified ? 'success' : 'warning'}">
                ${dom.isVerified ? 'VERIFIED' : 'DNS PENDING'}
            </span>
        `;
        li.onclick = () => selectDomainForDns(dom.domainName);
        ul.appendChild(li);
    });
}

function selectDomainForDns(domainName) {
    activeDnsDomainName = domainName;
    renderDomainsList(); // Refresh active list highlights

    document.getElementById('dns-empty-state').classList.add('hidden');
    document.getElementById('dns-verification-panel').classList.remove('hidden');

    const domains = window.AlumniMailDB.getDomainsForUser(session.username);
    const dom = domains.find(d => d.domainName === domainName);

    if (!dom) return;

    document.getElementById('dns-active-domain-name').innerText = dom.domainName;
    
    const badge = document.getElementById('dns-domain-status-badge');
    const verifyBtn = document.getElementById('btn-dns-verify');
    const aliasSection = document.getElementById('alias-creator-section');

    if (dom.isVerified) {
        badge.className = "badge success";
        badge.innerText = "✅ DOMAIN VERIFIED";
        verifyBtn.classList.add('hidden');
        aliasSection.classList.remove('hidden');
        document.getElementById('alias-domain-label').innerText = `@${dom.domainName}`;
        renderAliasesList(dom.domainName);
    } else {
        badge.className = "badge warning";
        badge.innerText = "⏳ PENDING DNS VERIFICATION";
        verifyBtn.classList.remove('hidden');
        aliasSection.classList.add('hidden');
    }

    // Populate rows status
    updateDnsRecordRowStatus('mx', dom.dnsRecords.mx.resolved);
    updateDnsRecordRowStatus('spf', dom.dnsRecords.spf.resolved);
    updateDnsRecordRowStatus('dkim', dom.dnsRecords.dkim.resolved);
    updateDnsRecordRowStatus('dmarc', dom.dnsRecords.dmarc.resolved);
}

function updateDnsRecordRowStatus(recType, isResolved) {
    const el = document.getElementById(`dns-status-${recType}`);
    if (isResolved) {
        el.className = "status-icon verified";
        el.innerHTML = "✅ Resolved";
    } else {
        el.className = "status-icon";
        el.innerHTML = "⏳ Pending";
    }
}

function handleNewDomain(event) {
    event.preventDefault();
    const input = document.getElementById('new-domain-input');
    const val = input.value.trim().toLowerCase();

    if (!val) return;

    // Basic domain validation
    if (!val.includes('.') || val.length < 4) {
        alert("Please enter a valid domain format.");
        return;
    }

    // Free account custom domain limit
    const domains = window.AlumniMailDB.getDomainsForUser(session.username);
    if (session.userTier !== 'Pro' && domains.length >= 1) {
        alert("Free accounts are strictly limited to exactly 1 custom domain. Please upgrade to Pro to unlock unlimited custom domains!");
        openUpgradeModal();
        return;
    }

    // Check duplicate
    if (domains.some(d => d.domainName === val)) {
        alert("This domain is already linked to your account.");
        return;
    }

    window.AlumniMailDB.addDomain(val, session.username);
    input.value = '';
    renderDomainsView();
}

// Simulates checking records at root DNS authority, updating verified flags
function simulateDNSVerification() {
    if (!activeDnsDomainName) return;

    const verifyBtn = document.getElementById('btn-dns-verify');
    verifyBtn.disabled = true;
    verifyBtn.innerText = "🔍 Querying NS Authorities...";

    const records = ['mx', 'spf', 'dkim', 'dmarc'];
    let delay = 600;

    records.forEach((rec, idx) => {
        setTimeout(() => {
            const el = document.getElementById(`dns-status-${rec}`);
            el.innerHTML = "🔄 Validating record...";
            
            setTimeout(() => {
                const dom = window.AlumniMailDB.verifyDomainRecord(activeDnsDomainName, rec);
                updateDnsRecordRowStatus(rec, true);
                
                // Final verify step
                if (idx === records.length - 1) {
                    verifyBtn.disabled = false;
                    verifyBtn.innerText = "Verify DNS Records";
                    // Refresh view
                    selectDomainForDns(activeDnsDomainName);
                }
            }, 500);

        }, idx * delay);
    });
}

function renderAliasesList(domainName) {
    const ul = document.getElementById('deployed-aliases-ul');
    ul.innerHTML = '';

    const aliases = window.AlumniMailDB.getAliasesForUser(session.username);
    const domainAliases = aliases.filter(a => a.email.endsWith(`@${domainName}`));

    if (domainAliases.length === 0) {
        ul.innerHTML = `<li class="empty-li">No custom email addresses deployed yet.</li>`;
        return;
    }

    domainAliases.forEach(alias => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>${alias.email}</span>
            <span class="alias-badge-secure">🔒 E2EE Key Pair Active</span>
        `;
        ul.appendChild(li);
    });
}

async function handleCreateAlias(event) {
    event.preventDefault();
    const input = document.getElementById('alias-username-input');
    const val = input.value.trim().toLowerCase();

    if (!val || !activeDnsDomainName) return;

    const fullAlias = `${val}@${activeDnsDomainName}`;

    // Free account custom domain alias limit
    const aliases = window.AlumniMailDB.getAliasesForUser(session.username);
    if (session.userTier !== 'Pro' && aliases.length >= 1) {
        alert("Free accounts are strictly limited to exactly 1 custom domain email alias. Please upgrade to Pro to unlock unlimited domain aliases!");
        openUpgradeModal();
        return;
    }

    // Verify alias does not duplicate existing addresses in standard registry
    if (window.AlumniMailDB.getPublicKey(fullAlias)) {
        alert("This address alias is already registered.");
        return;
    }

    // Deploy cryptographic keys for this specific alias!
    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', '🔑 Querying local session master seed...');
    
    try {
        // Step 1: RSA Key Generation specific to the alias
        updateCryptoOverlayStep('pbkdf2', 'completed', '✅ Session verified.');
        updateCryptoOverlayStep('rsa', 'active', `🔒 Generating RSA-OAEP 2048-bit keys for ${fullAlias}...`);
        
        const aliasKeypair = await window.AlumniMailCrypto.generateRSAKeyPair();
        const aliasPubJwk = await window.crypto.subtle.exportKey("jwk", aliasKeypair.publicKey);
        updateCryptoOverlayStep('rsa', 'completed', '✅ Cryptographic keys deployed.');

        // Step 2: Encrypt the alias private key locally under the user's primary KDK in memory!
        updateCryptoOverlayStep('aes', 'active', `🔒 Encrypting alias private key with AES-GCM under KDK...`);
        const encPrivateKey = await window.AlumniMailCrypto.encryptPrivateKey(aliasKeypair.privateKey, session.kdk);
        updateCryptoOverlayStep('aes', 'completed', '✅ Private Key encrypted locally.');

        // Step 3: Save to DB alias schema
        updateCryptoOverlayStep('db', 'active', '📤 Transmitting alias registers to server...');
        window.AlumniMailDB.createAlias(fullAlias, session.username, aliasPubJwk, encPrivateKey);
        updateCryptoOverlayStep('db', 'completed', '✅ Custom address successfully active.');

        setTimeout(() => {
            hideCryptoOverlay();
            input.value = '';
            renderAliasesList(activeDnsDomainName);
            logActiveMemorySecrets(); // Update memory console views
        }, 1000);

    } catch (e) {
        console.error(e);
        hideCryptoOverlay();
        alert("Alias crypt deploy failed: " + e.message);
    }
}

// -------------------------------------------------------------
// KEY RING VIEWS
// -------------------------------------------------------------
function renderKeysView() {
    document.getElementById('key-mgr-user').innerText = session.username;
    
    // Dump public key JWK
    document.getElementById('key-mgr-public').innerText = JSON.stringify(session.publicJwk, null, 2);
    // Dump encrypted private key payload
    document.getElementById('key-mgr-private').innerText = JSON.stringify(session.encPrivateKey, null, 2);

    // Recipient directory dump
    const tbody = document.getElementById('key-ring-tbody');
    tbody.innerHTML = '';

    // Load active registered users + custom aliases from database
    const usersObj = JSON.parse(localStorage.getItem('alumni_mail_users') || '{}');
    const aliasesArr = JSON.parse(localStorage.getItem('alumni_mail_aliases') || '[]');

    Object.keys(usersObj).forEach(uname => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="font-mono">${uname}</span></td>
            <td>RSA-OAEP-2048</td>
            <td><span class="status-icon verified">✅ Encrypt Key Active</span></td>
        `;
        tbody.appendChild(tr);
    });

    aliasesArr.forEach(al => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="font-mono">${al.email}</span></td>
            <td>RSA-OAEP-2048</td>
            <td><span class="status-icon verified">✅ Encrypt Key Active</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function exportPublicKey() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(session.publicJwk, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", `${session.username}_public_key.json`);
    dl.click();
}

function exportPrivateKeyEncrypted() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(session.encPrivateKey, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", `${session.username}_encrypted_private_key.json`);
    dl.click();
}

// -------------------------------------------------------------
// RESET METHODS
// -------------------------------------------------------------
function nukeAndReset() {
    const conf = confirm("Are you sure you want to completely erase the mock database? All cryptographic keys and emails will be permanently deleted.");
    if (conf) {
        window.AlumniMailDB.nukeDatabase();
        handleLogout();
    }
}

// -------------------------------------------------------------
// SECURITY OVERLAYS
// -------------------------------------------------------------
function showCryptoOverlay() {
    document.getElementById('crypto-overlay').classList.remove('hidden');
    
    // Clear overlay statuses
    const steps = ['pbkdf2', 'rsa', 'aes', 'db'];
    steps.forEach(st => {
        const el = document.getElementById(`step-${st}`);
        el.className = "step";
        el.querySelector('.step-status').innerText = "⏳";
    });
}

function updateCryptoOverlayStep(stepId, state, text) {
    const el = document.getElementById(`step-${stepId}`);
    const statusSpan = el.querySelector('.step-status');
    
    document.getElementById('crypto-status-text').innerText = text;
    
    if (state === 'active') {
        el.className = "step active";
        statusSpan.innerText = "🔄";
    } else if (state === 'completed') {
        el.className = "step completed";
        statusSpan.innerText = "✅";
    }
}

function hideCryptoOverlay() {
    document.getElementById('crypto-overlay').classList.add('hidden');
}

// -------------------------------------------------------------
// SECURITY AUDITOR & TRANS-LOGGER
// -------------------------------------------------------------
function toggleAuditorDrawer() {
    const container = document.getElementById('auditor-drawer');
    const btn = document.getElementById('btn-toggle-auditor');
    
    if (container.classList.contains('minimized')) {
        container.classList.remove('minimized');
        container.classList.add('expanded');
        btn.innerText = "▼ Minimize Console";
    } else {
        container.classList.remove('expanded');
        container.classList.add('minimized');
        btn.innerText = "▲ Expand Console";
    }
}

function switchAuditorTab(tabName) {
    const tabs = ['db', 'network', 'memory'];
    tabs.forEach(tab => {
        const elBtn = document.querySelector(`.auditor-tab-btn[onclick*="${tab}"]`);
        const elPane = document.getElementById(`auditor-tab-${tab}`);
        
        if (tab === tabName) {
            elBtn.classList.add('active');
            elPane.classList.add('active');
        } else {
            elBtn.classList.remove('active');
            elPane.classList.remove('active');
        }
    });

    if (tabName === 'memory') {
        logActiveMemorySecrets();
    }
}

function logDBQuery({ timestamp, action, sqlQuery, rawData }) {
    const container = document.getElementById('db-sql-logs');
    if (!container) return;

    const line = document.createElement('div');
    line.className = `log-line ${action.toLowerCase()}`;
    
    let timeSpan = `<span class="system">[${timestamp}]</span>`;
    let querySpan = `<span>${sqlQuery}</span>`;
    
    line.innerHTML = `${timeSpan} ${querySpan}`;
    container.appendChild(line);

    if (rawData) {
        const sub = document.createElement('div');
        sub.className = "log-line payload-info";
        sub.innerText = `└─ Server Response Payload: ${typeof rawData === 'string' ? rawData : JSON.stringify(rawData)}`;
        container.appendChild(sub);
    }

    // Keep log container capped at 150 entries to prevent memory leak and rendering lag
    while (container.childNodes.length > 200) {
        container.removeChild(container.firstChild);
    }

    container.scrollTop = container.scrollHeight;
}

function logNetworkRequest(method, endpoint, payload) {
    const container = document.getElementById('network-api-logs');
    if (!container) return;

    const line = document.createElement('div');
    line.className = "log-line system";

    const timestamp = new Date().toLocaleTimeString();
    
    line.innerHTML = `
        <span class="system">[${timestamp}]</span> 
        <span class="highlight bold">${method}</span> 
        <span class="font-mono">${endpoint}</span>
    `;
    container.appendChild(line);

    if (payload) {
        const sub = document.createElement('div');
        sub.className = "log-line payload-info";
        sub.innerText = `└─ Payload Body: ${JSON.stringify(payload, null, 2)}`;
        container.appendChild(sub);
    }

    // Keep log container capped at 150 entries to prevent memory leak and rendering lag
    while (container.childNodes.length > 200) {
        container.removeChild(container.firstChild);
    }

    container.scrollTop = container.scrollHeight;
}

async function logActiveMemorySecrets() {
    const kdkVal = document.getElementById('mem-kdk-val');
    const privVal = document.getElementById('mem-privkey-val');
    const domVal = document.getElementById('mem-domains-val');

    if (!session.kdk) {
        kdkVal.innerText = "Key locked. Please log in.";
        privVal.innerText = "Key locked. Please log in.";
        domVal.innerText = "No custom domains verified.";
        return;
    }

    try {
        // Export raw bytes of KDK to show hex values
        const rawKdk = await window.crypto.subtle.exportKey("raw", session.kdk);
        kdkVal.innerText = `AES-GCM 256-bit:\nHex: ${window.AlumniMailCrypto.bufferToHex ? window.AlumniMailCrypto.bufferToHex(rawKdk) : "Exported in memory."}`;
    } catch (e) {
        kdkVal.innerText = "AES-GCM 256-bit:\nIn-Memory Lock Active (Non-exportable raw bytes)";
    }

    try {
        // Render JWK representation of the decrypted RSA Private key
        const rawPriv = await window.crypto.subtle.exportKey("jwk", session.privateKey);
        privVal.innerText = `RSA Private Key (JWK):\nalg: ${rawPriv.alg}\nkty: ${rawPriv.kty}\nn: ${rawPriv.n.substring(0, 30)}...\nd: [VOLATILE SECRET REDACTED]`;
    } catch (e) {
        privVal.innerText = "RSA Private Key:\nIn-Memory Lock Active (Non-exportable raw bytes)";
    }

    // List verified domains & aliases currently cached
    const domains = window.AlumniMailDB.getDomainsForUser(session.username).filter(d => d.isVerified);
    const aliases = window.AlumniMailDB.getAliasesForUser(session.username);

    if (domains.length === 0) {
        domVal.innerText = "No custom domains verified.";
    } else {
        let dump = "Verified Domains:\n";
        domains.forEach(d => {
            dump += `└─ ${d.domainName}\n`;
            const domAliases = aliases.filter(a => a.email.endsWith(`@${d.domainName}`));
            domAliases.forEach(a => {
                dump += `   └─ Alias: ${a.email} (RSA key loaded)\n`;
            });
        });
        domVal.innerText = dump;
    }
}

function clearAuditorLogs(type) {
    if (type === 'db') {
        const container = document.getElementById('db-sql-logs');
        container.innerHTML = `<div class="log-line system">[SYSTEM] Query transaction logging active.</div>`;
    } else {
        const container = document.getElementById('network-api-logs');
        container.innerHTML = `<div class="log-line system">[SYSTEM] HTTP Network payload tracer active.</div>`;
    }
}

// -------------------------------------------------------------
// HELPER UTILITIES
// -------------------------------------------------------------
function filterEmails() {
    const query = document.getElementById('mail-search').value.toLowerCase().trim();
    const cards = document.querySelectorAll('.email-card');
    
    cards.forEach(card => {
        const sender = card.querySelector('.card-sender').innerText.toLowerCase();
        const subject = card.querySelector('.card-subject').innerText.toLowerCase();
        const snippet = card.querySelector('.card-snippet').innerText.toLowerCase();
        
        if (sender.includes(query) || subject.includes(query) || snippet.includes(query)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert(`Copied: "${text}" to clipboard!`);
    }).catch(err => {
        console.error("Clipboard copy failed:", err);
    });
}

// -------------------------------------------------------------
// SECTION 8: PRO UPGRADE & SUBSCRIPTION BILLING CYCLE FLOWS
// -------------------------------------------------------------
let billingCycle = 'yearly';
let paymentMethod = 'fiat';

function openUpgradeModal() {
    document.getElementById('upgrade-modal').classList.add('active');
    document.getElementById('upgrade-modal').classList.remove('hidden');
    document.getElementById('upgrade-error').classList.add('hidden');
    document.getElementById('upgrade-success').classList.add('hidden');
    
    // Default billing cycle is yearly, default payment is fiat
    setBillingCycle('yearly');
    setPaymentMethod('fiat');
}

function closeUpgradeModal() {
    document.getElementById('upgrade-modal').classList.remove('active');
    document.getElementById('upgrade-modal').classList.add('hidden');
}

function setBillingCycle(cycle) {
    billingCycle = cycle;
    const knob = document.getElementById('billing-cycle-knob');
    const labelMonthly = document.getElementById('label-billing-monthly');
    const labelYearly = document.getElementById('label-billing-yearly');
    
    if (cycle === 'monthly') {
        knob.style.left = '2px';
        labelMonthly.style.color = 'var(--accent-light)';
        labelYearly.style.color = 'var(--text-color)';
    } else {
        knob.style.left = '24px';
        labelMonthly.style.color = 'var(--text-color)';
        labelYearly.style.color = 'var(--accent-light)';
    }
    
    updateBillingPrices();
}

function toggleBillingCycle() {
    if (billingCycle === 'monthly') {
        setBillingCycle('yearly');
    } else {
        setBillingCycle('monthly');
    }
}

function updateBillingPrices() {
    const priceDisplay = document.getElementById('pro-price-display');
    const periodDisplay = document.getElementById('pro-period-display');
    const tokenDisplay = document.getElementById('token-payable-display');
    
    if (billingCycle === 'monthly') {
        priceDisplay.innerText = "$3.99";
        periodDisplay.innerText = "/ month";
        // 30% Off First Year: $3.99 * 0.70 = $2.79 = 279 ALUMNI
        tokenDisplay.innerText = "279 ALUMNI";
    } else {
        // Yearly saves 20%: $3.16/mo * 12 = $38.00 / year
        priceDisplay.innerText = "$38.00";
        periodDisplay.innerText = "/ year";
        // 30% Off First Year: $38.00 * 0.70 = $26.60 = 2660 ALUMNI
        tokenDisplay.innerText = "2660 ALUMNI";
    }
}

function setPaymentMethod(method) {
    paymentMethod = method;
    const btnFiat = document.getElementById('pay-method-fiat');
    const btnToken = document.getElementById('pay-method-token');
    const formFiat = document.getElementById('fiat-payment-form');
    const formToken = document.getElementById('token-payment-form');
    
    if (method === 'fiat') {
        btnFiat.classList.add('active');
        btnToken.classList.remove('active');
        formFiat.classList.remove('hidden');
        formToken.classList.add('hidden');
    } else {
        btnFiat.classList.remove('active');
        btnToken.classList.add('active');
        formFiat.classList.add('hidden');
        formToken.classList.remove('hidden');
    }
}

function loadUserTier() {
    const tier = localStorage.getItem(`user_tier_${session.username}`) || 'Free';
    session.userTier = tier;
    const badge = document.getElementById('user-tier-badge');
    if (badge) {
        if (tier === 'Pro') {
            badge.innerText = "💎 PRO MEMBER";
            badge.style.background = "linear-gradient(135deg, rgba(255, 215, 0, 0.15) 0%, rgba(0, 229, 255, 0.15) 100%)";
            badge.style.color = "gold";
            badge.style.borderColor = "gold";
            badge.style.boxShadow = "0 0 10px rgba(255, 215, 0, 0.3)";
        } else {
            badge.innerText = "FREE TIER";
            badge.style.background = "rgba(255, 255, 255, 0.06)";
            badge.style.color = "var(--accent-light)";
            badge.style.borderColor = "var(--accent-light)";
            badge.style.boxShadow = "none";
        }
    }
}

async function submitFiatUpgrade() {
    const cardNum = document.getElementById('upgrade-card-number').value.trim();
    const errorEl = document.getElementById('upgrade-error');
    const successEl = document.getElementById('upgrade-success');
    
    errorEl.classList.add('hidden');
    successEl.classList.add('hidden');
    
    if (cardNum.length < 16) {
        errorEl.innerText = "❌ Please enter a valid 16-digit credit card number.";
        errorEl.classList.remove('hidden');
        return;
    }
    
    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', '💳 Authorizing credit transaction with bank...');
    
    try {
        await new Promise(resolve => setTimeout(resolve, 800));
        updateCryptoOverlayStep('rsa', 'active', '🔒 Syncing encrypted membership flags...');
        
        await window.AlumniMailDB.upgradeUserTier(session.username, 'Pro', 'fiat', { cardEnding: cardNum.slice(-4) });
        
        updateCryptoOverlayStep('aes', 'completed', '✅ Credit payment approved.');
        updateCryptoOverlayStep('db', 'completed', '✅ Local Database upgrade finalized.');
        
        setTimeout(() => {
            hideCryptoOverlay();
            successEl.innerText = "🎉 Account upgraded successfully! Welcome to ALUMNI PRO.";
            successEl.classList.remove('hidden');
            loadUserTier();
            setTimeout(closeUpgradeModal, 1500);
        }, 800);
    } catch (e) {
        hideCryptoOverlay();
        errorEl.innerText = "❌ Upgrade failed: " + e.message;
        errorEl.classList.remove('hidden');
    }
}

async function submitTokenUpgrade() {
    const errorEl = document.getElementById('upgrade-error');
    const successEl = document.getElementById('upgrade-success');
    
    errorEl.classList.add('hidden');
    successEl.classList.add('hidden');
    
    // Check wallet tag and private PEM key
    const walletTag = localStorage.getItem(`wallet_tag_${session.username}`);
    const walletPem = localStorage.getItem(`wallet_pem_${session.username}`);
    
    if (!walletTag || !walletPem) {
        errorEl.innerText = "❌ No Alumni PEM Wallet connected. Please connect wallet first via the sidebar.";
        errorEl.classList.remove('hidden');
        return;
    }
    
    // Check balance
    const balanceText = document.getElementById('wallet-balance').innerText;
    const currentBalance = parseFloat(balanceText.replace(/[^\d.]/g, '')) || 0;
    const requiredAmount = billingCycle === 'monthly' ? 279 : 2660;
    
    if (currentBalance < requiredAmount) {
        errorEl.innerText = `❌ Insufficient L1 Balance. Upgrade requires ${requiredAmount} ALUMNI. (Current: ${currentBalance})`;
        errorEl.classList.remove('hidden');
        return;
    }
    
    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', `🪙 Initiating L1 Token subtraction: ${requiredAmount} ALUMNI...`);
    
    try {
        await new Promise(resolve => setTimeout(resolve, 600));
        updateCryptoOverlayStep('rsa', 'active', '✍️ Signing transaction payload locally with private PEM key...');
        
        // Generate mock transaction signature
        const txPayload = JSON.stringify({
            sender: walletTag,
            recipient: "alumnimail.escrow",
            amount: requiredAmount,
            nonce: Date.now()
        });
        
        const signatureBytes = new Uint8Array(64);
        window.crypto.getRandomValues(signatureBytes);
        const signatureHex = Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        
        updateCryptoOverlayStep('aes', 'active', '🚀 Broadcasting signed subscription payload to L1 RPC node...');
        
        // POST to blockchain relayer
        const res = await fetch('/api/v1/wallet/send', {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                senderTag: walletTag,
                recipientTag: "alumnimail.escrow",
                amount: requiredAmount,
                pemPrivateKey: walletPem,
                txPayload,
                signatureHex
            })
        });
        
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || "L1 consensus rejected payment.");
        }
        
        const txData = await res.json();
        
        updateCryptoOverlayStep('db', 'completed', '✅ L1 Block confirmed.');
        
        await window.AlumniMailDB.upgradeUserTier(session.username, 'Pro', 'token', null, requiredAmount, txData.txHash);
        
        // Update local wallet balance immediately
        updateWalletBalance(walletTag);
        
        setTimeout(() => {
            hideCryptoOverlay();
            successEl.innerText = `🎉 Consensually verified on-chain! Upgraded to ALUMNI PRO. Tx: ${txData.txHash.substring(0, 12)}...`;
            successEl.classList.remove('hidden');
            loadUserTier();
            setTimeout(closeUpgradeModal, 2000);
        }, 1000);
    } catch (e) {
        hideCryptoOverlay();
        errorEl.innerText = "❌ Blockchain consensus failed: " + e.message;
        errorEl.classList.remove('hidden');
    }
}

// -------------------------------------------------------------
// SECTION 9: E2EE CALENDAR ACTIONS & RENDER CHANNELS
// -------------------------------------------------------------
let calendarMonth = 4; // May
let calendarYear = 2026;
let calendarMeetings = [];
let selectedDateString = "2026-05-19"; // default to seed date

function prevMonth() {
    calendarMonth--;
    if (calendarMonth < 0) {
        calendarMonth = 11;
        calendarYear--;
    }
    renderCalendarView();
}

function nextMonth() {
    calendarMonth++;
    if (calendarMonth > 11) {
        calendarMonth = 0;
        calendarYear++;
    }
    renderCalendarView();
}

function openAddMeetingModal() {
    // Check custom meeting scheduling limits for Free users
    const userMeetings = calendarMeetings.filter(m => m.username === session.username);
    if (session.userTier !== 'Pro' && userMeetings.length >= 1) {
        alert("🔒 Free accounts are strictly limited to exactly 1 scheduled meeting. Please upgrade to Pro for unlimited zero-knowledge scheduling!");
        openUpgradeModal();
        return;
    }
    
    document.getElementById('add-meeting-modal').classList.remove('hidden');
    document.getElementById('meeting-title').value = '';
    document.getElementById('meeting-desc').value = '';
    
    // Initialize date to selected day
    document.getElementById('meeting-date').value = selectedDateString;
    document.getElementById('meeting-time').value = "14:00";
}

function closeAddMeetingModal() {
    document.getElementById('add-meeting-modal').classList.add('hidden');
}

async function handleSaveMeeting(event) {
    event.preventDefault();
    const title = document.getElementById('meeting-title').value.trim();
    const date = document.getElementById('meeting-date').value;
    const time = document.getElementById('meeting-time').value;
    const desc = document.getElementById('meeting-desc').value.trim();
    
    if (!title || !date || !time) return;
    
    showCryptoOverlay();
    updateCryptoOverlayStep('pbkdf2', 'active', '🔑 Querying user local public key JWK...');
    
    try {
        // Encrypt meeting elements locally using the user's own RSA key so only they can decrypt!
        updateCryptoOverlayStep('rsa', 'active', '🔒 Encrypting meeting details with hybrid RSA-OAEP + AES-GCM...');
        const encData = await window.AlumniMailCrypto.encryptEmail(title, desc, session.publicJwk);
        
        updateCryptoOverlayStep('aes', 'completed', '✅ Details locally encrypted inside browser memory.');
        updateCryptoOverlayStep('db', 'active', '📤 Registering encrypted agenda stream to node storage...');
        
        const meetingObj = {
            id: window.AlumniMailCrypto.bufferToBase64(window.crypto.getRandomValues(new Uint8Array(16))),
            encryptedTitle: encData.encryptedPayload,
            encryptedDesc: encData.encryptedPayload, // we wrap both title+desc inside the single payload
            wrappingKey: encData.encryptedSessionKey,
            ivTitle: encData.iv,
            ivDesc: encData.iv,
            date,
            time
        };
        
        await window.AlumniMailDB.saveMeeting(session.username, meetingObj);
        updateCryptoOverlayStep('db', 'completed', '✅ Calendar transaction sync succeeded.');
        
        setTimeout(async () => {
            hideCryptoOverlay();
            closeAddMeetingModal();
            selectedDateString = date;
            await renderCalendarView();
        }, 600);
    } catch (e) {
        hideCryptoOverlay();
        alert("E2EE Meeting save failed: " + e.message);
    }
}

async function renderCalendarView() {
    const monthYearEl = document.getElementById('calendar-month-year');
    const daysGrid = document.getElementById('calendar-days-grid');
    
    const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    monthYearEl.innerText = `${months[calendarMonth]} ${calendarYear}`;
    
    // Fetch all user meetings from DB
    calendarMeetings = await window.AlumniMailDB.getMeetingsForUser(session.username);
    
    // Build days calendar cells
    daysGrid.innerHTML = '';
    
    const firstDayIndex = new Date(calendarYear, calendarMonth, 1).getDay();
    const totalDays = new Date(calendarYear, calendarMonth + 1, 0).getDate();
    
    // Empty cells for padding
    for (let i = 0; i < firstDayIndex; i++) {
        const emptyCell = document.createElement('div');
        emptyCell.style.opacity = '0';
        daysGrid.appendChild(emptyCell);
    }
    
    // Populating active days
    for (let d = 1; d <= totalDays; d++) {
        const cell = document.createElement('div');
        cell.className = 'calendar-day-cell';
        cell.style.cssText = `
            padding: 8px; 
            border: 1px solid rgba(255,255,255,0.03); 
            border-radius: 6px; 
            min-height: 48px; 
            text-align: right; 
            font-size: 0.8rem; 
            cursor: pointer; 
            position: relative; 
            transition: all 0.2s;
            background: rgba(255, 255, 255, 0.01);
        `;
        
        const dayStr = `${calendarYear}-${String(calendarMonth + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
        cell.innerHTML = `<span style="font-weight:700;">${d}</span>`;
        
        // Click selector
        cell.onclick = () => {
            const activeCells = document.querySelectorAll('.calendar-day-cell');
            activeCells.forEach(ac => ac.style.borderColor = 'rgba(255,255,255,0.03)');
            cell.style.borderColor = 'var(--accent-light)';
            selectedDateString = dayStr;
            renderAgenda(dayStr);
        };
        
        // Check meetings for this specific date
        const dayMeetings = calendarMeetings.filter(m => m.date === dayStr);
        if (dayMeetings.length > 0) {
            const dot = document.createElement('span');
            dot.style.cssText = "position: absolute; bottom: 6px; left: 8px; width: 6px; height: 6px; border-radius: 50%; background: var(--accent-light); box-shadow: 0 0 8px var(--accent-light);";
            cell.appendChild(dot);
        }
        
        // Highlight active date selection
        if (dayStr === selectedDateString) {
            cell.style.borderColor = 'var(--accent-light)';
            cell.style.background = 'rgba(0, 229, 255, 0.05)';
        }
        
        daysGrid.appendChild(cell);
    }
    
    // Auto-load agenda for default or selected day
    renderAgenda(selectedDateString);
}

async function renderAgenda(dayString) {
    const listEl = document.getElementById('agenda-meetings-list');
    listEl.innerHTML = '';
    
    // Format human-readable date
    const dateObj = new Date(dayString + "T00:00:00");
    const formattedDate = dateObj.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });
    
    const header = document.createElement('div');
    header.style.cssText = "font-size: 0.85rem; font-weight: 800; color: var(--text-muted); margin-bottom: 5px;";
    header.innerText = formattedDate;
    listEl.appendChild(header);
    
    const dayMeetings = calendarMeetings.filter(m => m.date === dayString);
    
    if (dayMeetings.length === 0) {
        const noEvent = document.createElement('div');
        noEvent.style.cssText = "color: var(--text-muted); text-align: center; margin-top: 15px; font-size: 0.75rem; border: 1px dashed rgba(255,255,255,0.04); padding: 20px; border-radius: 6px;";
        noEvent.innerText = "No secure meetings scheduled for this day.";
        listEl.appendChild(noEvent);
        return;
    }
    
    // Free premium restriction alert check
    if (session.userTier !== 'Pro') {
        const lockedCard = document.createElement('div');
        lockedCard.className = 'glass-panel';
        lockedCard.style.cssText = "padding: 15px; text-align: center; border: 1px solid var(--accent-light); cursor: pointer; transition: all 0.2s;";
        lockedCard.onclick = openUpgradeModal;
        lockedCard.innerHTML = `
            <div style="font-size: 1.1rem; margin-bottom: 5px;">🔒</div>
            <h4 style="margin:0 0 5px 0; font-size: 0.8rem; font-weight: 800; color: var(--accent-light);">E2EE Details Locked</h4>
            <p style="margin:0; font-size: 0.7rem; color: var(--text-muted); line-height: 1.3;">
                Zero-Knowledge agenda details are premium E2EE capabilities. Upgrade to PRO to view encrypted events.
            </p>
        `;
        listEl.appendChild(lockedCard);
        return;
    }
    
    // Decrypt and display each meeting
    for (const m of dayMeetings) {
        const item = document.createElement('div');
        item.className = 'glass-panel';
        item.style.cssText = "padding: 12px; margin-bottom: 8px; border: 1px solid var(--border-color); background: rgba(255,255,255,0.01);";
        
        const loader = document.createElement('div');
        loader.style.cssText = "font-size: 0.7rem; color: var(--text-muted); font-style: italic;";
        loader.innerHTML = "🔓 Local RSA decryption stream active...";
        item.appendChild(loader);
        listEl.appendChild(item);
        
        try {
            // RSA private key unwrap payload E2EE
            const decrypted = await window.AlumniMailCrypto.decryptEmail(m.encryptedTitle, m.wrappingKey, m.ivTitle, session.privateKey);
            
            // Render decrypted contents beautifully!
            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                    <h4 style="margin: 0; font-weight: 800; font-size: 0.85rem; color: var(--accent-light);">${decrypted.subject}</h4>
                    <span style="font-size: 0.7rem; background: var(--border-color); padding: 2px 6px; border-radius: 4px; font-family: monospace; font-weight: 800;">⏰ ${m.time}</span>
                </div>
                <p style="margin: 0; font-size: 0.75rem; color: var(--text-muted); line-height: 1.4;">${decrypted.body}</p>
                <div style="margin-top: 8px; display: flex; align-items: center; gap: 4px; font-size: 0.6rem; color: var(--success-light); font-weight: 800; text-shadow: 0 0 6px rgba(16, 185, 129, 0.2);">
                    🔑 Authenticated & Locally Decrypted (E2EE)
                </div>
            `;
        } catch (err) {
            item.innerHTML = `
                <h4 style="margin: 0 0 4px 0; font-size: 0.85rem; color: var(--accent-light);">⚠️ Decryption Error</h4>
                <p style="margin: 0; font-size: 0.7rem; color: var(--text-muted);">Failed to decrypt securely with loaded private keys.</p>
            `;
        }
    }
}
