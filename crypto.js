/**
 * Alumni Mail Cryptographic Engine
 * Powered by browser-native Web Crypto API
 * Implements PBKDF2, RSA-OAEP (2048-bit), and AES-GCM (256-bit)
 */

// Helper: Convert ArrayBuffer to Base64 String
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper: Convert Base64 String to ArrayBuffer
function base64ToBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Helper: Convert Hex String to ArrayBuffer
function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes.buffer;
}

// Helper: Convert ArrayBuffer to Hex String
function bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: Convert text to ArrayBuffer
function textToBuffer(text) {
    return new TextEncoder().encode(text);
}

// Helper: Convert ArrayBuffer to text
function bufferToText(buffer) {
    return new TextDecoder().decode(buffer);
}

/**
 * Derives a key and an authentication hash from a user's password and salt using PBKDF2.
 * @param {string} password - The user's cleartext password.
 * @param {Uint8Array|string} salt - The user's cryptographic salt.
 * @returns {Promise<{ kdk: CryptoKey, authHash: string }>} Key Decryption Key and Auth Hash.
 */
async function deriveKeys(password, salt) {
    const passwordBytes = textToBuffer(password);
    const saltBytes = typeof salt === 'string' ? base64ToBuffer(salt) : salt;

    // 1. Import cleartext password as master keying material
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey", "deriveBits"]
    );

    // 2. Derive the 256-bit Key Decryption Key (KDK) for local AES-GCM operations
    const kdk = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 10000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    // 3. Derive Auth Hash for zero-knowledge server authentication (so server never knows the password or KDK)
    const authSaltBytes = textToBuffer("alumni-auth-salt-" + bufferToBase64(saltBytes));
    const authHashBuffer = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: authSaltBytes,
            iterations: 5000,
            hash: "SHA-256"
        },
        baseKey,
        256
    );
    const authHash = bufferToHex(authHashBuffer);

    return { kdk, authHash };
}

/**
 * Generates an RSA-OAEP 2048-bit key pair.
 * @returns {Promise<CryptoKeyPair>} The cryptographic key pair.
 */
async function generateRSAKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256"
        },
        true, // exportable
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts a private key using AES-GCM with a KDK derived key.
 * @param {CryptoKey} privateKey - RSA private key.
 * @param {CryptoKey} kdk - AES Key Decryption Key.
 * @returns {Promise<{ ciphertext: string, iv: string }>} Encrypted private key payload.
 */
async function encryptPrivateKey(privateKey, kdk) {
    // Export the key as JSON Web Key (JWK)
    const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
    const jwkString = JSON.stringify(jwk);

    // Encrypt using AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        kdk,
        textToBuffer(jwkString)
    );

    return {
        ciphertext: bufferToBase64(encryptedBuffer),
        iv: bufferToBase64(iv)
    };
}

/**
 * Decrypts a private key using AES-GCM.
 * @param {string} ciphertextBase64 - Encrypted private key in base64.
 * @param {string} ivBase64 - IV in base64.
 * @param {CryptoKey} kdk - AES Key Decryption Key.
 * @returns {Promise<CryptoKey>} Decrypted RSA Private Key.
 */
async function decryptPrivateKey(ciphertextBase64, ivBase64, kdk) {
    const ciphertext = base64ToBuffer(ciphertextBase64);
    const iv = base64ToBuffer(ivBase64);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        kdk,
        ciphertext
    );

    const jwkString = bufferToText(decryptedBuffer);
    const jwk = JSON.parse(jwkString);

    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
}

/**
 * Performs hybrid encryption of an email payload for a recipient's public key.
 * 1. Generates random AES-GCM session key.
 * 2. Encrypts payload (subject + body) with AES-GCM.
 * 3. Encrypts AES session key with recipient's RSA-OAEP public key.
 * @param {string} subject - Cleartext email subject.
 * @param {string} body - Cleartext email body.
 * @param {object} recipientPublicJwk - Recipient's RSA public key in JWK format.
 * @returns {Promise<{ encryptedPayload: string, encryptedSessionKey: string, iv: string }>} Encrypted email payload.
 */
async function encryptEmail(subject, body, recipientPublicJwk) {
    // 1. Import recipient's public key
    const recipientPublicKey = await window.crypto.subtle.importKey(
        "jwk",
        recipientPublicJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    // 2. Generate random 256-bit AES symmetric session key
    const sessionKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    // 3. Encrypt subject and body with session key
    const payload = JSON.stringify({ subject, body });
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedPayloadBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        textToBuffer(payload)
    );

    // 4. Export session key raw bytes
    const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);

    // 5. Encrypt (wrap) session key with recipient's RSA public key
    const encryptedSessionKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPublicKey,
        rawSessionKey
    );

    return {
        encryptedPayload: bufferToBase64(encryptedPayloadBuffer),
        encryptedSessionKey: bufferToBase64(encryptedSessionKeyBuffer),
        iv: bufferToBase64(iv)
    };
}

/**
 * Decrypts a hybrid-encrypted email using the user's RSA private key.
 * @param {string} encryptedPayload - Encrypted body+subject in base64.
 * @param {string} encryptedSessionKey - Encrypted AES session key in base64.
 * @param {string} iv - IV in base64.
 * @param {CryptoKey} privateKey - Recipient's RSA-OAEP private key.
 * @returns {Promise<{ subject: string, body: string }>} Decrypted email elements.
 */
async function decryptEmail(encryptedPayload, encryptedSessionKey, iv, privateKey) {
    // 1. Decrypt (unwrap) the raw AES session key using RSA private key
    const rawSessionKey = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        base64ToBuffer(encryptedSessionKey)
    );

    // 2. Import the raw AES session key
    const sessionKey = await window.crypto.subtle.importKey(
        "raw",
        rawSessionKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    // 3. Decrypt the payload
    const decryptedPayloadBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBuffer(iv) },
        sessionKey,
        base64ToBuffer(encryptedPayload)
    );

    const decryptedString = bufferToText(decryptedPayloadBuffer);
    return JSON.parse(decryptedString);
}

/**
 * Encrypts a message using a symmetric key derived from a custom password (for non-E2EE external recipients).
 * @param {string} subject - Cleartext email subject.
 * @param {string} body - Cleartext email body.
 * @param {string} customPassword - Standard shared password string.
 * @returns {Promise<{ encryptedPayload: string, salt: string, iv: string }>} Encrypted payload.
 */
async function encryptWithPassword(subject, body, customPassword) {
    const passwordBytes = textToBuffer(customPassword);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    // Derive AES key using PBKDF2
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 5000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    const payload = JSON.stringify({ subject, body });
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        textToBuffer(payload)
    );

    return {
        encryptedPayload: bufferToBase64(encryptedBuffer),
        salt: bufferToBase64(salt),
        iv: bufferToBase64(iv)
    };
}

/**
 * Decrypts a message using a custom password.
 * @param {string} encryptedPayload - Base64 payload.
 * @param {string} salt - Base64 salt.
 * @param {string} iv - Base64 iv.
 * @param {string} customPassword - Decryption password.
 * @returns {Promise<{ subject: string, body: string }>} Decrypted elements.
 */
async function decryptWithPassword(encryptedPayload, salt, iv, customPassword) {
    const passwordBytes = textToBuffer(customPassword);
    const saltBytes = base64ToBuffer(salt);
    const ivBytes = base64ToBuffer(iv);

    // Derive AES key
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 5000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        key,
        base64ToBuffer(encryptedPayload)
    );

    return JSON.parse(bufferToText(decryptedBuffer));
}

// Make functions globally available
window.AlumniMailCrypto = {
    bufferToBase64,
    base64ToBuffer,
    bufferToHex,
    deriveKeys,
    generateRSAKeyPair,
    encryptPrivateKey,
    decryptPrivateKey,
    encryptEmail,
    decryptEmail,
    encryptWithPassword,
    decryptWithPassword
};
