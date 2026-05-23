import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const RPC_URL = process.env.L1_RPC_URL || 'http://localhost:3001';
const WALLET_FILE = './blockchain-temp/alumni-blockchain/alumni_node_wallet.json';
const DB_FILE = './server_db.json';

// Helper to wait
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
    console.log("🚀 Starting Ledger Seeding and Premium User Provisioning...");

    // 1. Compute app.js bundle SHA-256 hash
    if (!fs.existsSync('./app.js')) {
        console.error("❌ app.js not found!");
        process.exit(1);
    }
    const appCode = fs.readFileSync('./app.js', 'utf8');
    const bundleHash = crypto.createHash('sha256').update(appCode).digest('hex');
    console.log(`📦 Local app.js bundle SHA-256: ${bundleHash}`);

    // 2. Load wallet keys
    if (!fs.existsSync(WALLET_FILE)) {
        console.error(`❌ Wallet file not found at ${WALLET_FILE}`);
        process.exit(1);
    }
    const walletKeys = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    const fromAddress = walletKeys.publicKey;
    const privateKey = walletKeys.privateKey;

    // 3. Resolve contract address
    const contractAddress = process.env.ALUMNI_MAIL_REGISTRY_ADDRESS || "9e4e86b5fba2149708c545dec031c398c2fb54b62a246f194a9048c91ca3d003";
    console.log(`📜 Target contract address: ${contractAddress}`);

    // 4. Check/seed users in server_db.json
    if (!fs.existsSync(DB_FILE)) {
        console.error(`❌ Database file not found at ${DB_FILE}`);
        process.exit(1);
    }
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!db.users) db.users = {};

    const targetUsers = [
        { email: 'khalil@alumnimail.app', tag: '@ALUMNI.KHALIL' },
        { email: 'satoshi@alumnimail.app', tag: '@ALUMNI.SATOSHI' },
        { email: 'nycole@alumnimail.app', tag: '@ALUMNI.NYCOLE' },
        { email: 'dev@alumnimail.app', tag: '@ALUMNI.DEV' }
    ];

    const { subtle } = crypto.webcrypto;

    // Helper functions for Web Crypto compatibility in Node.js
    const textToBuffer = (text) => new TextEncoder().encode(text);
    const bufferToBase64 = (buffer) => Buffer.from(buffer).toString('base64');
    const base64ToBuffer = (base64) => Buffer.from(base64, 'base64').buffer;
    const bufferToHex = (buffer) => Buffer.from(buffer).toString('hex');

    async function deriveKeys(password, salt) {
        const passwordBytes = textToBuffer(password);
        const saltBytes = typeof salt === 'string' ? base64ToBuffer(salt) : salt;

        const baseKey = await subtle.importKey(
            "raw",
            passwordBytes,
            "PBKDF2",
            false,
            ["deriveKey", "deriveBits"]
        );

        const kdk = await subtle.deriveKey(
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

        const authSaltBytes = textToBuffer("alumni-auth-salt-" + bufferToBase64(saltBytes));
        const authHashBuffer = await subtle.deriveBits(
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

    async function encryptPrivateKey(privateKey, kdk) {
        const jwk = await subtle.exportKey("jwk", privateKey);
        const jwkString = JSON.stringify(jwk);

        const iv = crypto.randomBytes(12);
        const encryptedBuffer = await subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            kdk,
            textToBuffer(jwkString)
        );

        return {
            ciphertext: bufferToBase64(encryptedBuffer),
            iv: bufferToBase64(iv)
        };
    }

    for (const u of targetUsers) {
        const exists = db.users[u.email];
        const isDummy = exists && exists.encPrivateKey && (exists.encPrivateKey.ciphertext === "seeded_cipher_data" || exists.encPrivateKey.ciphertext === "cipher" || exists.encPrivateKey.ciphertext.length < 50);
        
        if (!exists || isDummy) {
            console.log(`👤 Seeding cryptographically valid profile for ${u.email} in database...`);
            
            const saltBytes = crypto.randomBytes(16);
            const saltBase64 = bufferToBase64(saltBytes);
            const password = "password123";
            
            // Derive master keys
            const { kdk, authHash } = await deriveKeys(password, saltBase64);
            
            // Generate RSA key pair for E2EE
            const keypair = await subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );
            
            const publicJwk = await subtle.exportKey("jwk", keypair.publicKey);
            const encPrivateKey = await encryptPrivateKey(keypair.privateKey, kdk);
            
            db.users[u.email] = {
                username: u.email,
                authHash: authHash,
                salt: saltBase64,
                publicJwk: publicJwk,
                encPrivateKey: encPrivateKey,
                tier: "Elite",
                walletTag: u.tag,
                registeredAt: Date.now(),
                webauthnCredentials: []
            };
            console.log(`✅ Profile successfully seeded for ${u.email}. Password is: "${password}"`);
        } else {
            console.log(`👤 Profile for ${u.email} already exists and is valid. Ensuring Elite tier and wallet link tag...`);
            db.users[u.email].tier = "Elite";
            db.users[u.email].walletTag = u.tag;
        }
    }

    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 4), 'utf8');
    console.log("✅ server_db.json successfully updated with premium profiles.");

    // 5. Broadcast app registration for "alumnimail.app" and "Alumni Mail"
    const appsToRegister = ["alumnimail.app", "Alumni Mail"];
    for (const appName of appsToRegister) {
        console.log(`📡 Registering dApp "${appName}" on-chain...`);
        const txPayload = {
            privateKey,
            fromAddress,
            toAddress: contractAddress,
            amount: 0,
            type: "CONTRACT_CALL",
            payload: {
                method: "registerApp",
                args: {
                    appName,
                    description: "Official Alumni Certified Secure E2EE Communications Client",
                    bundleHash,
                    version: "1.0.0"
                }
            }
        };

        const res = await fetch(`${RPC_URL}/transaction/sign-and-send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(txPayload)
        });
        const result = await res.json();
        if (!res.ok) {
            console.warn(`⚠️ Warning during registering ${appName}: ${result.error || 'Failed'}`);
        } else {
            console.log(`✅ App "${appName}" registered! Tx: ${result.hash}`);
        }
    }

    // 6. Broadcast user public keys and wallet links
    for (const u of targetUsers) {
        const userObj = db.users[u.email];
        console.log(`📡 Registering public key for ${u.email} on-chain...`);
        
        const pkPayload = {
            privateKey,
            fromAddress,
            toAddress: contractAddress,
            amount: 0,
            type: "CONTRACT_CALL",
            payload: {
                method: "registerPublicKey",
                args: {
                    email: u.email,
                    publicJwk: userObj.publicJwk
                }
            }
        };

        const pkRes = await fetch(`${RPC_URL}/transaction/sign-and-send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(pkPayload)
        });
        const pkResult = await pkRes.json();
        if (!pkRes.ok) {
            console.warn(`⚠️ Key registration warning for ${u.email}: ${pkResult.error}`);
        } else {
            console.log(`✅ Public key registered for ${u.email}. Tx: ${pkResult.hash}`);
        }

        console.log(`📡 Linking ${u.email} to wallet tag ${u.tag} on-chain...`);
        const linkPayload = {
            privateKey,
            fromAddress,
            toAddress: contractAddress,
            amount: 0,
            type: "CONTRACT_CALL",
            payload: {
                method: "linkEmailToWallet",
                args: {
                    email: u.email,
                    walletTag: u.tag
                }
            }
        };

        const linkRes = await fetch(`${RPC_URL}/transaction/sign-and-send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(linkPayload)
        });
        const linkResult = await linkRes.json();
        if (!linkRes.ok) {
            console.warn(`⚠️ Wallet link warning for ${u.email}: ${linkResult.error}`);
        } else {
            console.log(`✅ Wallet link complete for ${u.email}. Tx: ${linkResult.hash}`);
        }
    }

    // 7. Propose block to mine everything instantly
    console.log("⏳ Proposing consensus block to mine transactions...");
    const proposeRes = await fetch(`${RPC_URL}/propose`, { method: 'POST' });
    if (proposeRes.ok) {
        console.log("🎉 Block proposed successfully! Ledger is now fully seeded and live!");
    } else {
        console.warn("⚠️ Block proposal failed, transactions will mine in the background.");
    }
}

main().catch(err => {
    console.error("❌ Seeding failed:", err);
});
