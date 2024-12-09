class CryptoWallet {
    constructor() {
        this.keyPair = null;
        this.walletAddress = null;
        this.encryptedPrivateKey = null;
        this.signature = null;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        document.getElementById('generateWallet').addEventListener('click', () => this.generateWallet());
        document.getElementById('encryptKey').addEventListener('click', () => this.encryptPrivateKey());
        document.getElementById('signTransaction').addEventListener('click', () => this.signTransaction());
        document.getElementById('verifyTransaction').addEventListener('click', () => this.verifyTransaction());
    }

    async generateWallet() {
        try {
            // Generate key pair
            this.keyPair = await crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ["sign", "verify"]
            );

            // Export public key
            const publicKeyBuffer = await crypto.subtle.exportKey(
                "raw",
                this.keyPair.publicKey
            );
            const publicKeyHex = utils.bufferToHex(publicKeyBuffer);

            // Export private key
            const privateKeyBuffer = await crypto.subtle.exportKey(
                "pkcs8",
                this.keyPair.privateKey
            );
            const privateKeyHex = utils.bufferToHex(privateKeyBuffer);

            // Generate wallet address (hash of public key)
            const publicKeyHash = await utils.sha256(publicKeyHex);
            try {
                this.walletAddress = utils.stringToBase58(utils.bufferToHex(publicKeyHash));
            } catch (error) {
                console.error('Error generating wallet address:', error);
                // Fallback to using hex representation if Base58 fails
                this.walletAddress = utils.bufferToHex(publicKeyHash);
            }

            // Display wallet info
            document.getElementById('publicKey').value = publicKeyHex;
            document.getElementById('privateKey').value = privateKeyHex;
            document.getElementById('walletAddress').value = this.walletAddress;
            document.getElementById('walletInfo').style.display = 'block';
        } catch (error) {
            console.error('Error generating wallet:', error);
            alert('Failed to generate wallet');
        }
    }

    async encryptPrivateKey() {
        try {
            if (!this.keyPair) {
                throw new Error('No wallet generated');
            }

            const password = document.getElementById('encryptPassword').value;
            if (!password) {
                throw new Error('Password is required');
            }

            // Export private key
            const privateKeyBuffer = await crypto.subtle.exportKey(
                "pkcs8",
                this.keyPair.privateKey
            );

            // Generate salt and IV
            const salt = utils.generateSalt();
            const iv = utils.generateIV();

            // Derive encryption key from password
            const encryptionKey = await utils.deriveKey(password, salt);

            // Encrypt private key
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                encryptionKey,
                privateKeyBuffer
            );

            // Combine salt, IV, and encrypted data
            const encryptedPrivateKey = utils.bufferToHex(salt) +
                utils.bufferToHex(iv) +
                utils.bufferToHex(encryptedData);

            document.getElementById('encryptedKey').value = encryptedPrivateKey;
            document.getElementById('encryptedKeyInfo').style.display = 'block';
        } catch (error) {
            console.error('Error encrypting private key:', error);
            alert('Failed to encrypt private key: ' + error.message);
        }
    }

    async signTransaction() {
        try {
            if (!this.keyPair) {
                throw new Error('No wallet generated');
            }

            const transactionData = document.getElementById('transactionData').value;
            if (!transactionData) {
                throw new Error('Transaction data is required');
            }

            // Convert transaction data to ArrayBuffer
            const encoder = new TextEncoder();
            const data = encoder.encode(transactionData);

            // Sign the transaction
            const signature = await crypto.subtle.sign(
                {
                    name: "ECDSA",
                    hash: { name: "SHA-256" },
                },
                this.keyPair.privateKey,
                data
            );

            this.signature = utils.bufferToHex(signature);
            document.getElementById('signature').value = this.signature;
            document.getElementById('signatureInfo').style.display = 'block';
        } catch (error) {
            console.error('Error signing transaction:', error);
            alert('Failed to sign transaction: ' + error.message);
        }
    }

    async verifyTransaction() {
        try {
            if (!this.keyPair || !this.signature) {
                throw new Error('No signature or wallet available');
            }

            const transactionData = document.getElementById('transactionData').value;
            if (!transactionData) {
                throw new Error('Transaction data is required');
            }

            // Convert transaction data to ArrayBuffer
            const encoder = new TextEncoder();
            const data = encoder.encode(transactionData);

            // Verify the signature
            const isValid = await crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: { name: "SHA-256" },
                },
                this.keyPair.publicKey,
                utils.hexToBuffer(this.signature),
                data
            );

            const resultDiv = document.getElementById('verificationResult');
            resultDiv.style.display = 'block';
            resultDiv.textContent = isValid ? 'Signature is valid!' : 'Invalid signature!';
        } catch (error) {
            console.error('Error verifying transaction:', error);
            alert('Failed to verify transaction: ' + error.message);
        }
    }
}

// Initialize wallet when the page loads
window.addEventListener('load', () => {
    window.wallet = new CryptoWallet();
});
