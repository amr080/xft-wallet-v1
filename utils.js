// Utility functions for crypto operations
const utils = {
    // Base58 alphabet
    ALPHABET: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    
    // Convert ArrayBuffer to hex string
    bufferToHex: (buffer) => {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Convert hex string to ArrayBuffer
    hexToBuffer: (hex) => {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return bytes.buffer;
    },

    // Generate a random salt
    generateSalt: () => {
        return crypto.getRandomValues(new Uint8Array(16));
    },

    // Derive key from password using PBKDF2
    async deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Generate a random IV for AES encryption
    generateIV: () => {
        return crypto.getRandomValues(new Uint8Array(12));
    },

    // Custom Base58 implementation
    encodeBase58: (buffer) => {
        const digits = [0];
        for (let i = 0; i < buffer.length; i++) {
            let carry = buffer[i];
            for (let j = 0; j < digits.length; j++) {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry = (carry / 58) | 0;
            }
            while (carry > 0) {
                digits.push(carry % 58);
                carry = (carry / 58) | 0;
            }
        }

        // Convert digits to Base58 string
        let str = '';
        for (let i = 0; i < digits.length; i++) {
            str = utils.ALPHABET[digits[i]] + str;
        }

        // Add leading zeros
        for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
            str = '1' + str;
        }

        return str;
    },

    // Convert string to Base58
    stringToBase58: (str) => {
        try {
            const bytes = new TextEncoder().encode(str);
            return utils.encodeBase58(bytes);
        } catch (error) {
            console.warn('Base58 encoding failed, using hex encoding fallback');
            return Array.from(new TextEncoder().encode(str))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    },

    // Hash data using SHA-256
    async sha256(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        return new Uint8Array(hashBuffer);
    }
};
