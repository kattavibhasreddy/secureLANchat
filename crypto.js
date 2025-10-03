/**
 * Client-side cryptography module using Web Crypto API
 * Provides AES-GCM encryption with SHA-256 key derivation
 */

class CryptoHelper {
    constructor() {
        this.key = null;
    }
    
    /**
     * Derive encryption key from password using SHA-256
     * @param {string} password - The shared password
     * @returns {Promise<CryptoKey>} - The derived encryption key
     */
    async deriveKey(password) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
        
        this.key = await crypto.subtle.importKey(
            'raw',
            hashBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
        
        return this.key;
    }
    
    /**
     * Encrypt a message using AES-GCM
     * @param {string} message - The plaintext message
     * @returns {Promise<string>} - Base64 encoded encrypted message
     */
    async encrypt(message) {
        if (!this.key) {
            throw new Error('Key not initialized. Call deriveKey first.');
        }
        
        const encoder = new TextEncoder();
        const messageBuffer = encoder.encode(message);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            this.key,
            messageBuffer
        );
        
        const encryptedArray = new Uint8Array(encryptedBuffer);
        const combined = new Uint8Array(iv.length + encryptedArray.length);
        combined.set(iv);
        combined.set(encryptedArray, iv.length);
        
        return this.arrayBufferToBase64(combined);
    }
    
    /**
     * Decrypt a message using AES-GCM
     * @param {string} encryptedBase64 - Base64 encoded encrypted message
     * @returns {Promise<string>} - The decrypted plaintext message
     */
    async decrypt(encryptedBase64) {
        if (!this.key) {
            throw new Error('Key not initialized. Call deriveKey first.');
        }
        
        const combined = this.base64ToArrayBuffer(encryptedBase64);
        
        const iv = combined.slice(0, 12);
        const encryptedData = combined.slice(12);
        
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            this.key,
            encryptedData
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);
    }
    
    /**
     * Convert ArrayBuffer to Base64 string
     * @param {Uint8Array} buffer - The buffer to convert
     * @returns {string} - Base64 encoded string
     */
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Convert Base64 string to ArrayBuffer
     * @param {string} base64 - Base64 encoded string
     * @returns {Uint8Array} - The decoded buffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}
