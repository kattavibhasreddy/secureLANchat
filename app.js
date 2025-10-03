/**
 * Chat application client
 * Handles WebSocket connection, encryption, and UI updates
 */

let ws = null;
let crypto = new CryptoHelper();
let username = '';

const loginScreen = document.getElementById('loginScreen');
const chatScreen = document.getElementById('chatScreen');
const statusDiv = document.getElementById('status');
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('messageInput');
const usernameInput = document.getElementById('usernameInput');
const passwordInput = document.getElementById('passwordInput');
const loginError = document.getElementById('loginError');

/**
 * Connect to the WebSocket server
 */
async function connect() {
    username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    
    if (!username) {
        loginError.textContent = 'Please enter a username';
        return;
    }
    
    if (!password) {
        loginError.textContent = 'Please enter a password';
        return;
    }
    
    loginError.textContent = '';
    
    try {
        await crypto.deriveKey(password);
        
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsHost = window.location.hostname;
        const wsPort = 8001;
        
        ws = new WebSocket(`${wsProtocol}//${wsHost}:${wsPort}`);
        
        ws.onopen = () => {
            console.log('Connected to server');
            statusDiv.textContent = `Connected as ${username}`;
            statusDiv.className = 'status connected';
            loginScreen.style.display = 'none';
            chatScreen.classList.add('active');
            messageInput.focus();
        };
        
        ws.onmessage = async (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === 'message') {
                    const decryptedMessage = await crypto.decrypt(data.encrypted);
                    displayMessage(decryptedMessage, false);
                }
            } catch (error) {
                console.error('Error processing message:', error);
                displaySystemMessage('Error: Failed to decrypt message. Check password.');
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            loginError.textContent = 'Connection error. Please try again.';
        };
        
        ws.onclose = () => {
            console.log('Disconnected from server');
            statusDiv.textContent = 'Disconnected';
            statusDiv.className = 'status disconnected';
            displaySystemMessage('Disconnected from server');
        };
        
    } catch (error) {
        console.error('Connection error:', error);
        loginError.textContent = 'Failed to connect. Please try again.';
    }
}

/**
 * Send a message
 */
async function sendMessage() {
    const message = messageInput.value.trim();
    
    if (!message) return;
    
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        displaySystemMessage('Not connected to server');
        return;
    }
    
    try {
        const formattedMessage = `[${username}] ${message}`;
        const encrypted = await crypto.encrypt(formattedMessage);
        
        ws.send(JSON.stringify({
            type: 'message',
            encrypted: encrypted
        }));
        
        displayMessage(formattedMessage, true);
        messageInput.value = '';
        
    } catch (error) {
        console.error('Error sending message:', error);
        displaySystemMessage('Error sending message');
    }
}

/**
 * Display a chat message
 * @param {string} message - The message to display
 * @param {boolean} isOwn - Whether this is the user's own message
 */
function displayMessage(message, isOwn) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isOwn ? 'own' : ''}`;
    
    const match = message.match(/^\[(.+?)\] (.+)$/);
    if (match) {
        const [, user, text] = match;
        messageDiv.innerHTML = `
            <div class="username">${escapeHtml(user)}</div>
            <div class="text">${escapeHtml(text)}</div>
        `;
    } else {
        messageDiv.innerHTML = `<div class="text">${escapeHtml(message)}</div>`;
    }
    
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

/**
 * Display a system message
 * @param {string} message - The system message to display
 */
function displaySystemMessage(message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    messageDiv.innerHTML = `<div class="text" style="background: #f8d7da; color: #721c24;">${escapeHtml(message)}</div>`;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

/**
 * Handle Enter key press in message input
 * @param {KeyboardEvent} event - The keyboard event
 */
function handleKeyPress(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

usernameInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        passwordInput.focus();
    }
});

passwordInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        connect();
    }
});
