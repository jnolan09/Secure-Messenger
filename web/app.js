/**
 * Frontend JavaScript - Eel Integration
 * Connects HTML UI to Python backend
 */
// Track whether RSA keys have been generated
let keysGenerated = false;

// Get DOM Elements
const usernameInput = document.getElementById('username');
const recipientInput = document.getElementById('recipient');
const messageInput = document.getElementById('messageInput');
const messageDisplay = document.getElementById('messageDisplay');
const statusText = document.getElementById('statusText');
const logsModal = document.getElementById('logsModal');

/**
 * Generate RSA Keys
 * Calls Python backend to generate RSA-2048 key pairs
 */
document.getElementById('generateKeysBTN').addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const recipient = recipientInput.value.trim();
    
    if (!username || !recipient) {
        alert('Please enter both names!');
        return;
    }
    // Call Python backend through Eel
    const result = await eel.generate_keys(username, recipient)();


    if (result.success) {
        keysGenerated = true;
        // Display success message
        messageDisplay.innerHTML = `
        <div class= "message-item">
        <div class="message-header"style="color: #28a745;">Security Keys Generated!</div>
        <div class="message-text">User: ${username}</div>
        <div class="message-text">Recipient: ${recipient}</div>
        <div class="message-text">Algorithm: RSA-2048</div>
        <div class="message-status">Ready to send secure messages.</div>
        </div>
        `;
        statusText.textContent = 'Keys generated | Ready for secure messaging';
        statusText.style.color = '#28a745';
        alert(result.message);
    } else {
        alert('Error: ' + result.message);
    }
});

/**
 * Send Message Function
 * Encrypts, signs, and logs message through Python backend
 */
async function sendMessage(){
    if(!keysGenerated){
        alert('Please generate keys first!');
        return;
    }

    const message = messageInput.value.trim();
    if(!message){
        alert('Please enter a message!');
        return;
    }

    const sender = usernameInput.value.trim();
    const recipient = recipientInput.value.trim();

    const result = await eel.send_message(sender, recipient, message)();

    if(result.success){
        const time = new Date(result.timestamp).toLocaleTimeString()

        const messageHTML = `
        <div class="message-item message-sent">
            <div class="message-header">${sender} <span class="message-time">${time}</span></div>
            <div class="message-text">${result.message}</div>
            <div class="message-status">Status: Sent</div>
        </div>
        `;

        messageDisplay.innerHTML += messageHTML;
        messageDisplay.scrollTop = messageDisplay.scrollHeight;
        messageInput.value = '';
        statusText.textContent = '● Message sent securely';
        statusText.style.color = '#28a745';
    } else {
        alert('Error: ' + result.message);
    }
}

document.getElementById('sendBTN').addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
    if(e.key === 'Enter'){
        sendMessage();
    }
});

// Recieve Message
document.getElementById('receiveBTN').addEventListener('click', async () => {
    const result = await eel.receive_message()();

    if(result.success){
        const time = new Date(result.timestamp).toLocaleTimeString()

        const messageHTML = `
        <div class="message-item message-received">
            <div class="message-header">${result.sender} <span class="message-time">${time}</span></div>
            <div class="message-text">${result.message}</div>
            <div class="message-status">Status: Received</div>
        </div>
        `;

        messageDisplay.innerHTML += messageHTML;
        messageDisplay.scrollTop = messageDisplay.scrollHeight;
        statusText.textContent = '● Message received securely';
        statusText.style.color = '#28a745';
    } else {
        alert('Error: ' + result.message);
    }
});

// Clear History
document.getElementById('clearBTN').addEventListener('click', async () => {
    if(confirm('Clear all messages?')){
        await eel.clear_history()();
        messageDisplay.innerHTML = '<div class= "welcome-message">Message history cleared.</div>';
        statusText.textContent = '● Message history cleared';
        statusText.style.color = '#ffc107';
    }
});

// View Logs
document.getElementById('logsBTN').addEventListener('click', async () => {
    const logs = await eel.get_logs()();

    if(logs.length === 0){
        alert('No messages logged yet');
        return;
    }

    let logsHTML = '<div style="font-family: monospace; white-space: pre;">';
    logsHTML += '═══════════════════════════════════════════════════\n';
    logsHTML += 'SECURITY AUDIT LOG - NON-REPUDIATION EVIDENCE\n';
    logsHTML += '═══════════════════════════════════════════════════\n\n';
    logsHTML += `Total Messages Logged: ${logs.length}\n\n`; 
    logs.forEach((log, index) => {
        logsHTML += '───────────────────────────────────────────────────\n';
        logsHTML += `Message #${index + 1}\n`;
        logsHTML += '───────────────────────────────────────────────────\n';
        logsHTML += `From:      ${log.sender}\n`;
        logsHTML += `To:        ${log.recipient}\n`;
        logsHTML += `Time:      ${log.timestamp}\n`;
        logsHTML += `Hash:      ${log.message_hash.substring(0, 50)}...\n`;
        logsHTML += `Signature: ${log.signature.substring(0, 50)}...\n\n`;
    });

    logsHTML += '</div>';
    
    document.getElementById('logsContent').innerHTML = logsHTML;
    logsModal.classList.add('active');
});
// Close modal
document.querySelector('.modal-close').addEventListener('click', () => {
    logsModal.classList.remove('active');
});

logsModal.addEventListener('click', (e) => {
    if (e.target === logsModal) {
        logsModal.classList.remove('active');
    }
})
;
