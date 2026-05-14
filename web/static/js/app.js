document.addEventListener('DOMContentLoaded', () => {
    // Check if logged in
    checkSession();

    // Create toast container
    const toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
});

let allEntries = [];

// Toast Notifications
function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (isError) toast.style.borderLeftColor = 'var(--danger)';
    toast.textContent = message;
    
    document.querySelector('.toast-container').appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('hide');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Authentication
function switchAuthTab(mode) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    document.getElementById('auth-mode').value = mode;
    document.getElementById('auth-submit-btn').textContent = mode === 'login' ? 'Login' : 'Register';
    document.getElementById('auth-error').textContent = '';
}

async function handleAuth(event) {
    event.preventDefault();
    const mode = document.getElementById('auth-mode').value;
    const username = document.getElementById('username').value;
    const master_password = document.getElementById('master_password').value;
    const errorEl = document.getElementById('auth-error');
    
    try {
        const res = await fetch(`/api/${mode}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, master_password })
        });
        
        const data = await res.json();
        
        if (!res.ok) {
            throw new Error(data.detail || 'Authentication failed');
        }
        
        showToast(data.message);
        checkSession(); // Switch view
    } catch (err) {
        errorEl.textContent = err.message;
    }
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/';
    } catch (err) {
        console.error(err);
    }
}

async function checkSession() {
    try {
        const res = await fetch('/api/session');
        if (res.ok) {
            const data = await res.json();
            document.getElementById('current-user').textContent = data.username;
            
            if (data.is_locked) {
                showView('unlock-view');
            } else {
                showView('app-view');
                loadEntries();
            }
        } else {
            showView('auth-view');
        }
    } catch (err) {
        showView('auth-view');
    }
}

async function handleUnlock(event) {
    event.preventDefault();
    const master_password = document.getElementById('unlock_password').value;
    const errorEl = document.getElementById('unlock-error');
    
    try {
        const res = await fetch('/api/vault/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password })
        });
        
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to unlock vault');
        
        showToast('Vault unlocked');
        document.getElementById('unlock_password').value = '';
        checkSession();
    } catch (err) {
        errorEl.textContent = err.message;
    }
}

// Views
function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
    document.body.classList.toggle('auth-active', viewId === 'auth-view');
}

// Modals
function openModal(id) {
    document.getElementById(id).classList.add('active');
}
function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    document.getElementById('add-form').reset();
    document.getElementById('add-error').textContent = '';
}

// Toggle Password
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Entries
async function loadEntries() {
    try {
        const res = await fetch('/api/entries');
        if (res.ok) {
            allEntries = await res.json();
            renderEntries(allEntries);
        } else if (res.status === 401) {
            showView('auth-view');
        }
    } catch (err) {
        showToast('Failed to load entries', true);
    }
}

function renderEntries(entries) {
    const grid = document.getElementById('entries-list');
    grid.innerHTML = '';
    
    if (entries.length === 0) {
        grid.innerHTML = '<p style="color: var(--text-muted); grid-column: 1/-1; text-align: center;">No entries found. Add your first password!</p>';
        return;
    }
    
    entries.forEach(entry => {
        const card = document.createElement('div');
        card.className = 'entry-card glass';
        card.innerHTML = `
            <div class="entry-header">
                <div class="entry-title">${escapeHTML(entry.name)}</div>
            </div>
            <div class="entry-username">${escapeHTML(entry.username)}</div>
            <div class="entry-actions">
                <button class="action-btn" onclick="copyPassword('${escapeHTML(entry.password)}')">Copy Pass</button>
                <button class="action-btn danger" onclick="deleteEntry('${escapeHTML(entry.name)}')">Delete</button>
            </div>
        `;
        grid.appendChild(card);
    });
}

function filterEntries() {
    const query = document.getElementById('search-input').value.toLowerCase();
    const filtered = allEntries.filter(e => 
        e.name.toLowerCase().includes(query) || 
        e.username.toLowerCase().includes(query)
    );
    renderEntries(filtered);
}

async function handleAddEntry(event) {
    event.preventDefault();
    const name = document.getElementById('entry-name').value;
    const username = document.getElementById('entry-username').value;
    const password = document.getElementById('entry-password').value;
    const notes = document.getElementById('entry-notes').value;
    const errorEl = document.getElementById('add-error');
    
    try {
        const res = await fetch('/api/entries', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, username, password, notes })
        });
        
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to add entry');
        
        showToast('Entry added successfully');
        closeModal('add-modal');
        loadEntries();
    } catch (err) {
        errorEl.textContent = err.message;
    }
}

async function deleteEntry(name) {
    if (!confirm(`Are you sure you want to delete '${name}'?`)) return;
    
    try {
        const res = await fetch(`/api/entries/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (res.ok) {
            showToast('Entry deleted');
            loadEntries();
        } else {
            showToast('Failed to delete entry', true);
        }
    } catch (err) {
        showToast('Failed to delete entry', true);
    }
}

async function copyPassword(password) {
    try {
        await navigator.clipboard.writeText(password);
        showToast('Password copied to clipboard!');
        
        // Auto-clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText('');
            showToast('Clipboard auto-cleared');
        }, 30000);
    } catch (err) {
        showToast('Failed to copy password', true);
    }
}

function escapeHTML(str) {
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
}

// FEATURE: Secure Password Generator
function generatePassword() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    let password = "";
    const array = new Uint32Array(16);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 16; i++) {
        password += chars[array[i] % chars.length];
    }
    const input = document.getElementById('entry-password');
    input.value = password;
    input.type = 'text'; // Show it to the user
    checkPasswordStrength(password);
}

// FEATURE: Password Strength Meter
let strengthTimeout;
async function checkPasswordStrength(password) {
    clearTimeout(strengthTimeout);
    const bar = document.getElementById('strength-bar');
    const text = document.getElementById('strength-text');
    
    if (!password) {
        bar.style.width = '0%';
        text.textContent = '';
        return;
    }

    // Debounce API call
    strengthTimeout = setTimeout(async () => {
        try {
            const res = await fetch('/api/vault/check-strength', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await res.json();
            
            // Map score 0-4 to width and colors
            const colors = ['#ef4444', '#ef4444', '#f59e0b', '#3b82f6', '#10b981'];
            bar.style.width = ((data.score + 1) * 20) + '%';
            bar.style.backgroundColor = colors[data.score];
            text.textContent = data.feedback || (data.score > 2 ? 'Strong password!' : 'Weak password');
            text.style.color = colors[data.score];
        } catch (err) {}
    }, 300);
}

// FEATURE: Secure Export
function exportVault() {
    window.open('/api/vault/export', '_blank');
}

// FEATURE: Auto-Lock Idle Timer
let idleTimeout;
function resetIdleTimer() {
    clearTimeout(idleTimeout);
    // 5 minutes
    idleTimeout = setTimeout(() => {
        const isAppViewActive = document.getElementById('app-view').classList.contains('active');
        if (isAppViewActive) {
            logout();
            showToast('Vault auto-locked due to inactivity', true);
        }
    }, 300000);
}
['mousemove', 'mousedown', 'keypress', 'touchstart'].forEach(evt => 
    document.addEventListener(evt, resetIdleTimer)
);
resetIdleTimer();
