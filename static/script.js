// --- DASHBOARD LOGIC ---

// 1. Disconnect
function disconnect() {
    if(confirm("Close SSH Session?")) {
        socket.emit('task', {name: 'disconnect'});
        document.getElementById('dash').classList.add('disabled'); // Visual feedback
    }
}

// 2. Restart Service
function restartSvc(svc) {
    runTask('restart_svc', {service: svc});
}

// 3. Handle Health Updates (Dots)
socket.on('health_update', (d) => {
    const dot = document.getElementById(`dot-${d.service}`);
    if(dot) {
        dot.className = `status-dot ${d.state}`; // active or inactive
    }
});

// 4. Populate Dropdown with Instances
socket.on('instance_list', (d) => {
    const sel = document.getElementById('inspect_inst_list');
    sel.innerHTML = "";
    d.instances.forEach(inst => {
        let opt = document.createElement('option');
        opt.value = inst;
        opt.innerText = inst;
        sel.appendChild(opt);
    });
});

// 5. Fetch Deep Stats
function fetchDeepStats() {
    const inst = document.getElementById('inspect_inst_list').value;
    runTask('deep_stats', {inst: inst});
    document.getElementById('secrets_panel').classList.remove('hidden');
}

// 6. Render Deep Stats
socket.on('deep_stats_result', (d) => {
    // Fill Text
    document.getElementById('d_dbname').innerText = d.db_name;
    document.getElementById('d_dbuser').innerText = d.db_user;
    document.getElementById('d_dbpass').innerText = d.db_pass;
    document.getElementById('d_ver').innerText = d.version;
    
    // Fill Stats
    document.getElementById('stat_items').innerText = d.stats_items;
    document.getElementById('stat_users').innerText = d.stats_users;

    // Construct Links (Using the Host IP we connected with)
    const hostIP = document.getElementById('host').value; 
    document.getElementById('link_staff').href = `http://${hostIP}:${d.staff_port}`;
    document.getElementById('link_opac').href = `http://${hostIP}:${d.opac_port}`;
    document.getElementById('link_staff').innerText = `http://${hostIP}:${d.staff_port}`;
    document.getElementById('link_opac').innerText = `http://${hostIP}:${d.opac_port}`;
});

// --- RESIZER LOGIC ---
const resizer = document.getElementById('resizer');
const root = document.documentElement;

resizer.addEventListener('mousedown', (e) => {
    e.preventDefault();
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    resizer.classList.add('resizing');
});

function handleMouseMove(e) {
    const newHeight = window.innerHeight - e.clientY;
    if (newHeight > 50 && newHeight < (window.innerHeight * 0.8)) {
        root.style.setProperty('--console-height', `${newHeight}px`);
    }
}

function handleMouseUp() {
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('mouseup', handleMouseUp);
    resizer.classList.remove('resizing');
}

// --- NEW: THEME SWITCHER ---
function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
}

// Load Saved Theme
if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark-mode');
}
