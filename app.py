import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, jsonify, send_from_directory, after_this_request
from flask_socketio import SocketIO, emit, disconnect
from ssh_core import SSHManager
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'koha_cyber_secret'
app.config['UPLOAD_FOLDER'] = '/tmp'
socketio = SocketIO(app, async_mode='eventlet', ping_timeout=300, ping_interval=25)

# --- MULTI-SESSION STORAGE ---
# Replaces the old global 'ssh = ...'
# Format: { 'socket_id_user_A': <SSHManager Object>, 'socket_id_user_B': <SSHManager Object> }
active_sessions = {}

def get_ssh():
    """Helper to get the SSH connection for the current user."""
    return active_sessions.get(request.sid)

@app.route('/')
def index(): 
    return render_template('index.html')

# --- CONNECTION HANDLERS ---

@socketio.on('connect')
def on_connect():
    pass

@socketio.on('disconnect')
def on_disconnect():
    """Clean up the specific user's connection on tab close."""
    if request.sid in active_sessions:
        # Only disconnect this specific user's SSH
        active_sessions[request.sid].disconnect()
        del active_sessions[request.sid]

@socketio.on('connect_ssh')
def handle_conn(data):
    sid = request.sid
    
    # Create a "Scoped Emitter" so logs go ONLY to this user
    def scoped_emit(event, payload):
        socketio.emit(event, payload, room=sid)

    # Instantiate a NEW Manager for this specific user
    new_ssh = SSHManager(scoped_emit)
    
    # Attempt connection
    if new_ssh.connect(data['host'], data['user']):
        active_sessions[sid] = new_ssh
        emit('status', {'msg': 'Connected'})
    else:
        emit('status', {'msg': 'Failed'})

# --- TASK ROUTING ---

@socketio.on('task')
def handle_task(data):
    # 1. Retrieve THIS user's SSH session
    ssh = get_ssh()
    
    # 2. Safety Check: Is the user actually connected?
    if not ssh:
        emit('log_update', {'msg': '❌ Session expired or not connected.', 'type': 'ERROR'})
        return

    task = data.get('name')
    args = data.get('args', {})
    
    # 3. Execute Task
    if task == 'health': 
        ssh.check_health()
        
    elif task == 'restart_svc':
        ssh.restart_service(args['service'])
        
    elif task == 'deep_stats': 
        socketio.start_background_task(ssh.get_deep_stats, args['inst'])

    elif task == 'disconnect':
        ssh.disconnect()
        if request.sid in active_sessions:
            del active_sessions[request.sid]

    elif task == 'raw': 
        ssh.run_raw(args['cmd'])
        
    elif task == 'sql': 
        ssh.run_sql(args['inst'], args['query'])
        
    elif task == 'toolbox': 
        ssh.toolbox_action(args['action'], args['inst'])
        
    elif task == 'install': 
        socketio.start_background_task(ssh.install_koha, args)
        
    elif task == 'backup_now': 
        socketio.start_background_task(ssh.run_backup_now)

    elif task == 'backup_config': 
        ssh.configure_backup(args)
        
    elif task == 'ufw': 
        ssh.configure_firewall(args['ports'], args['rports'], args['rips'])
        
    elif task == 'stunnel': 
        socketio.start_background_task(ssh.setup_stunnel, args)
        
    elif task == 'sip2': 
        ssh.configure_sip2(args)
    
    elif task == 'fetch_user_data':
        ssh.fetch_user_data(args['inst'])

    elif task == 'create_super':
        socketio.start_background_task(ssh.create_superlibrarian, args)
        
    elif task == 'rm_inst': 
        socketio.start_background_task(ssh.remove_instance, args['inst'])
        
    elif task == 'rm_stunnel':
        socketio.start_background_task(ssh.nuke_stunnel)
        
    elif task == 'rm_koha': 
        socketio.start_background_task(ssh.nuke_koha)
        
    elif task == 'rm_tailscale': 
        socketio.start_background_task(ssh.nuke_tailscale)

    elif task == 'server_stats':
        ssh.get_server_stats()

    # Inside handle_task(data):
    elif task == 'ls':
        # Default to /home/user if no path provided
        path = args.get('path', '/home')
        ssh.list_dir(path)
        
    elif task == 'get_file':
        socketio.start_background_task(ssh.fetch_remote_file, args.get('path'))

    elif task == 'put_file':
        # This is triggered AFTER the HTTP upload (Phase 2)
        ssh.upload_remote_file(args.get('local_path'), args.get('remote_path'))

    elif task == 'rm_file':
        ssh.delete_file(args.get('path'))

# Add this new Upload Route for the File Manager
@app.route('/upload-fm', methods=['POST'])
def uploadFM():
    if 'file' not in request.files: return jsonify({'status': 'error'})
    f = request.files['file']
    path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
    f.save(path)
    # Return local path so socket can push it via SCP
    return jsonify({'status': 'uploaded', 'local_path': path, 'filename': f.filename})

# --- UPLOAD & EXECUTE HANDLERS (Decoupled) ---

@app.route('/upload-db', methods=['POST'])
def uploadDb():
    """Phase 1: Just save the file."""
    if 'file' not in request.files: return jsonify({'status': 'error'})
    f = request.files['file']
    path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
    f.save(path)
    # Return path to frontend so it can trigger Phase 2
    return jsonify({'status': 'uploaded', 'path': path})

@socketio.on('start_restore')
def handle_restore_trigger(data):
    """Phase 2: Execute Restore using the User's SSH Session."""
    ssh = get_ssh()
    if not ssh: return
    
    socketio.start_background_task(
        ssh.restore, 
        data['inst'], 
        data['path'], 
        data['zebra']
    )

@app.route('/upload-sp', methods=['POST'])
def uploadSp():
    """Phase 1: Just save the file (for DB Users)."""
    path = ""
    if 'file' in request.files:
        f = request.files['file']
        if f.filename != '':
            path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            f.save(path)
    return jsonify({'status': 'uploaded', 'path': path})

@socketio.on('start_db_user')
def handle_db_user_trigger(data):
    """Phase 2: Execute DB User Creation."""
    ssh = get_ssh()
    if not ssh: return
    socketio.start_background_task(ssh.create_mysql_user, data)

@app.route('/download/<filename>')
def download_stunnel_zip(filename):
    directory = os.path.join(os.getcwd(), 'static/downloads')
    file_path = os.path.join(directory, filename)

    # Schedule file deletion to happen AFTER the response is sent
    @after_this_request
    def remove_file(response):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error removing file: {e}")
        return response

    return send_from_directory(directory, filename, as_attachment=True)

# --- TERMINAL SOCKET HANDLERS ---

@socketio.on('start_terminal')
def handle_term_start(data):
    ssh = get_ssh()
    if ssh:
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        ssh.open_shell(cols, rows)

@socketio.on('term_input')
def handle_term_input(payload):
    ssh = get_ssh()
    if ssh:
        ssh.write_to_shell(payload)

@socketio.on('resize_term')
def handle_term_resize(data):
    ssh = get_ssh()
    if ssh:
        ssh.resize_shell(data['cols'], data['rows'])

@socketio.on('disconnect_terminal')
def handle_term_disconnect():
    ssh = get_ssh()
    if ssh:
        ssh.close_shell()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')