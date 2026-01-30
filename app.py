import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from ssh_core import SSHManager
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'koha_cyber_secret'
app.config['UPLOAD_FOLDER'] = '/tmp'
socketio = SocketIO(app, async_mode='eventlet', ping_timeout=300, ping_interval=25)

# Singleton SSH manager
ssh = SSHManager(socketio.emit)

@app.route('/')
def index(): return render_template('index.html')

@socketio.on('connect_ssh')
def handle_conn(data):
    if ssh.connect(data['host'], data['user'], data['pass']):
        emit('status', {'msg': 'Connected'})
    else:
        emit('status', {'msg': 'Failed'})

@socketio.on('task')
def handle_task(data):
    task = data.get('name')
    args = data.get('args', {})
    
    # --- ROUTING TABLE ---
    if task == 'health': 
        ssh.check_health()
        
    elif task == 'restart_svc':
        # FIX: Connects the restart button to the backend logic
        ssh.restart_service(args['service'])
        
    elif task == 'deep_stats': 
        # FIX: Connects the "Fetch Secrets" button to the backend logic
        socketio.start_background_task(ssh.get_deep_stats, args['inst'])

    elif task == 'disconnect':
        ssh.disconnect()

    elif task == 'raw': 
        ssh.run_raw(args['cmd'])
        
    elif task == 'sql': 
        ssh.run_sql(args['inst'], args['query'])
        
    elif task == 'toolbox': 
        ssh.toolbox_action(args['action'], args['inst'])
        
    elif task == 'install': 
        socketio.start_background_task(ssh.install_koha, args)
        
    elif task == 'backup_now': 
        # Trigger immediate backup in background
        socketio.start_background_task(ssh.run_backup_now)

    elif task == 'backup_config': 
        # Apply the cron configuration
        ssh.configure_backup(args)
        
    elif task == 'ufw': 
        ssh.configure_firewall(args['ports'], args['rports'], args['rips'])
        
    elif task == 'stunnel': 
        socketio.start_background_task(ssh.setup_stunnel, args)
        
    elif task == 'sip2': 
        ssh.configure_sip2(args)
    
    elif task == 'fetch_user_data':
        # No background task needed, it's fast
        ssh.fetch_user_data(args['inst'])

    elif task == 'create_super':
        socketio.start_background_task(ssh.create_superlibrarian, args)
        
    elif task == 'rm_inst': 
        # Background task for safety
        socketio.start_background_task(ssh.remove_instance, args['inst'])
        
    elif task == 'rm_stunnel':
        socketio.start_background_task(ssh.nuke_stunnel)
        
    elif task == 'rm_koha': 
        socketio.start_background_task(ssh.nuke_koha)
        
    elif task == 'rm_tailscale': 
        socketio.start_background_task(ssh.nuke_tailscale)

@app.route('/upload-db', methods=['POST'])
def uploadDb():
    f = request.files['file']
    path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
    f.save(path)
    
    task_type = request.form['type']
    if task_type == 'restore':
        inst = request.form['inst']
        # FIX: Capture the checkbox value (passed as string 'true'/'false' from JS)
        zebra_raw = request.form.get('zebra', 'true')
        rebuild_zebra = zebra_raw.lower() == 'true'
        
        socketio.start_background_task(ssh.restore, inst, path, rebuild_zebra)
    
    return jsonify({'status': 'ok'})

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory('/tmp', filename, as_attachment=True)

@app.route('/upload-sp', methods=['POST'])
def uploadSp():
    task_type = request.form['type']
    
    # Existing Restore Logic
    if task_type == 'restore':
        f = request.files['file']
        path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(path)
        inst = request.form['inst']
        zebra_raw = request.form.get('zebra', 'true')
        rebuild_zebra = zebra_raw.lower() == 'true'
        socketio.start_background_task(ssh.restore, inst, path, rebuild_zebra)
    
    # NEW: MySQL User Logic
    elif task_type == 'db_user':
        # File is optional here
        file_path = None
        if 'file' in request.files:
            f = request.files['file']
            if f.filename != '':
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
                f.save(file_path)
        
        # Gather text args
        data = {
            'dbname': request.form['dbname'],
            'host': request.form['host'],
            'dbuser': request.form['dbuser'],
            'dbpass': request.form['dbpass'],
            'sql_file': file_path
        }
        socketio.start_background_task(ssh.create_mysql_user, data)

    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')
