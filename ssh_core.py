import paramiko
from scp import SCPClient
import os
import time
import gzip
import shutil
import secrets
import string

def generate_psk(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

class SSHManager:
    def __init__(self, socket_emit):
        self.client = None
        self.emit_log = socket_emit

    def log(self, msg, type="INFO"):
        self.emit_log('log_update', {'msg': msg, 'type': type})

    def connect(self, host, user, password):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(host, username=user, password=password, timeout=10)
            self.password = password
            self.log("🔌 Connected.", "WARN")
            self.emit_log('status', {'msg': 'Connected'})
            return True
        except Exception as e:
            self.log(f"Connection Error: {e}", "ERROR")
            return False

    def execute(self, cmd, stream=True):
        if not self.client: return
        self.log(f"EXEC: {cmd}", "CMD")
        # Wrapper to handle sudo with password automatically
        safe_cmd = f"sudo -S -p '' bash -c '{cmd.replace("'", "'\\''")}'"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(safe_cmd, get_pty=True)
            stdin.write(f"{self.password}\n"); stdin.flush()
            
            if stream:
                for line in iter(stdout.readline, ""):
                    l = line.strip()
                    if l and l != self.password: self.log(l, "INFO")
            
            return stdout.channel.recv_exit_status()
        except Exception as e:
            self.log(f"Execution Error: {e}", "ERROR")
            return 1

    # --- DASHBOARD ACTIONS ---
    def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None
            self.log("🔌 Disconnected.", "WARN")
            self.emit_log('status', {'msg': 'Disconnected'})

    def restart_service(self, service):
        self.log(f"🔄 Restarting {service}...", "WARN")
        # 'koha-common' is the package, the service is often just 'koha-common' 
        # but for Plack we need specific koha-plack commands usually, 
        # though systemctl restart koha-common often covers it. 
        # For specific plack restart per instance, we use koha-plack --restart
        
        if service == 'plack':
            # Restart Plack for ALL instances (Ruthless approach)
            self.execute("for i in $(koha-list); do koha-plack --restart $i; done")
        else:
            self.execute(f"systemctl restart {service}")
        
        self.check_health() # Refresh status immediately

    # --- DASHBOARD & HEALTH CHECKS (RESTORED) ---
    def check_health(self):
        """Checks status of critical services and emits to dashboard."""
        if not self.client: return

        services = {
            "koha-common": "koha-common", 
            "apache2": "apache2", 
            "mariadb": "mariadb", 
            "memcached": "memcached",
            "cron": "cron"
        }
        
        # 1. Check Systemd Services
        for svc_name, ui_id in services.items():
            try:
                # Run quietly, just get exit code
                cmd = f"systemctl is-active {svc_name}"
                stdin, stdout, stderr = self.client.exec_command(cmd)
                status = stdout.read().decode().strip()
                
                state = "active" if status == "active" else "inactive"
                self.emit_log('health_update', {'service': ui_id, 'state': state})
            except:
                self.emit_log('health_update', {'service': ui_id, 'state': 'inactive'})

        # 2. Check Plack (Starman)
        try:
            stdin, stdout, stderr = self.client.exec_command("ps aux | grep '[s]tarman master'")
            plack_status = "active" if stdout.read().decode().strip() else "inactive"
            self.emit_log('health_update', {'service': 'plack', 'state': plack_status})
        except:
            self.emit_log('health_update', {'service': 'plack', 'state': 'inactive'})

        # 3. Populate Instance List
        try:
            stdin, stdout, stderr = self.client.exec_command("koha-list")
            instances = stdout.read().decode().strip().split()
            self.emit_log('instance_list', {'instances': instances})
        except:
            pass

    def restart_service(self, service):
        """Restarts a specific service."""
        self.log(f"🔄 Restarting {service}...", "WARN")
        if service == 'plack':
            # Restart Plack for ALL instances
            self.execute("for i in $(koha-list); do koha-plack --restart $i; done")
        else:
            self.execute(f"sudo -S systemctl restart {service}")
        
        time.sleep(2)
        self.check_health() # Refresh status

    # --- DEEP INSPECTION (FIXED & ROBUST) ---
    def get_deep_stats(self, inst):
        self.log(f"🕵️ Mining details for instance: {inst}...", "INFO")
        
        # Initialize Defaults
        data = {
            'db_name': f"koha_{inst}", 'db_user': f"koha_{inst}", 
            'db_pass': "Unknown", 'version': "Unknown",
            'stats_items': "No Data", 'stats_users': "No Data",
            'opac_port': "80", 'staff_port': "8080"
        }

        # 1. VERSION (Working Fine)
        try:
            cmd = "dpkg -s koha-common | grep Version"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            raw = stdout.read().decode().strip()
            if ":" in raw:
                data['version'] = raw.split(":", 1)[1].strip()
            else:
                data['version'] = raw
        except: pass

        # 2. PASSWORD (Updated: Grep Strategy)
        # We use grep to pull ONLY the password line. 
        # This avoids buffer errors from reading the whole file.
        try:
            cmd = f"sudo -S -p '' grep '<pass>' /etc/koha/sites/{inst}/koha-conf.xml"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdin.write(f"{self.password}\n"); stdin.flush()
            
            # Result is just one line: " <pass>YOUR_PASSWORD</pass>"
            line = stdout.read().decode().strip()
            
            # Simple, Robust Parsing
            if "<pass>" in line and "</pass>" in line:
                data['db_pass'] = line.split("<pass>")[1].split("</pass>")[0].strip()
            else:
                data['db_pass'] = "Tag Not Found"
                
        except Exception as e:
            data['db_pass'] = "Extraction Error"

        # 3. PORTS (Working Fine)
        try:
            # 1. Use sudo to ensure we can actually read the file
            cmd = "sudo -S -p '' cat /etc/koha/koha-sites.conf"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            
            # 2. Send password for sudo
            stdin.write(f"{self.password}\n")
            stdin.flush()
            
            # 3. Read Output
            backup_conf = stdout.read().decode().strip()
            
            # 4. Parse line by line
            if backup_conf:
                for line in backup_conf.split('\n'):
                    line = line.strip()
                    # We check startswith to avoid matching comments or partial words
                    if line.startswith("OPACPORT="):
                        data['opac_port'] = line.split("=")[1].strip('"\'')
                    if line.startswith("INTRAPORT="):
                        data['staff_port'] = line.split("=")[1].strip('"\'')
            else:
                # Optional: Log if file was empty so you know why it failed
                self.log("⚠️ koha-sites.conf was empty or unreadable.", "WARN")

        except Exception as e:
            # Log the actual error instead of silently passing
            self.log(f"❌ Port Extraction Failed: {e}", "ERROR")

        # 4. STATS (Working Fine - Native koha-mysql)
        try:
            # Items
            q1 = "SELECT COALESCE(itemtypes.description, items.itype), COUNT(*) FROM items LEFT JOIN itemtypes ON (items.itype = itemtypes.itemtype) GROUP BY items.itype"
            cmd1 = f"sudo -S -p '' koha-mysql {inst} -N -e \"{q1}\""
            stdin, stdout, stderr = self.client.exec_command(cmd1)
            stdin.write(f"{self.password}\n"); stdin.flush()
            
            res = stdout.read().decode().strip()
            fmt = ""
            if res:
                for line in res.split('\n'):
                    if "Using password" in line or "Warning" in line: continue
                    p = line.split('\t')
                    if len(p) >= 2: fmt += f"{p[0]}: {p[1]}\n"
                    else: fmt += f"{line}\n"
            data['stats_items'] = fmt if fmt else "0 Items"

            # Patrons
            q2 = "SELECT COALESCE(categories.description, borrowers.categorycode), COUNT(*) FROM borrowers LEFT JOIN categories ON (borrowers.categorycode = categories.categorycode) GROUP BY borrowers.categorycode"
            cmd2 = f"sudo -S -p '' koha-mysql {inst} -N -e \"{q2}\""
            stdin, stdout, stderr = self.client.exec_command(cmd2)
            stdin.write(f"{self.password}\n"); stdin.flush()
            
            res_u = stdout.read().decode().strip()
            fmt_u = ""
            if res_u:
                for line in res_u.split('\n'):
                    if "Using password" in line or "Warning" in line: continue
                    p = line.split('\t')
                    if len(p) >= 2: fmt_u += f"{p[0]}: {p[1]}\n"
                    else: fmt_u += f"{line}\n"
            data['stats_users'] = fmt_u if fmt_u else "0 Patrons"
            
        except Exception as e:
            data['stats_items'] = "SQL Error"
            data['stats_users'] = str(e)

        self.emit_log('deep_stats_result', data)
        self.log("✅ Data Extraction Complete", "SUCCESS")


    # --- TOOLBOX ---
    def toolbox_action(self, action, inst):
        cmds = {
            'zebra': f"koha-rebuild-zebra -v -f {inst}",
            'memcached': "echo 'flush_all' | nc localhost 11211",
            'perms': f"chown -R {inst}-koha:{inst}-koha /var/lib/koha/{inst}",
            'plack': f"koha-plack --restart {inst}",
            'enable_log': f"koha-enable-query-log {inst}",
            'disable_log': f"koha-disable-query-log {inst}"
        }
        if action in cmds: self.execute(cmds[action])

    # --- INSTALLER ---
    def install_koha(self, data):
        # 1. Extract inputs matching your Tkinter variables
        ver = data.get('ver')
        name = data.get('name')
        sport = data.get('sport')
        oport = data.get('oport')
        do_plack = data.get('plack')
        do_fix = data.get('fix')

        if not all([ver, name, sport, oport]):
            self.log("❌ Missing required fields!", "ERROR")
            return

        self.log(f"🚀 Starting Validated Installation for '{name}'...", "WARN")

        # 2. Define the 'exec_check' helper to match your desktop logic
        # This ensures we STOP immediately if any step fails (Exit Code != 0)
        def run_step(cmd, desc):
            self.log(f"⏳ {desc}...", "INFO")
            status = self.execute(cmd)
            if status != 0:
                self.log(f"❌ FAILED: {desc} (Exit Code: {status})", "ERROR")
                raise Exception(f"Step failed: {desc}")

        try:
            # --- PHASE 1: PREREQUISITES ---
            run_step("apt-get update", "Updating Apt Cache")
            run_step("DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg lsb-release curl mariadb-server mariadb-client pwgen", "Installing Prerequisites")

            # --- PHASE 2: REPO SETUP ---
            run_step("wget -qO - https://debian.koha-community.org/koha/gpg.asc | gpg --yes --dearmor -o /usr/share/keyrings/koha-keyring.gpg", "Adding Koha GPG Key")
            
            repo_list = f"deb [signed-by=/usr/share/keyrings/koha-keyring.gpg] https://debian.koha-community.org/koha {ver} main"
            run_step(f"echo '{repo_list}' > /etc/apt/sources.list.d/koha.list", "Adding Koha Repository")
            
            run_step("apt-get update", "Updating Repo Lists")
            run_step("apt-get install -y koha-common", "Installing Koha Packages")

            # --- PHASE 3: PORTS CONFIG ---
            run_step("test -f /etc/koha/koha-sites.conf", "Verifying Config File Exists")
            run_step(f"sed -i 's/^INTRAPORT=.*/INTRAPORT={sport}/' /etc/koha/koha-sites.conf", "Setting Staff Port")
            run_step(f"sed -i 's/^OPACPORT=.*/OPACPORT={oport}/' /etc/koha/koha-sites.conf", "Setting OPAC Port")

            # --- PHASE 4: APACHE MODULES ---
            run_step("a2enmod rewrite cgi deflate headers proxy_http", "Enabling Apache Modules")
            run_step("systemctl restart apache2", "Restarting Apache")

            # --- PHASE 5: CREATE INSTANCE ---
            self.log(f"🏗️ Creating Instance: {name}...", "INFO")
            # We use --create-db as per your script
            run_step(f"koha-create --create-db {name}", f"Creating Instance '{name}'")

            # --- PHASE 6: AUTO-FIX CONFIG (The "Special Sauce") ---
            if do_fix:
                self.log("🔧 Applying XML Configuration Fixes...", "INFO")
                
                # 6a. Generate Key using pwgen (Manual Capture)
                # We can't use run_step here because we need the output string
                try:
                    stdin, stdout, stderr = self.client.exec_command("pwgen 32 1")
                    new_key = stdout.read().decode().strip()
                except:
                    new_key = ""
                
                if not new_key: 
                    new_key = "KohaSecretKeyGeneratedByScript" # Fallback
                
                conf_file = f"/etc/koha/sites/{name}/koha-conf.xml"
                run_step(f"test -f {conf_file}", "Verifying Instance Config")
                
                # 6b. Apply the specific sed commands from your logic
                fixes = [
                    (f"sed -i 's|<encryption_key>.*</encryption_key>|<encryption_key>{new_key}</encryption_key>|' {conf_file}", "Setting Encryption Key"),
                    (f"sed -i 's|<enable_plugins>.*</enable_plugins>|<enable_plugins>1</enable_plugins>|' {conf_file}", "Enabling Plugins"),
                    (f"sed -i 's|<backup_db_via_tools>.*</backup_db_via_tools>|<backup_db_via_tools>1</backup_db_via_tools>|' {conf_file}", "Enabling DB Tools Backup"),
                    (f"sed -i 's|<plugins_restricted>.*</plugins_restricted>|<plugins_restricted>0</plugins_restricted>|' {conf_file}", "Disabling Plugin Restrictions")
                ]
                for cmd, desc in fixes:
                    run_step(cmd, desc)

            # --- PHASE 7: FINALIZE APACHE PORTS ---
            # Checks if Listen directive exists, if not appends it
            for port in [sport, oport]:
                run_step(f"grep -q 'Listen {port}' /etc/apache2/ports.conf || echo 'Listen {port}' >> /etc/apache2/ports.conf", f"Opening Port {port} in Apache")

            # --- PHASE 8: ENABLE SITE ---
            run_step(f"a2ensite {name}", "Enabling VirtualHost")
            run_step("systemctl restart apache2", "Restarting Apache Final")

            # --- PHASE 9: PLACK ---
            if do_plack:
                run_step(f"koha-plack --enable {name}", "Enabling Plack")
                run_step(f"koha-plack --start {name}", "Starting Plack")
                run_step("service apache2 restart", "Restarting Web Server")

            #-- Restart Services ---
            run_step("systemctl restart memcached", "Restarting Memcached Service")
            run_step("systemctl restart koha-common", "Restarting Koha Common Service")

            self.log(f"✅ INSTALLATION SUCCESSFUL! Instance '{name}' is ready.", "SUCCESS")
            # Refresh dashboard instance list
            self.check_health()

        except Exception as e:
            self.log(f"⛔ INSTALLATION ABORTED: {e}", "ERROR")

    # --- RESTORE ---
    def restore(self, inst, local_path, rebuild_zebra):
        self.log(f"🚀 Preparing restore for instance: {inst}...", "INFO")
        
        # Helper to stop if a command fails
        def run_step(cmd, desc):
            self.log(f"⏳ {desc}...", "INFO")
            if self.execute(cmd) != 0:
                raise Exception(f"Failed: {desc}")

        upfile = local_path
        must_delete_local = False
        
        try:
            # 1. COMPRESSION LOGIC (Matches your Tkinter _ui_restore)
            # If file is not .gz, compress it first to save bandwidth
            if not local_path.endswith(".gz"):
                self.log(f"Compressing {os.path.basename(local_path)}...", "INFO")
                upfile = local_path + ".gz"
                # Compressing the file received from Flask to a temp .gz
                with open(local_path, 'rb') as f_in, gzip.open(upfile, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                must_delete_local = True

            remote_gz = f"/tmp/res_{int(time.time())}.gz"
            
            # 2. UPLOAD
            self.log("🚀 Uploading Dump to Server...", "INFO")
            with SCPClient(self.client.get_transport()) as scp: 
                scp.put(upfile, remote_gz)
            
            # 3. EXTRACTION
            # -f forces overwrite
            run_step(f"gzip -d -f {remote_gz}", "Extracting SQL on Server")
            remote_sql = remote_gz.replace(".gz", "")
            
            # 4. DATABASE RESET (Exact Syntax from your code)
            # Drops and Recreates DB with correct charset
            db_cmd = f"mysql -e \"DROP DATABASE IF EXISTS koha_{inst}; CREATE DATABASE koha_{inst} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\""
            run_step(db_cmd, "Resetting Database")
            
            # 5. IMPORT
            self.log("⏳ Importing SQL (This may take time)...", "INFO")
            # We use bash -c to ensure the '|| exit 1' logic works as intended
            run_step(f"bash -c 'mysql koha_{inst} < {remote_sql} || exit 1'", "Importing Data")

            # 6. Memcached restart
            run_step("systemctl restart memcached", "Restarting Memcached")
            
            # 7. POST-IMPORT UPGRADES
            run_step(f"koha-upgrade-schema {inst}", "Upgrading Schema")
            
            # 8. ZEBRA & PLACK (Conditional)
            if rebuild_zebra:
                run_step(f"koha-rebuild-zebra -v -f {inst}", "Rebuilding Zebra Index")
                run_step(f"koha-plack --restart {inst}", "Restarting Plack")
                
            # 8. CLEANUP REMOTE
            self.execute(f"rm {remote_sql}")
            self.log("✨ RESTORE COMPLETE! Database is live.", "SUCCESS")
            
            # Refresh dashboard to show new stats if any
            self.check_health()

        except Exception as e:
            self.log(f"⛔ RESTORE FAILED: {e}", "ERROR")
            
        finally:
            # 9. CLEANUP LOCAL
            # Only delete the temp .gz we created. 
            # We also clean up the original upload from Flask to keep /tmp clean.
            if must_delete_local and os.path.exists(upfile):
                os.remove(upfile)
            if os.path.exists(local_path):
                os.remove(local_path)

    # --- BACKUP ---
    def configure_backup(self, data):
        self.log("⚙️ Setting up Cron Schedule...", "INFO")
        
        try:
            # 1. Define Local Backup Script
            loc_scr = """#!/bin/bash
mkdir -p /home/backup/data
for I in $(koha-list); do mysqldump koha_$I | gzip > /home/backup/data/${I}_$(date +%F).sql.gz; done
find /home/backup/data -mtime +7 -delete"""

            # 2. Write Script (Using TEE to bypass sudo redirect limits)
            self.execute(f"echo '{loc_scr}' | sudo tee /usr/local/bin/koha-backup.sh > /dev/null")
            self.execute("chmod +x /usr/local/bin/koha-backup.sh")

            # 3. Write Cron Job (5 PM)
            self.execute("echo '0 17 * * * root /usr/local/bin/koha-backup.sh' | sudo tee /etc/cron.d/koha-backup > /dev/null")
            self.log("✅ Local Backup Set (5:00 PM).", "SUCCESS")

            # 4. Configure Google Drive (Optional)
            if data.get('gdrive'):
                rem = data.get('remote')
                pth = data.get('path')
                
                # Install Rclone if missing
                self.execute("if ! command -v rclone &> /dev/null; then curl https://rclone.org/install.sh | sudo bash; fi")
                
                # Define GDrive Script
                c_scr = f"#!/bin/bash\nrclone sync /home/backup/data {rem}:{pth} --create-empty-src-dirs"
                
                # Write Script
                self.execute(f"echo '{c_scr}' | sudo tee /usr/local/bin/gdrive.sh > /dev/null")
                self.execute("chmod +x /usr/local/bin/gdrive.sh")
                
                # Write Cron (5:30 PM)
                self.execute("echo '30 17 * * * root /usr/local/bin/gdrive.sh' | sudo tee /etc/cron.d/gdrive > /dev/null")
                
                self.log("✅ Drive Sync Set (5:30 PM).", "SUCCESS")
                self.log("⚠️ Remember to run 'rclone config' in terminal manually if not done!", "WARN")
            else:
                # Cleanup if disabled
                self.execute("rm -f /etc/cron.d/gdrive")
                self.execute("rm -f /usr/local/bin/gdrive.sh")
                self.log("🚫 GDrive Sync Disabled/Removed.", "INFO")

        except Exception as e:
            self.log(f"Backup Config Failed: {e}", "ERROR")

    def run_backup_now(self):
        """Runs the backup script immediately."""
        self.log("💾 Starting Immediate Backup...", "INFO")
        
        # Check if script exists, if not, create it on the fly or run commands directly
        # For robustness, we'll try running the script we expect to be there, 
        # or fallback to running the raw commands.
        script_path = "/usr/local/bin/koha-backup.sh"
        
        # Check existence
        check = self.execute(f"test -f {script_path}")
        
        if check == 0:
            self.log("🚀 Executing existing backup script...", "INFO")
            if self.execute(f"sudo {script_path}") == 0:
                self.log("✅ Immediate Backup Complete! Check /home/backup/data", "SUCCESS")
            else:
                self.log("❌ Backup Script Failed.", "ERROR")
        else:
            self.log("⚠️ Script not found. Running one-off backup...", "WARN")
            cmd = "mkdir -p /home/backup/data && for I in $(koha-list); do mysqldump koha_$I | gzip > /home/backup/data/${I}_$(date +%F_manual).sql.gz; done"
            if self.execute(cmd) == 0:
                self.log("✅ One-off Backup Complete!", "SUCCESS")
            else:
                self.log("❌ One-off Backup Failed.", "ERROR")

    # --- NETWORK (UFW & Stunnel) ---
    def configure_firewall(self, ports, rports, rips):
        self.log("🛡️ Configuring Firewall...", "INFO")
        try:
            # 1. Global Ports
            if ports:
                for p in ports.split(','): 
                    if p.strip(): self.execute(f"ufw allow {p.strip()}")
            
            # 2. Restricted Ports (IP Specific)
            # Matches logic: ufw allow from IP to any port PORT
            if rports and rips:
                rp_list = rports.split(',')
                rip_list = rips.split(',')
                for port in rp_list:
                    for ip in rip_list:
                        if port.strip() and ip.strip(): 
                            self.execute(f"ufw allow from {ip.strip()} to any port {port.strip()}")
            
            self.execute("ufw --force enable && ufw reload")
            self.log("✅ Firewall Rules Applied.", "SUCCESS")
        except Exception as e:
            self.log(f"Firewall Error: {e}", "ERROR")

    def setup_stunnel(self, data):
        name = data.get('name')
        use_psk = data.get('psk')
        auto_ip = data.get('auto')
        man_ip = data.get('man')

        if not name: 
            self.log("❌ Cert Name is required!", "ERROR")
            return

        self.log(f"🔒 Starting Stunnel Gen ({name})...", "INFO")
        
        try:
            # 1. Install Deps
            self.execute("apt-get update && apt-get install -y stunnel4 zip")
            self.execute("mkdir -p /etc/stunnel")
            
            # 2. Determine Connect IP (for Windows Config)
            connect_ip = man_ip
            if auto_ip:
                # Get first IP address of the server
                self.client.exec_command("hostname -I") # Flush buffer
                stdin, stdout, _ = self.client.exec_command("hostname -I | awk '{print $1}'")
                connect_ip = stdout.read().decode().strip()

            # 3. Generate Keys/Secrets & Config Bodies
            linux_conf = ""
            win_conf = ""
            file_to_zip = ""
            
            # Common Headers
            l_cipher = ""
            l_secret = ""
            w_secret = ""
            
            if use_psk:
                self.log("🔑 Generating PSK...", "INFO")
                # Generate random 32 char string
                chars = string.ascii_letters + string.digits
                secret = ''.join(secrets.choice(chars) for _ in range(32))
                
                # Write PSK on Server
                self.execute(f"echo '{name}:{secret}' > /etc/stunnel/psk.txt")
                self.execute("chmod 600 /etc/stunnel/psk.txt")
                
                l_cipher = "ciphers = PSK"
                l_secret = "PSKsecrets = /etc/stunnel/psk.txt"
                w_secret = "PSKsecrets = psk.txt"
                file_to_zip = "psk.txt"
                
                # Copy PSK to temp for zipping
                self.execute(f"echo '{name}:{secret}' > /tmp/psk.txt")
                
            else:
                self.log("📜 Generating Self-Signed Cert...", "INFO")
                self.execute("openssl genrsa -out key.pem 2048")
                self.execute(f"openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj '/CN={name}'")
                self.execute(f"cat key.pem cert.pem > /etc/stunnel/{name}.pem")
                self.execute(f"chmod 600 /etc/stunnel/{name}.pem")
                
                l_secret = f"cert = /etc/stunnel/{name}.pem"
                w_secret = f"cert = {name}.pem"
                file_to_zip = f"{name}.pem"
                
                # Copy PEM to temp for zipping
                self.execute(f"cp /etc/stunnel/{name}.pem /tmp/")

            # 4. Build Configurations (The 3-Port Logic)
            # Port Mapping: 
            # 8051 -> 8023 (Telnet)
            # 8052 -> 6001 (SIP Raw)
            # 8053 -> 3306 (MySQL)
            
            # Linux (Server Side)
            linux_conf = f"""pid = /var/run/stunnel4/stunnel.pid
output = /var/log/stunnel4/stunnel.log
client = no
sslVersion = TLSv1.2
[{name}-8023]
accept = 8051
connect = 127.0.0.1:8023
{l_cipher}
{l_secret}
[{name}-6001]
accept = 8052
connect = 127.0.0.1:6001
{l_cipher}
{l_secret}
[{name}-3306]
accept = 8053
connect = 127.0.0.1:3306
{l_cipher}
{l_secret}
"""

            # Windows (Client Side) - Connects TO the IP we found earlier
            win_conf = f"""client = yes
sslVersion = TLSv1.2
{l_cipher}
{w_secret}
[{name}-8023]
accept = 127.0.0.1:8023
connect = {connect_ip}:8051
[{name}-6001]
accept = 127.0.0.1:6001
connect = {connect_ip}:8052
[{name}-3306]
accept = 127.0.0.1:3306
connect = {connect_ip}:8053
"""

            # 5. Apply Linux Config
            self.log("⚙️ Applying Server Config...", "INFO")
            # We use base64 to avoid escaping hell when writing complex multiline strings
            # But for simplicity here, we'll write line by line or use a safe echo
            self.execute(f"echo '{linux_conf}' > /etc/stunnel/stunnel.conf")
            
            self.execute("sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4")
            self.execute("systemctl enable stunnel4 && systemctl restart stunnel4")
            
            # 6. Package Windows Zip
            self.log("📦 Packaging Client Config...", "INFO")
            self.execute(f"echo '{win_conf}' > /tmp/stunnel.conf")
            
            zip_name = f"{name}_win.zip"
            # Zip the conf and the secret file (psk.txt or name.pem)
            self.execute(f"cd /tmp && zip {zip_name} stunnel.conf {file_to_zip}")
            
            # 7. Cleanup Temp
            self.execute(f"rm /tmp/stunnel.conf /tmp/{file_to_zip}")
            
            # 8. Trigger Download
            self.log("✅ Stunnel Ready! Downloading...", "SUCCESS")
            
            # Tell Frontend to download this file
            self.emit_log('download_ready', {'filename': zip_name})

        except Exception as e:
            self.log(f"Stunnel Failed: {e}", "ERROR")

    # --- SIP2 ---
    def configure_sip2(self, data):
        inst = data.get('inst')
        user = data.get('user')
        pwd = data.get('pass')
        telnet = data.get('telnet')
        raw = data.get('raw')
        iid = data.get('iid')

        if not all([inst, user, pwd, telnet, raw, iid]):
            self.log("❌ Missing required SIP2 fields!", "ERROR")
            return

        self.log(f"⚙️ Configuring SIP2 for {inst}...", "INFO")

        try:
            # 1. Enable SIP on Instance
            self.execute(f"koha-sip --enable {inst}")

            # 2. Backup Existing Config
            cfg_path = f"/etc/koha/sites/{inst}/SIPconfig.xml"
            bak_path = f"{cfg_path}.bak.{int(time.time())}"
            self.log("📂 Backing up old config...", "INFO")
            # Ignore error if file doesn't exist
            self.execute(f"cp {cfg_path} {bak_path} 2>/dev/null || true")
            self.execute(f"rm -f {cfg_path}")

            # 3. Generate Robust XML (Matches Desktop Logic)
            xml_content = f"""<acsconfig xmlns="http://openncip.org/acs-config/1.0/">
  <error-detect enabled="true" />
  <server-params min_servers='10' min_spare_servers='5' />
  <listeners>
    <service port="127.0.0.1:{telnet}/tcp/IPv4" transport="telnet" protocol="SIP/2.00" timeout="60" />
    <service port="127.0.0.1:{raw}/tcp/IPv4" transport="RAW" protocol="SIP/2.00" client_timeout="600" timeout="60" />
  </listeners>
  <accounts>
    <login id="{user}" password="{pwd}" delimiter="|" error-detect="enabled" institution="{iid}" encoding="ascii" checked_in_ok="0" />
  </accounts>
  <institutions>
    <institution id="{iid}" implementation="ILS" parms="">
      <policy checkin="true" renewal="true" checkout="true" status_update="false" offline="false" timeout="100" retries="5" />
    </institution>
  </institutions>
</acsconfig>"""

            # 4. Upload Logic
            self.log("📝 Uploading new SIPconfig.xml...", "INFO")
            local_temp = "sip_temp_upload.xml"
            remote_temp = f"/tmp/sip_{inst}.xml"
            
            # Write locally (on Flask server)
            with open(local_temp, "w", encoding="utf-8") as f:
                f.write(xml_content)
            
            # SCP to Remote Server
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_temp, remote_temp)
            
            # Cleanup Local
            if os.path.exists(local_temp): os.remove(local_temp)

            # 5. Move & Permissions
            # We use sudo for these operations
            self.execute(f"mv {remote_temp} {cfg_path}")
            self.execute(f"chmod 600 {cfg_path}")
            self.execute(f"chown {inst}-koha:{inst}-koha {cfg_path}")

            # 6. Restart
            self.execute(f"koha-sip --restart {inst}")
            self.log("✅ SIP2 Reconfigured & Restarted.", "SUCCESS")

        except Exception as e:
            self.log(f"SIP2 Config Failed: {e}", "ERROR")

    # --- USER MANAGEMENT ---
    def fetch_user_data(self, inst):
        """Fetches branches and categories for dropdowns."""
        self.log(f"🔍 Fetching Branches & Categories for '{inst}'...", "INFO")
        
        # Helper to run SQL using the robust koha-mysql wrapper
        def run_query(query):
            # -N: No column headers
            # -B: Batch mode (tab-separated)
            # -e: Execute query
            cmd = f"sudo -S -p '' koha-mysql {inst} -N -B -e \"{query}\""
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdin.write(f"{self.password}\n"); stdin.flush()
            
            raw = stdout.read().decode().strip()
            # We don't strictly check stderr here because mysql warnings often go there
            
            rows = []
            if not raw: return []
            
            for line in raw.split('\n'):
                line = line.strip()
                # Filter out common noise/warnings that break parsing
                if not line or "Using password" in line or "Warning" in line: continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    rows.append({'code': parts[0], 'name': f"{parts[0]} - {parts[1]}"})
                elif len(parts) == 1:
                    # Fallback if description is missing
                    rows.append({'code': parts[0], 'name': parts[0]})
            return rows

        try:
            branches = run_query("SELECT branchcode, branchname FROM branches")
            categories = run_query("SELECT categorycode, description FROM categories")
            
            # Emit data back to frontend
            self.emit_log('user_data_ready', {'branches': branches, 'categories': categories})
            
            if branches or categories:
                self.log(f"✅ Loaded {len(branches)} branches, {len(categories)} categories.", "SUCCESS")
            else:
                self.log("⚠️ No data found. (Is the instance name correct?)", "WARN")
        
        except Exception as e:
            self.log(f"Fetch Failed: {e}", "ERROR")
            self.emit_log('user_data_ready', {'branches': [], 'categories': []})

    def create_superlibrarian(self, data):
        inst = data.get('inst')
        user = data.get('user')
        pwd = data.get('pass')
        branch = data.get('branch')
        category = data.get('category')
        card = data.get('card')

        if not all([inst, user, pwd, branch, category, card]):
            self.log("❌ Missing User Details", "ERROR")
            return

        self.log(f"🦸 Creating Superlibrarian '{user}'...", "INFO")
        
        # Perl script execution with environment variables
        cmd = f"export PERL5LIB=/usr/share/koha/lib && export KOHA_CONF=/etc/koha/sites/{inst}/koha-conf.xml && cd /usr/share/koha/bin/devel/ && ./create_superlibrarian.pl --userid {user} --password {pwd} --branchcode {branch} --categorycode {category} --cardnumber {card}"
        
        if self.execute(cmd) == 0:
            self.log(f"✅ Superlibrarian '{user}' Created!", "SUCCESS")
        else:
            self.log("❌ Creation Failed. Check logs (Cardnumber must be unique).", "ERROR")

    def create_mysql_user(self, data):
        db = data.get('dbname')
        user = data.get('dbuser')
        pw = data.get('dbpass')
        host = data.get('host', '%')
        local_file = data.get('sql_file')

        if not all([db, user, pw]):
            self.log("❌ Missing DB Credentials", "ERROR")
            return

        self.log(f"🗄️ Creating MySQL User '{user}'@'{host}'...", "INFO")
        
        try:
            # 1. Create User & Grants
            sql = f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{pw}'; GRANT EXECUTE ON \\`{db}\\`.* TO '{user}'@'{host}'; GRANT SELECT ON \\`{db}\\`.* TO '{user}'@'{host}'; FLUSH PRIVILEGES;"
            
            if self.execute(f"mysql -e \"{sql}\"") == 0:
                self.log("✅ User Privileges Applied.", "SUCCESS")
            else:
                self.log("❌ Failed to create DB User.", "ERROR")
                return

            # 2. Import SQL File (Optional)
            if local_file and os.path.exists(local_file):
                self.log("📄 Uploading SQL Object...", "INFO")
                remote_path = f"/tmp/db_obj_{int(time.time())}.sql"
                
                with SCPClient(self.client.get_transport()) as scp:
                    scp.put(local_file, remote_path)
                
                self.log("⚙️ Executing SQL Object...", "INFO")
                if self.execute(f"mysql {db} < {remote_path}") == 0:
                    self.log("✅ SQL Object Imported.", "SUCCESS")
                else:
                    self.log("❌ SQL Import Failed.", "ERROR")
                
                self.execute(f"rm {remote_path}")
                os.remove(local_file)

        except Exception as e:
            self.log(f"DB Action Error: {e}", "ERROR")

    # --- MAINTENANCE & NUKE ---
    def remove_instance(self, inst):
        self.log(f"🗑️ Removing instance '{inst}'...", "WARN")
        # koha-remove does a decent job, but we'll wrap it to catch errors
        if self.execute(f"koha-remove {inst}") == 0:
            self.log(f"✅ Instance '{inst}' removed.", "SUCCESS")
        else:
            self.log(f"❌ Failed to remove '{inst}'. Check logs.", "ERROR")

    def nuke_stunnel(self):
        self.log("⏹️ Stopping and disabling stunnel4 service...", "INFO")
        self.execute("systemctl stop stunnel4")
        self.execute("systemctl disable stunnel4")
        
        self.log("🧹 Removing stunnel4 package...", "INFO")
        self.execute("apt purge --auto-remove stunnel4 -y")
        
        self.log("🗑️ Deleting Stunnel files...", "INFO")
        self.execute("rm -rf /etc/stunnel /etc/default/stunnel4 /var/log/stunnel4 /var/run/stunnel4 /var/lib/stunnel4")
        
        # Cleanup users/groups
        self.execute("deluser --remove-home stunnel4")
        self.execute("delgroup stunnel4")
        
        self.log("✅ Stunnel4 completely removed from the system.", "SUCCESS")

    def nuke_tailscale(self):
        self.log("☢️ NUKING TAILSCALE (SCORCHED EARTH MODE)...", "WARN")
        
        # 1. Create a "Scorched Earth" cleanup script
        # explicitly targeting the leftover files you found
        script_content = """#!/bin/bash
sleep 5

echo "1. Stopping Services..."
tailscale logout || true
systemctl stop tailscaled || true
systemctl disable tailscaled || true
pkill -9 tailscaled || true

echo "2. Purging Packages..."
apt-get purge tailscale tailscale-archive-keyring -y || true
# Force remove from dpkg database if apt missed it
dpkg --purge --force-all tailscale || true
dpkg --purge --force-all tailscale-archive-keyring || true

echo "3. removing Binaries & Configs..."
rm -f /usr/bin/tailscale
rm -f /usr/sbin/tailscaled
rm -f /etc/default/tailscaled
rm -f /etc/apt/sources.list.d/tailscale.list
rm -f /usr/share/keyrings/tailscale-archive-keyring.gpg

echo "4. Cleaning Systemd Units..."
rm -f /etc/systemd/system/multi-user.target.wants/tailscaled.service
rm -f /usr/lib/systemd/system/tailscaled.service
rm -f /var/lib/systemd/deb-systemd-helper-enabled/tailscaled*
rm -rf /var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants/tailscaled*

echo "5. Wiping Data Directories..."
rm -rf /var/lib/tailscale
rm -rf /var/cache/tailscale
rm -rf /var/log/tailscale
rm -rf /run/tailscale
rm -rf /home/*/.local/share/tailscale

echo "6. Cleaning Apt Cache & Lists..."
rm -f /var/cache/apt/archives/tailscale*
rm -f /var/lib/apt/lists/pkgs.tailscale.com*

echo "7. Cleaning Dpkg Metadata..."
rm -f /var/lib/dpkg/info/tailscale*

echo "8. Reloading Daemon..."
systemctl daemon-reload
echo "DONE."
"""
        
        try:
            # 2. Write the script to /tmp/nuke_ts.sh
            self.execute(f"echo '{script_content}' > /tmp/nuke_ts.sh")
            self.execute("chmod +x /tmp/nuke_ts.sh")
            
            self.log("💣 Cleanup script uploaded. Detonating...", "WARN")
            
            # 3. Execute blindly in background
            # We use nohup so it survives the connection drop
            cmd = "nohup bash /tmp/nuke_ts.sh > /dev/null 2>&1 &"
            
            # Send command blindly
            full_cmd = f"sudo -S -p '' bash -c \"{cmd}\""
            stdin, stdout, stderr = self.client.exec_command(full_cmd)
            stdin.write(f"{self.password}\n")
            stdin.flush()
            
            self.log("👋 Total Nuke sent. Connection will close in ~5 seconds.", "SUCCESS")
            
        except Exception as e:
            self.log(f"Nuke Failed: {e}", "ERROR")
