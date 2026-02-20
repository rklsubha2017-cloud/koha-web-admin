import threading
import paramiko
from scp import SCPClient
import os
import time
import gzip
import shutil
import secrets
import string
import base64

def generate_psk(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

class SSHManager:
    def __init__(self, socket_emit):
        self.client = None
        self.emit_log = socket_emit
        # Ensure you generate this key: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
        self.key_path = os.path.expanduser("/home/ksg/.ssh/id_ed25519") 

    def log(self, msg, type="INFO"):
        self.emit_log('log_update', {'msg': msg, 'type': type})

    def connect(self, host, user):
        """Connects using SSH Key. No passwords allowed."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Load the private key
            if not os.path.exists(self.key_path):
                 self.log(f"❌ SSH Key missing at {self.key_path}", "ERROR")
                 return False

            k = paramiko.Ed25519Key.from_private_key_file(self.key_path)

            # Connect securely
            self.client.connect(host, username=user, pkey=k, timeout=10)
            
            self.log("🔌 Connected (Key Auth).", "WARN")
            self.emit_log('status', {'msg': 'Connected'})
            return True
        except Exception as e:
            self.log(f"Connection Error: {e}", "ERROR")
            return False

    def execute(self, cmd, stream=True):
        if not self.client: return
        self.log(f"EXEC: {cmd}", "CMD")
        
        try:
            # We add -t (get_pty=True) to ensure sudo commands don't complain about no tty
            stdin, stdout, stderr = self.client.exec_command(cmd, get_pty=True)
            
            if stream:
                for line in iter(stdout.readline, ""):
                    l = line.strip()
                    if l: self.log(l, "INFO")
            
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

    # --- RESOURCE MONITOR ---
    def get_server_stats(self):
        """Fetches lightweight server stats (RAM, Disk, Load)."""
        if not self.client: return

        data = {'ram_pct': 0, 'disk_pct': 0, 'cpu_pct': 0}

        try:
            # 1. RAM Usage (Used / Total)
            # Command returns: "2048 8192" (Used Total in MB)
            cmd_ram = "free -m | awk '/Mem:/ {print $3, $2}'"
            stdin, stdout, stderr = self.client.exec_command(cmd_ram)
            ram_raw = stdout.read().decode().strip().split()
            if len(ram_raw) == 2:
                used = int(ram_raw[0])
                total = int(ram_raw[1])
                data['ram_used'] = f"{used}MB"
                data['ram_total'] = f"{total}MB"
                data['ram_pct'] = round((used / total) * 100, 1)

            # 2. Disk Usage (Root Partition)
            # Command returns: "50% 20G 40G" (Use% Used Size)
            cmd_disk = "df -h / | awk 'NR==2 {print $5, $3, $2}'"
            stdin, stdout, stderr = self.client.exec_command(cmd_disk)
            disk_raw = stdout.read().decode().strip().split()
            if len(disk_raw) == 3:
                data['disk_pct'] = disk_raw[0].replace('%', '') # Remove % for the bar
                data['disk_used'] = disk_raw[1]
                data['disk_total'] = disk_raw[2]

            # 3. CPU Load (Load Average)
            # We use Load Average because precise CPU % requires snapshotting which is slow.
            # We fetch 1 min and 5 min load avg.
            cmd_cpu = "cat /proc/loadavg"
            stdin, stdout, stderr = self.client.exec_command(cmd_cpu)
            load = stdout.read().decode().strip().split()
            if len(load) >= 3:
                data['cpu_text'] = f"{load[0]} (1m) / {load[1]} (5m)"
                # Visualize Load: Assuming 1.0 load = ~100% core usage (rough visualization)
                data['cpu_pct'] = min(float(load[0]) * 50, 100) 

            self.emit_log('stats_update', data)
            
        except Exception as e:
            # Silent fail for stats is better than spamming logs
            pass

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
        
        for svc_name, ui_id in services.items():
            try:
                cmd = f"systemctl is-active {svc_name}"
                stdin, stdout, stderr = self.client.exec_command(cmd)
                status = stdout.read().decode().strip()
                state = "active" if status == "active" else "inactive"
                self.emit_log('health_update', {'service': ui_id, 'state': state})
            except:
                self.emit_log('health_update', {'service': ui_id, 'state': 'inactive'})

        try:
            stdin, stdout, stderr = self.client.exec_command("ps aux | grep '[s]tarman master'")
            plack_status = "active" if stdout.read().decode().strip() else "inactive"
            self.emit_log('health_update', {'service': 'plack', 'state': plack_status})
        except:
            self.emit_log('health_update', {'service': 'plack', 'state': 'inactive'})

        try:
            # Check if ANY instance has a running SIP server
            cmd = "for i in $(koha-list); do sudo koha-sip --status $i; done"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            output = stdout.read().decode().strip()
            
            if "SIP server running" in output:
                self.emit_log('health_update', {'service': 'sip2', 'state': 'active'})
            else:
                self.emit_log('health_update', {'service': 'sip2', 'state': 'inactive'})
        except:
            self.emit_log('health_update', {'service': 'sip2', 'state': 'inactive'})

        try:
            stdin, stdout, stderr = self.client.exec_command("koha-list")
            instances = stdout.read().decode().strip().split()
            self.emit_log('instance_list', {'instances': instances})
        except:
            pass

    def restart_service(self, service):
        self.log(f"🔄 Restarting {service}...", "WARN")
        
        if service == 'plack':
            self.execute("for i in $(koha-list); do sudo koha-plack --restart $i; done")
        
        # --- NEW SIP2 RESTART LOGIC ---
        elif service == 'sip2':
            # Restart SIP for every instance found on the system
            self.execute("for i in $(koha-list); do sudo koha-sip --restart $i; done")
            
        else:
            # Standard Systemd Services
            self.execute(f"sudo systemctl restart {service}")
        
        # Wait a moment for services to come up before refreshing UI
        time.sleep(2)
        self.check_health() 

    # --- DEEP INSPECTION ---
    def get_deep_stats(self, inst):
        self.log(f"🕵️ Mining details for instance: {inst}...", "INFO")
        
        data = {
            'db_name': f"koha_{inst}", 'db_user': f"koha_{inst}", 
            'db_pass': "Unknown", 'version': "Unknown",
            'stats_items': "No Data", 'stats_users': "No Data",
            'opac_port': "80", 'staff_port': "8080"
        }

        # 1. VERSION
        try:
            cmd = "dpkg -s koha-common | grep Version"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            raw = stdout.read().decode().strip()
            if ":" in raw:
                data['version'] = raw.split(":", 1)[1].strip()
            else:
                data['version'] = raw
        except: pass

        # 2. PASSWORD (Secure Grep)
        try:
            cmd = f"sudo grep '<pass>' /etc/koha/sites/{inst}/koha-conf.xml"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            
            line = stdout.read().decode().strip()
            if "<pass>" in line and "</pass>" in line:
                data['db_pass'] = line.split("<pass>")[1].split("</pass>")[0].strip()
            else:
                data['db_pass'] = "Tag Not Found"
        except Exception as e:
            data['db_pass'] = "Extraction Error"

        # 3. PORTS
        try:
            cmd = "sudo cat /etc/koha/koha-sites.conf"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            backup_conf = stdout.read().decode().strip()
            
            if backup_conf:
                for line in backup_conf.split('\n'):
                    line = line.strip()
                    if line.startswith("OPACPORT="):
                        data['opac_port'] = line.split("=")[1].strip('"\'')
                    if line.startswith("INTRAPORT="):
                        data['staff_port'] = line.split("=")[1].strip('"\'')
            else:
                self.log("⚠️ koha-sites.conf was empty or unreadable.", "WARN")

        except Exception as e:
            self.log(f"❌ Port Extraction Failed: {e}", "ERROR")

        # 4. STATS
        try:
            # Items
            q1 = "SELECT COALESCE(itemtypes.description, items.itype), COUNT(*) FROM items LEFT JOIN itemtypes ON (items.itype = itemtypes.itemtype) GROUP BY items.itype"
            cmd1 = f"sudo koha-mysql {inst} -N -e \"{q1}\""
            stdin, stdout, stderr = self.client.exec_command(cmd1)
            
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
            cmd2 = f"sudo koha-mysql {inst} -N -e \"{q2}\""
            stdin, stdout, stderr = self.client.exec_command(cmd2)
            
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
            'zebra': f"sudo koha-rebuild-zebra -v -f {inst}",
            'memcached': "echo 'flush_all' | nc localhost 11211",
            'perms': f"sudo chown -R {inst}-koha:{inst}-koha /var/lib/koha/{inst}",
            'plack': f"sudo koha-plack --restart {inst}",
            'enable_log': f"sudo koha-enable-query-log {inst}",
            'disable_log': f"sudo koha-disable-query-log {inst}"
        }
        if action in cmds: self.execute(cmds[action])

    # --- INSTALLER ---
    def install_koha(self, data):
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

        def run_step(cmd, desc):
            self.log(f"⏳ {desc}...", "INFO")
            final_cmd = cmd if cmd.startswith("sudo") or "DEBIAN_FRONTEND" in cmd else f"sudo {cmd}"
            status = self.execute(final_cmd)
            if status != 0:
                self.log(f"❌ FAILED: {desc} (Exit Code: {status})", "ERROR")
                raise Exception(f"Step failed: {desc}")

        try:
            # PHASE 1: PREREQUISITES
            run_step("sudo apt-get update", "Updating Apt Cache")
            run_step("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg lsb-release curl mariadb-server mariadb-client pwgen", "Installing Prerequisites")

            # PHASE 2: REPO SETUP
            run_step("wget -qO - https://debian.koha-community.org/koha/gpg.asc | sudo gpg --yes --dearmor -o /usr/share/keyrings/koha-keyring.gpg", "Adding Koha GPG Key")
            
            repo_list = f"deb [signed-by=/usr/share/keyrings/koha-keyring.gpg] https://debian.koha-community.org/koha {ver} main"
            run_step(f"echo '{repo_list}' | sudo tee /etc/apt/sources.list.d/koha.list", "Adding Koha Repository")
            
            run_step("sudo apt-get update", "Updating Repo Lists")
            run_step("sudo apt-get install -y koha-common", "Installing Koha Packages")

            # PHASE 3: PORTS CONFIG
            run_step("test -f /etc/koha/koha-sites.conf", "Verifying Config File Exists")
            run_step(f"sudo sed -i 's/^INTRAPORT=.*/INTRAPORT={sport}/' /etc/koha/koha-sites.conf", "Setting Staff Port")
            run_step(f"sudo sed -i 's/^OPACPORT=.*/OPACPORT={oport}/' /etc/koha/koha-sites.conf", "Setting OPAC Port")

            # PHASE 4: APACHE MODULES
            run_step("sudo a2enmod rewrite cgi deflate headers proxy_http", "Enabling Apache Modules")
            run_step("sudo systemctl restart apache2", "Restarting Apache")

            # PHASE 5: CREATE INSTANCE
            self.log(f"🏗️ Creating Instance: {name}...", "INFO")
            run_step(f"sudo koha-create --create-db {name}", f"Creating Instance '{name}'")

            # PHASE 6: AUTO-FIX CONFIG
            if do_fix:
                self.log("🔧 Applying XML Configuration Fixes...", "INFO")
                
                # Generate Key using pwgen
                try:
                    stdin, stdout, stderr = self.client.exec_command("pwgen 32 1")
                    new_key = stdout.read().decode().strip()
                except:
                    new_key = ""
                
                if not new_key: new_key = "KohaSecretKeyGeneratedByScript"
                
                conf_file = f"/etc/koha/sites/{name}/koha-conf.xml"
                run_step(f"test -f {conf_file}", "Verifying Instance Config")
                
                fixes = [
                    (f"sudo sed -i 's|<encryption_key>.*</encryption_key>|<encryption_key>{new_key}</encryption_key>|' {conf_file}", "Setting Encryption Key"),
                    (f"sudo sed -i 's|<enable_plugins>.*</enable_plugins>|<enable_plugins>1</enable_plugins>|' {conf_file}", "Enabling Plugins"),
                    (f"sudo sed -i 's|<backup_db_via_tools>.*</backup_db_via_tools>|<backup_db_via_tools>1</backup_db_via_tools>|' {conf_file}", "Enabling DB Tools Backup"),
                    (f"sudo sed -i 's|<plugins_restricted>.*</plugins_restricted>|<plugins_restricted>0</plugins_restricted>|' {conf_file}", "Disabling Plugin Restrictions")
                ]
                for cmd, desc in fixes:
                    run_step(cmd, desc)

            # PHASE 7: FINALIZE APACHE PORTS
            for port in [sport, oport]:
                run_step(f"grep -q 'Listen {port}' /etc/apache2/ports.conf || echo 'Listen {port}' | sudo tee -a /etc/apache2/ports.conf", f"Opening Port {port} in Apache")

            # PHASE 8: ENABLE SITE
            run_step(f"sudo a2ensite {name}", "Enabling VirtualHost")
            run_step(f"sudo a2dissite 000-default", "Disabling Default Site")
            run_step("sudo systemctl restart apache2", "Restarting Apache Final")

            # PHASE 9: PLACK
            if do_plack:
                run_step(f"sudo koha-plack --enable {name}", "Enabling Plack")
                run_step(f"sudo koha-plack --start {name}", "Starting Plack")
                run_step("sudo service apache2 restart", "Restarting Web Server")

            run_step("sudo systemctl restart memcached", "Restarting Memcached Service")
            run_step("sudo systemctl restart koha-common", "Restarting Koha Common Service")

            self.log(f"✅ INSTALLATION SUCCESSFUL! Instance '{name}' is ready.", "SUCCESS")
            self.check_health()

        except Exception as e:
            self.log(f"⛔ INSTALLATION ABORTED: {e}", "ERROR")

    # --- RESTORE ---
    def restore(self, inst, local_path, rebuild_zebra):
        self.log(f"🚀 Preparing restore for instance: {inst}...", "INFO")
        
        def run_step(cmd, desc):
            self.log(f"⏳ {desc}...", "INFO")
            if self.execute(cmd) != 0:
                raise Exception(f"Failed: {desc}")

        upfile = local_path
        must_delete_local = False
        
        try:
            if not local_path.endswith(".gz"):
                self.log(f"Compressing {os.path.basename(local_path)}...", "INFO")
                upfile = local_path + ".gz"
                with open(local_path, 'rb') as f_in, gzip.open(upfile, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                must_delete_local = True

            remote_gz = f"/tmp/res_{int(time.time())}.gz"
            
            self.log("🚀 Uploading Dump to Server...", "INFO")
            with SCPClient(self.client.get_transport()) as scp: 
                scp.put(upfile, remote_gz)
            
            run_step(f"gzip -d -f {remote_gz}", "Extracting SQL on Server")
            remote_sql = remote_gz.replace(".gz", "")
            
            db_cmd = f"sudo mysql -e \"DROP DATABASE IF EXISTS koha_{inst}; CREATE DATABASE koha_{inst};\""
            run_step(db_cmd, "Resetting Database")
            
            self.log("⏳ Importing SQL (This may take time)...", "INFO")
            run_step(f"sudo bash -c 'mysql koha_{inst} < {remote_sql} || exit 1'", "Importing Data")

            run_step("sudo systemctl restart memcached", "Restarting Memcached")
            run_step(f"sudo koha-upgrade-schema {inst}", "Upgrading Schema")
            
            if rebuild_zebra:
                run_step(f"sudo koha-rebuild-zebra -v -f {inst}", "Rebuilding Zebra Index")
                run_step(f"sudo koha-plack --restart {inst}", "Restarting Plack")
                
            self.execute(f"rm {remote_sql}")
            self.log("✨ RESTORE COMPLETE! Database is live.", "SUCCESS")
            self.check_health()

        except Exception as e:
            self.log(f"⛔ RESTORE FAILED: {e}", "ERROR")
            
        finally:
            if must_delete_local and os.path.exists(upfile):
                os.remove(upfile)
            if os.path.exists(local_path):
                os.remove(local_path)

    # --- BACKUP ---
    def configure_backup(self, data):
        self.log("⚙️ Setting up Cron Schedule...", "INFO")
        
        try:
            loc_scr = """#!/bin/bash
mkdir -p /home/backup/data
for I in $(koha-list); do mysqldump koha_$I | gzip > /home/backup/data/${I}_$(date +%F).sql.gz; done
find /home/backup/data -mtime +7 -delete"""

            self.execute(f"echo '{loc_scr}' | sudo tee /usr/local/bin/koha-backup.sh > /dev/null")
            self.execute("sudo chmod +x /usr/local/bin/koha-backup.sh")

            self.execute("echo '0 17 * * * root /usr/local/bin/koha-backup.sh' | sudo tee /etc/cron.d/koha-backup > /dev/null")
            self.log("✅ Local Backup Set (5:00 PM).", "SUCCESS")

            if data.get('gdrive'):
                rem = data.get('remote')
                pth = data.get('path')
                
                self.execute("if ! command -v rclone &> /dev/null; then curl https://rclone.org/install.sh | sudo bash; fi")
                
                c_scr = f"#!/bin/bash\nrclone sync /home/backup/data {rem}:{pth} --create-empty-src-dirs"
                
                self.execute(f"echo '{c_scr}' | sudo tee /usr/local/bin/gdrive.sh > /dev/null")
                self.execute("sudo chmod +x /usr/local/bin/gdrive.sh")
                self.execute("echo '30 17 * * * root /usr/local/bin/gdrive.sh' | sudo tee /etc/cron.d/gdrive > /dev/null")
                
                self.log("✅ Drive Sync Set (5:30 PM).", "SUCCESS")
                self.log("⚠️ Remember to run 'rclone config' in terminal manually if not done!", "WARN")
            else:
                self.execute("sudo rm -f /etc/cron.d/gdrive")
                self.execute("sudo rm -f /usr/local/bin/gdrive.sh")
                self.log("🚫 GDrive Sync Disabled/Removed.", "INFO")

        except Exception as e:
            self.log(f"Backup Config Failed: {e}", "ERROR")

    def run_backup_now(self):
        self.log("💾 Starting Immediate Backup...", "INFO")
        script_path = "/usr/local/bin/koha-backup.sh"
        
        if self.execute(f"test -f {script_path}") == 0:
            self.log("🚀 Executing existing backup script...", "INFO")
            if self.execute(f"sudo {script_path}") == 0:
                self.log("✅ Immediate Backup Complete! Check /home/backup/data", "SUCCESS")
            else:
                self.log("❌ Backup Script Failed.", "ERROR")
        else:
            self.log("⚠️ Script not found. Running one-off backup...", "WARN")
            cmd = "sudo mkdir -p /home/backup/data && sudo bash -c 'for I in $(koha-list); do mysqldump koha_$I | gzip > /home/backup/data/${I}_$(date +%F_manual).sql.gz; done'"
            if self.execute(cmd) == 0:
                self.log("✅ One-off Backup Complete!", "SUCCESS")
            else:
                self.log("❌ One-off Backup Failed.", "ERROR")

    # --- NETWORK ---
    def configure_firewall(self, ports, rports, rips):
        self.log("🛡️ Configuring Firewall...", "INFO")
        try:
            if ports:
                for p in ports.split(','): 
                    if p.strip(): self.execute(f"sudo ufw allow {p.strip()}")
            
            if rports and rips:
                rp_list = rports.split(',')
                rip_list = rips.split(',')
                for port in rp_list:
                    for ip in rip_list:
                        if port.strip() and ip.strip(): 
                            self.execute(f"sudo ufw allow from {ip.strip()} to any port {port.strip()}")
            
            self.execute("sudo ufw --force enable && sudo ufw reload")
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
            self.execute("sudo apt-get update && sudo apt-get install -y stunnel4 zip")
            self.execute("sudo mkdir -p /etc/stunnel")
            
            connect_ip = man_ip
            if auto_ip:
                # Get IP
                self.client.exec_command("hostname -I")
                stdin, stdout, _ = self.client.exec_command("hostname -I | awk '{print $1}'")
                connect_ip = stdout.read().decode().strip()

            l_cipher = ""
            l_secret = ""
            w_secret = ""
            file_to_zip = ""
            
            if use_psk:
                chars = string.ascii_letters + string.digits
                secret = ''.join(secrets.choice(chars) for _ in range(32))
                
                self.execute(f"echo '{name}:{secret}' | sudo tee /etc/stunnel/psk.txt > /dev/null")
                self.execute("sudo chmod 600 /etc/stunnel/psk.txt")
                
                l_cipher = "ciphers = PSK"
                l_secret = "PSKsecrets = /etc/stunnel/psk.txt"
                w_secret = "PSKsecrets = psk.txt"
                file_to_zip = "psk.txt"
                
                self.execute(f"echo '{name}:{secret}' > /tmp/psk.txt")
                
            else:
                self.execute("openssl genrsa -out key.pem 2048")
                self.execute(f"openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj '/CN={name}'")
                self.execute(f"cat key.pem cert.pem | sudo tee /etc/stunnel/{name}.pem > /dev/null")
                self.execute(f"sudo chmod 600 /etc/stunnel/{name}.pem")
                
                l_secret = f"cert = /etc/stunnel/{name}.pem"
                w_secret = f"cert = {name}.pem"
                file_to_zip = f"{name}.pem"
                self.execute(f"sudo cp /etc/stunnel/{name}.pem /tmp/")

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

            self.log("⚙️ Applying Server Config...", "INFO")
            self.execute(f"echo '{linux_conf}' | sudo tee /etc/stunnel/stunnel.conf > /dev/null")
            self.execute("sudo sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4")
            self.execute("sudo systemctl enable stunnel4 && sudo systemctl restart stunnel4")
            
            self.log("📦 Packaging Client Config...", "INFO")
            self.execute(f"echo '{win_conf}' > /tmp/stunnel.conf")
            
            zip_name = f"{name}_win.zip"
            self.execute(f"cd /tmp && zip {zip_name} stunnel.conf {file_to_zip}")
            
            # --- START OF NEW DOWNLOAD LOGIC ---
            self.log(f"📥 Pulling {zip_name} to local server...", "INFO")
            
            # Define where the file should land on YOUR machine
            local_dir = "static/downloads" # or just "downloads"
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            
            local_path = os.path.join(local_dir, zip_name)
            remote_path = f"/tmp/{zip_name}"

            # Use SCP (since you used it in SIP2) to download the file
            from scp import SCPClient
            with SCPClient(self.client.get_transport()) as scp:
                scp.get(remote_path, local_path) 
            # --- END OF NEW DOWNLOAD LOGIC ---

            self.execute(f"rm /tmp/stunnel.conf /tmp/{file_to_zip}")
            
            self.emit_log('download_ready', {'filename': zip_name})
            self.log("✅ Stunnel Ready! Downloading...", "SUCCESS")

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
            self.execute(f"sudo koha-sip --enable {inst}")
            cfg_path = f"/etc/koha/sites/{inst}/SIPconfig.xml"
            bak_path = f"{cfg_path}.bak.{int(time.time())}"
            self.log("📂 Backing up old config...", "INFO")
            self.execute(f"sudo cp {cfg_path} {bak_path} 2>/dev/null || true")
            self.execute(f"rm -f {cfg_path}")

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

            self.log("📝 Uploading new SIPconfig.xml...", "INFO")
            local_temp = "sip_temp_upload.xml"
            remote_temp = f"/tmp/sip_{inst}.xml"
            
            with open(local_temp, "w", encoding="utf-8") as f:
                f.write(xml_content)
            
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_temp, remote_temp)
            
            if os.path.exists(local_temp): os.remove(local_temp)

            self.execute(f"sudo mv {remote_temp} {cfg_path}")
            self.execute(f"sudo chmod 600 {cfg_path}")
            self.execute(f"sudo chown {inst}-koha:{inst}-koha {cfg_path}")
            self.execute(f"sudo koha-sip --restart {inst}")
            self.log("✅ SIP2 Reconfigured & Restarted.", "SUCCESS")

        except Exception as e:
            self.log(f"SIP2 Config Failed: {e}", "ERROR")

    # --- USER MANAGEMENT ---
    def fetch_user_data(self, inst):
        self.log(f"🔍 Fetching Branches & Categories for '{inst}'...", "INFO")
        
        def run_query(query):
            cmd = f"sudo koha-mysql {inst} -N -B -e \"{query}\""
            stdin, stdout, stderr = self.client.exec_command(cmd)
            raw = stdout.read().decode().strip()
            rows = []
            if not raw: return []
            
            for line in raw.split('\n'):
                line = line.strip()
                if not line or "Using password" in line or "Warning" in line: continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    rows.append({'code': parts[0], 'name': f"{parts[0]} - {parts[1]}"})
                elif len(parts) == 1:
                    rows.append({'code': parts[0], 'name': parts[0]})
            return rows

        try:
            branches = run_query("SELECT branchcode, branchname FROM branches")
            categories = run_query("SELECT categorycode, description FROM categories")
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
        cmd = f"sudo bash -c 'export PERL5LIB=/usr/share/koha/lib && export KOHA_CONF=/etc/koha/sites/{inst}/koha-conf.xml && cd /usr/share/koha/bin/devel/ && ./create_superlibrarian.pl --userid {user} --password {pwd} --branchcode {branch} --categorycode {category} --cardnumber {card}'"
        
        if self.execute(cmd) == 0:
            self.log(f"✅ Superlibrarian '{user}' Created!", "SUCCESS")
        else:
            self.log("❌ Creation Failed.", "ERROR")

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
            sql = f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{pw}'; GRANT EXECUTE ON \\`{db}\\`.* TO '{user}'@'{host}'; GRANT SELECT ON \\`{db}\\`.* TO '{user}'@'{host}'; FLUSH PRIVILEGES;"
            
            if self.execute(f"sudo mysql -e \"{sql}\"") == 0:
                self.log("✅ User Privileges Applied.", "SUCCESS")
            else:
                self.log("❌ Failed to create DB User.", "ERROR")
                return

            if local_file and os.path.exists(local_file):
                self.log("📄 Uploading SQL Object...", "INFO")
                remote_path = f"/tmp/db_obj_{int(time.time())}.sql"
                
                with SCPClient(self.client.get_transport()) as scp:
                    scp.put(local_file, remote_path)
                
                self.log("⚙️ Executing SQL Object...", "INFO")
                if self.execute(f"sudo mysql {db} < {remote_path}") == 0:
                    self.log("✅ SQL Object Imported.", "SUCCESS")
                else:
                    self.log("❌ SQL Import Failed.", "ERROR")
                
                self.execute(f"rm {remote_path}")
                os.remove(local_file)

        except Exception as e:
            self.log(f"DB Action Error: {e}", "ERROR")

    # --- MAINTENANCE ---
    def remove_instance(self, inst):
        self.log(f"🗑️ Removing instance '{inst}'...", "WARN")
        if self.execute(f"sudo koha-remove {inst}") == 0:
            self.log(f"✅ Instance '{inst}' removed.", "SUCCESS")
        else:
            self.log(f"❌ Failed to remove '{inst}'. Check logs.", "ERROR")

    def nuke_koha(self):
        self.log("☢️ Removing KOHA...", "WARN")

        try:
            # 1. Identify Instances
            self.log("🔍 Checking for running Koha instances...", "INFO")
            # We use a trick to read stdout into a variable
            stdin, stdout, stderr = self.client.exec_command("koha-list")
            instances_raw = stdout.read().decode().strip()
            instances = instances_raw.split() if instances_raw else []

            if not instances:
                self.log("⚠️ No active instances found via koha-list.", "WARN")
            else:
                self.log(f"found instances to destroy: {', '.join(instances)}", "WARN")

            # 2. Stop Services
            self.log("⏹️ Stopping koha-common service...", "INFO")
            self.execute("sudo systemctl stop koha-common")
            self.execute("sudo systemctl disable koha-common")

            # 3. Destroy Instances (DB + System Users + Apache Configs)
            for inst in instances:
                self.log(f"🚨 DESTROYING INSTANCE: {inst}", "WARN")
                
                # Drop DB and MySQL User
                # Note: We use sudo mysql to ensure root access without password
                sql = f"DROP DATABASE IF EXISTS koha_{inst}; DROP USER IF EXISTS 'koha_{inst}'@'localhost'; FLUSH PRIVILEGES;"
                self.execute(f"sudo mysql -e \"{sql}\"")
                
                # Remove System User
                self.execute(f"sudo deluser --remove-home {inst}-koha")
                
                # Remove Apache Configs
                self.log(f"🔥 Removing Apache config for {inst}...", "INFO")
                self.execute(f"sudo a2dissite {inst}")
                self.execute(f"sudo rm -f /etc/apache2/sites-available/{inst}.conf")
                self.execute(f"sudo rm -f /etc/apache2/sites-enabled/{inst}.conf")

            # 4. Purge Packages
            self.log("🧹 Purging Koha packages...", "INFO")
            self.execute("sudo apt-get purge --auto-remove koha-common -y")

            # 5. Remove Residual Files & Directories
            self.log("🗑️ Removing residual directories...", "INFO")
            dirs = [
                "/etc/koha", 
                "/var/lib/koha", 
                "/var/spool/koha", 
                "/var/lock/koha", 
                "/var/cache/koha", 
                "/var/log/koha", 
                "/var/run/koha", 
                "/usr/share/koha", 
                "/usr/share/keyrings/koha-keyring.gpg", 
                "/etc/apt/sources.list.d/koha.list"
            ]
            # Join dirs safely for the command
            dir_str = " ".join(dirs)
            self.execute(f"sudo rm -rf {dir_str}")

            # 6. Reload Apache to clear old configs
            self.log("🔄 Reloading Apache...", "INFO")
            self.execute("sudo systemctl reload apache2")

            self.log("✅ KOHA UNINSTALLATION COMPLETE. System is clean.", "SUCCESS")

        except Exception as e:
            self.log(f"❌ Nuke Protocol Failed: {e}", "ERROR")

    def run_raw(self, cmd):
        """Runs a raw command from the frontend."""
        self.log(f"⚡ RAW CMD: {cmd}", "WARN")
        self.execute(cmd)

    def run_sql(self, inst, query):
        """Runs a raw SQL query against a specific instance."""
        self.log(f"⚡ SQL ({inst}): {query}", "WARN")
        cmd = f"sudo koha-mysql {inst} -e \"{query}\""
        self.execute(cmd)

    def nuke_stunnel(self):
        self.log("⏹️ Stopping Stunnel...", "INFO")
        self.execute("sudo systemctl stop stunnel4")
        self.execute("sudo systemctl disable stunnel4")
        self.log("🧹 Removing stunnel4 package...", "INFO")
        self.execute("sudo apt purge --auto-remove stunnel4 -y")
        self.log("🗑️ Deleting Stunnel files...", "INFO")
        self.execute("sudo rm -rf /etc/stunnel /etc/default/stunnel4 /var/log/stunnel4 /var/run/stunnel4 /var/lib/stunnel4")
        self.log("✅ Stunnel4 Removed.", "SUCCESS")

    def nuke_tailscale(self):
        self.log("☢️ NUKING TAILSCALE (SCORCHED EARTH MODE)...", "WARN")
        
        # 1. The Script (Added explicit logging for debugging)
        script_content = """#!/bin/bash
# Log everything to a file so we know if it ran
LOGfile="/tmp/nuke_debug.log"
exec > >(tee -a $LOGfile) 2>&1

echo "[$(date)] STARTING NUKE PROTOCOL"

# Wait for the SSH command to return success before we cut the line
sleep 5 

echo "[$(date)] Stopping Services..."
systemctl stop tailscaled || true
systemctl disable tailscaled || true
pkill -9 tailscaled || true

echo "[$(date)] Purging Packages..."
apt-get purge tailscale tailscale-archive-keyring -y || true
dpkg --purge --force-all tailscale || true
rm -f /usr/bin/tailscale /usr/sbin/tailscaled
rm -f /etc/apt/sources.list.d/tailscale.list

echo "[$(date)] Wiping Directories..."
rm -rf /var/lib/tailscale
rm -rf /var/cache/tailscale
rm -rf /var/log/tailscale
rm -rf /home/*/.local/share/tailscale

echo "[$(date)] DONE. Goodbye."
"""
        local_temp = "nuke_payload.sh"
        remote_path = "/tmp/nuke_ts.sh"

        try:
            # STEP 1: Write file with UNIX line endings (Crucial fix for Windows devs)
            with open(local_temp, "w", encoding="utf-8", newline='\n') as f:
                f.write(script_content)

            # STEP 2: Upload
            self.log("📦 Uploading payload...", "INFO")
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_temp, remote_path)
            
            if os.path.exists(local_temp): os.remove(local_temp)

            # STEP 3: Make Executable
            self.execute(f"chmod +x {remote_path}")

            # STEP 4: DETACH COMPLETELY using systemd-run
            self.log("🧨 Detonating via Systemd...", "WARN")
            
            # This is the magic line. It creates a temporary system service.
            # It survives the SSH disconnect 100% of the time.
            cmd = f"sudo systemd-run --unit=nuke-tailscale --description='Nuke Tailscale' /bin/bash {remote_path}"
            
            if self.execute(cmd) == 0:
                self.log("✅ Nuke sequence initiated. Connection will drop in ~5s.", "SUCCESS")
            else:
                self.log("❌ Systemd failed. Trying fallback...", "ERROR")
                # Fallback to nohup if systemd isn't working
                self.execute(f"sudo nohup bash {remote_path} > /tmp/nuke_fallback.log 2>&1 &")
                self.log("⚠️ Fallback executed.", "WARN")

        except Exception as e:
            self.log(f"❌ Nuke Failed: {e}", "ERROR")
            if os.path.exists(local_temp): os.remove(local_temp)

    # --- INTERACTIVE TERMINAL ---
    def open_shell(self, cols=80, rows=24):
        """Opens a persistent interactive shell."""
        if not self.client: return False
        
        # 1. Open the Session (xterm env is crucial for nano/htop)
        try:
            self.shell = self.client.invoke_shell(term='xterm', width=cols, height=rows)
            self.shell.setblocking(0) # Non-blocking mode
            
            # 2. Start Background Reader Thread
            self.stop_shell = False
            t = threading.Thread(target=self.read_shell_output)
            t.daemon = True
            t.start()
            
            self.log("💻 Interactive Shell Opened.", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Shell Failed: {e}", "ERROR")
            return False

    def read_shell_output(self):
        """Background worker that pushes shell output to browser."""
        while not self.stop_shell and self.shell:
            try:
                if self.shell.recv_ready():
                    # Read up to 1024 bytes
                    data = self.shell.recv(1024)
                    # Emit RAW bytes (text) to frontend 'term_data' event
                    self.emit_log('term_data', {'data': data.decode('utf-8', 'ignore')})
                else:
                    time.sleep(0.01) # Prevent CPU spiking
            except Exception:
                break

    def write_to_shell(self, data):
        """Sends keystrokes from browser to server."""
        if self.shell:
            self.shell.send(data)

    def resize_shell(self, cols, rows):
        """Resizes the backend PTY to match browser window."""
        if self.shell:
            self.shell.resize_pty(width=cols, height=rows)

    def close_shell(self):
        """Closes the interactive shell and stops the background reader."""
        self.stop_shell = True  # kills the while loop in read_shell_output
        if self.shell:
            try:
                self.shell.close()
            except:
                pass
            self.shell = None
        self.log("💻 Shell Disconnected.", "WARN")

    # --- FILE MANAGER ---
    def list_dir(self, path):
        """Lists directory contents using SFTP."""
        if not self.client: return
        
        self.log(f"📂 Listing directory: {path}...", "INFO")
        try:
            sftp = self.client.open_sftp()
            
            # Handle root or empty path
            if not path or path == ".": path = "/home"
            
            # Get list of files with attributes
            attrs = sftp.listdir_attr(path)
            
            files = []
            for attr in attrs:
                # Determine type (File vs Directory)
                ftype = 'dir' if attr.st_mode & 0o40000 else 'file'
                size_str = f"{round(attr.st_size / 1024, 1)} KB" if attr.st_size < 1024*1024 else f"{round(attr.st_size / (1024*1024), 1)} MB"
                
                files.append({
                    'name': attr.filename,
                    'type': ftype,
                    'size': size_str,
                    'path': f"{path.rstrip('/')}/{attr.filename}"
                })
            
            # Sort: Directories first, then files
            files.sort(key=lambda x: (x['type'] != 'dir', x['name']))
            
            # Send back to UI
            self.emit_log('file_list', {'path': path, 'files': files})
            sftp.close()
            
        except Exception as e:
            self.log(f"List Failed: {e}", "ERROR")

    def fetch_remote_file(self, remote_path):
        """Downloads a remote file to the local Flask server for browser download."""
        self.log(f"⬇️ Fetching: {remote_path}...", "INFO")
        
        try:
            filename = os.path.basename(remote_path)
            
            # FIX: Use 'static/downloads' to match Stunnel/App logic
            local_dir = "static/downloads" 
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            
            local_path = os.path.join(local_dir, filename)
            
            # Use SCP to pull the file (Same as Stunnel)
            with SCPClient(self.client.get_transport()) as scp:
                scp.get(remote_path, local_path)
                
            self.log("✅ File staged. Starting download...", "SUCCESS")
            
            # Trigger the existing 'download_ready' listener in index.html
            self.emit_log('download_ready', {'filename': filename})
            
        except Exception as e:
            self.log(f"Download Failed: {e}", "ERROR")

    def upload_remote_file(self, local_path, remote_path):
        """Uploads a file to the current remote directory."""
        self.log(f"⬆️ Uploading to {remote_path}...", "INFO")
        try:
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_path, remote_path)
            self.log("✅ Upload Complete.", "SUCCESS")
            # Refresh directory listing
            self.list_dir(os.path.dirname(remote_path))
        except Exception as e:
            self.log(f"Upload Failed: {e}", "ERROR")

    def delete_file(self, path):
        """Deletes a file or directory safely."""
        self.log(f"🗑️ Deleting: {path}...", "WARN")
        
        # 1. Safety Block: Prevent accidental system destruction
        protected = ["/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", 
                     "/proc", "/root", "/run", "/sbin", "/sys", "/tmp", "/usr", "/var"]
        
        # Check if path is exactly a protected root folder
        if path in protected:
            self.log("❌ DELETION BLOCKED: Cannot delete system root directories.", "ERROR")
            return

        try:
            # 2. Execute Delete (rm -rf handles both files and folders)
            # We wrap path in quotes to handle spaces in filenames
            cmd = f"rm -rf \"{path}\""
            
            if self.execute(cmd) == 0:
                self.log(f"✅ Deleted: {os.path.basename(path)}", "SUCCESS")
                # 3. Refresh the view (List the parent directory)
                parent = os.path.dirname(path)
                self.list_dir(parent)
            else:
                self.log("❌ Deletion Failed", "ERROR")
        except Exception as e:
            self.log(f"Deletion Error: {e}", "ERROR")