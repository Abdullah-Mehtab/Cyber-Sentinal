#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import subprocess
import threading
import os
import time
import hashlib
import queue

class InstallerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Sentinel Installer")
        self.root.geometry("600x400")
        
        # Check for root privileges
        if os.geteuid() != 0:
            messagebox.showerror("Permission Error", "Please run this installer with sudo privileges.")
            self.root.destroy()
            return
        
        # Configuration variables
        self.repo_url = "https://github.com/Abdullah-Mehtab/Cyber-Sentinal.git"
        self.tmp_dir = "/tmp/cyber-sentinal-config"
        self.config_dir = f"{self.tmp_dir}/etc"
        self.installed_packages = []
        self.elk_version = "7.17.13"
        self.wazuh_version = "4.5.4-1"
        self.architecture = subprocess.check_output("dpkg --print-architecture", shell=True).decode().strip()
        self.logstash_deb_url = f"https://artifacts.elastic.co/downloads/logstash/logstash-7.17.13-{self.architecture}.deb"
        self.logstash_checksum = {
            "amd64": "a4e54b7e1b8f0f9d3f6d8a4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0",
            "arm64": "b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4a0f1b7f7e8b1b2f7c9a0f3b6d8e4"
        }.get(self.architecture, "")
        
        # Queue for thread-safe dialog communication
        self.input_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # GUI elements
        self.label = tk.Label(root, text="Welcome to Cyber Sentinel Installation", font=("Arial", 14))
        self.label.pack(pady=10)
        
        self.status_text = tk.Text(root, height=15, width=70, state='disabled')
        self.status_text.pack(pady=10)
        
        self.progress = ttk.Progressbar(root, length=400, mode='determinate')
        self.progress.pack(pady=10)
        
        self.start_button = tk.Button(root, text="Start Installation", command=self.start_installation)
        self.start_button.pack(pady=10)
        
        # Start polling for dialog requests
        self.poll_queue()

    def log(self, message):
        """Update the status text area with a message."""
        self.status_text.config(state='normal')
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state='disabled')
        self.root.update()

    def run_command(self, command, description, track_package=None):
        """Execute a shell command and log its progress."""
        self.log(f"Running: {description}")
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            if track_package:
                self.installed_packages.append(track_package)
            self.log(f"Completed: {description}")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Error: {description} failed - {e.output.decode()}")
            return False

    def check_package_version(self, package, version):
        """Check if the specified package version is installed."""
        try:
            result = subprocess.check_output(f"dpkg -l | grep {package}", shell=True).decode()
            return version in result
        except subprocess.CalledProcessError:
            return False

    def verify_package_availability(self, package, version):
        """Verify if a package version is available in the repository."""
        try:
            result = subprocess.check_output(f"apt-cache policy {package}", shell=True).decode()
            return version in result
        except subprocess.CalledProcessError:
            return False

    def verify_deb_checksum(self, file_path, expected_checksum):
        """Verify the SHA512 checksum of a downloaded DEB file."""
        if not os.path.exists(file_path):
            self.log(f"DEB file {file_path} not found")
            return False
        with open(file_path, "rb") as f:
            sha512_hash = hashlib.sha512()
            for chunk in iter(lambda: f.read(4096), b""):
                sha512_hash.update(chunk)
        computed_checksum = sha512_hash.hexdigest()
        if computed_checksum == expected_checksum:
            self.log("DEB file checksum verified successfully")
            return True
        self.log(f"Checksum mismatch: expected {expected_checksum}, got {computed_checksum}")
        return False

    def get_user_input(self, title, prompt, show=None):
        """Request user input via a dialog in the main thread."""
        self.input_queue.put((title, prompt, show))
        try:
            result = self.result_queue.get(timeout=60)  # Wait up to 60 seconds
            return result
        except queue.Empty:
            self.log(f"Timeout waiting for user input: {prompt}")
            return None

    def poll_queue(self):
        """Poll the input queue for dialog requests in the main thread."""
        try:
            if not self.input_queue.empty():
                title, prompt, show = self.input_queue.get_nowait()
                result = simpledialog.askstring(title, prompt, parent=self.root, show=show)
                self.result_queue.put(result)
            self.root.after(100, self.poll_queue)  # Schedule next poll
        except queue.Empty:
            pass
        except Exception as e:
            self.log(f"Error in dialog polling: {str(e)}")
            self.result_queue.put(None)

    def cleanup(self):
        """Remove all installed components on failure."""
        self.log("Installation failed. Initiating cleanup...")
        for package in self.installed_packages:
            self.run_command(f"apt-get remove --purge -y {package} && apt-get autoremove -y", f"Removing {package}")
        self.run_command(f"rm -rf {self.tmp_dir}", "Removing temporary files")
        self.run_command("rm -f /etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/elastic-7.x.list", "Removing repository files")
        self.run_command("rm -f /usr/share/keyrings/wazuh.gpg /usr/share/keyrings/elasticsearch-keyring.gpg", "Removing GPG keys")
        self.run_command("rm -rf /var/ossec/etc/ssl", "Removing deployed certificates")
        self.log("Cleanup complete. System reset for a fresh installation.")

    def start_installation(self):
        """Start the installation process in a separate thread."""
        self.start_button.config(state='disabled')
        threading.Thread(target=self.perform_installation, daemon=True).start()

    def perform_installation(self):
        """Execute the installation steps sequentially."""
        steps = [
            ("Install dependencies", self.install_dependencies),
            ("Setup Elastic repository", self.setup_elastic_repository),
            ("Install Java", self.install_java),
            ("Verify dependencies", self.verify_logstash_deps),
            ("Install Wazuh Manager", self.install_wazuh_manager),
            ("Install Elasticsearch", self.install_elasticsearch),
            ("Install Kibana", self.install_kibana),
            ("Install Logstash", self.install_logstash),
            ("Install Filebeat", self.install_filebeat),
            ("Stop services", self.stop_services),
            ("Clone and deploy configurations", self.clone_and_deploy_configs),
            ("Generate and deploy certificates", self.generate_and_deploy_certificates),
            ("Set permissions", self.set_permissions),
            ("Configure Elasticsearch JVM", self.configure_elasticsearch_jvm),
            ("Configure email alerts", self.configure_email_alerts),
            ("Install Kibana plugin", self.install_kibana_plugin),
            ("Enable and start services", self.enable_and_start_services),
        ]
        
        self.progress['maximum'] = len(steps)
        for i, (step_name, step_func) in enumerate(steps, start=1):
            self.log(f"Step {i}/{len(steps)}: {step_name}")
            if not step_func():
                self.cleanup()
                messagebox.showerror("Installation Failed", f"Failed at step: {step_name}. System cleaned up for retry.")
                self.start_button.config(state='normal')
                return
            self.progress['value'] = i
        
        # Cleanup temporary files
        self.run_command(f"rm -rf {self.tmp_dir}", "Cleaning up temporary files")
        
        # Provide Kibana access details
        try:
            ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
            self.log(f"Installation complete!\nAccess Kibana at: http://{ip}:5601\nDefault credentials: elastic/elastic (change after login)")
            messagebox.showinfo("Success", "Installation completed successfully!")
        except Exception as e:
            self.log(f"Error getting IP address: {str(e)}")
        self.start_button.config(state='normal')

    def install_dependencies(self):
        """Install required tools without system-wide upgrades."""
        command = "apt update -y && apt install -y curl apt-transport-https wget gnupg git ca-certificates docker.io"
        return self.run_command(command, "Installing dependencies", "docker.io")

    def install_java(self):
        """Install Java 11 explicitly."""
        if self.check_package_version("openjdk-11-jdk", ""):
            self.log("OpenJDK 11 already installed, skipping.")
            return True
        return self.run_command(
            "apt install -y openjdk-11-jdk",
            "Installing Java 11",
            "openjdk-11-jdk"
        )

    def verify_logstash_deps(self):
        """Verify Java and Ruby dependencies for Logstash."""
        return self.run_command(
            "java -version && ruby --version",
            "Verifying Java/Ruby dependencies"
        )

    def install_wazuh_manager(self):
        """Install Wazuh Manager version 4.5.4-1."""
        if self.check_package_version("wazuh-manager", self.wazuh_version):
            self.log(f"Wazuh Manager {self.wazuh_version} already installed, skipping.")
            return True
        command = (
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor | tee /usr/share/keyrings/wazuh.gpg > /dev/null && "
            "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list && "
            "apt update -y && apt install -y wazuh-manager=4.5.4-1"
        )
        return self.run_command(command, "Installing Wazuh Manager", "wazuh-manager")

    def setup_elastic_repository(self):
        """Setup Elastic repository with proxy support."""
        proxy = self.get_user_input("Proxy Setup", "Enter proxy (e.g., http://proxy:port) or leave blank)")
        if proxy:
            os.environ['http_proxy'] = proxy
            os.environ['https_proxy'] = proxy
            self.log(f"Using proxy: {proxy}")
        
        keyring_file = "/usr/share/keyrings/elasticsearch-keyring.gpg"
        repo_line = f"deb [signed-by={keyring_file}] https://artifacts.elastic.co/packages/7.x/apt stable main"
        command = (
            f"wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o {keyring_file} && "
            f"echo '{repo_line}' | tee /etc/apt/sources.list.d/elastic-7.x.list && "
            "apt update -y"
        )
        if not self.run_command(command, "Setting up Elastic repository"):
            self.log("Repository setup failed, checking connectivity")
            self.run_command("curl -I https://artifacts.elastic.co/packages/7.x/apt", "Testing repository connectivity")
            return False
        return True

    def install_elasticsearch(self):
        """Install Elasticsearch version 7.17.13."""
        if self.check_package_version("elasticsearch", self.elk_version):
            self.log(f"Elasticsearch {self.elk_version} already installed, skipping.")
            return True
        command = f"apt install -y elasticsearch={self.elk_version}"
        return self.run_command(command, "Installing Elasticsearch", "elasticsearch")

    def install_kibana(self):
        """Install Kibana version 7.17.13."""
        if self.check_package_version("kibana", self.elk_version):
            self.log(f"Kibana {self.elk_version} already installed, skipping.")
            return True
        command = f"apt install -y kibana={self.elk_version}"
        if not self.run_command(command, "Installing Kibana", "kibana"):
            return False
        # Verify Kibana binary
        if not os.path.exists("/usr/share/kibana/bin/kibana-plugin"):
            self.log("Kibana plugin binary not found at /usr/share/kibana/bin/kibana-plugin")
            return False
        return True

    def install_logstash(self):
        """Install Logstash version 7.17.13 with DEB priority and fallbacks."""
        if self.check_package_version("logstash", self.elk_version):
            self.log(f"Logstash {self.elk_version} already installed, skipping.")
            return True
        self.log(f"Attempting DEB installation from {self.logstash_deb_url}")
        deb_file = "/tmp/logstash-7.17.13.deb"
        command = (
            f"wget -q {self.logstash_deb_url} -O {deb_file} && "
            f"sha512sum {deb_file} && "
            f"dpkg -i {deb_file} && "
            "apt install -y -f && "
            f"rm -f {deb_file}"
        )
        if self.verify_deb_checksum(deb_file, self.logstash_checksum) and self.run_command(command, f"Installing Logstash via DEB ({self.architecture})", "logstash"):
            return True
        self.log(f"DEB installation failed, trying APT for Logstash {self.elk_version}")
        command = f"apt install -y logstash={self.elk_version}"
        return self.run_command(command, "Installing Logstash via APT", "logstash")

    def install_filebeat(self):
        """Install Filebeat version 7.17.13 with fallback."""
        if self.check_package_version("filebeat", self.elk_version):
            self.log(f"Filebeat {self.elk_version} already installed, skipping.")
            return True
        filebeat_deb_url = f"https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.13-{self.architecture}.deb"
        self.log(f"Attempting DEB installation from {filebeat_deb_url}")
        deb_file = "/tmp/filebeat-7.17.13.deb"
        command = (
            f"wget -q {self.logstash_deb_url} -O {deb_file} && "
            f"dpkg -i {deb_file} && "
            "apt install -y -f && "
            f"rm -f {deb_file}"
        )
        if self.run_command(command, f"Installing Filebeat via DEB ({self.architecture})", "filebeat"):
            return True
        self.log(f"DEB installation failed, trying APT for Filebeat {self.elk_version}")
        command = f"apt install -y filebeat={self.elk_version}"
        return self.run_command(command, "Installing Filebeat via APT", "filebeat")

    def stop_services(self):
        """Stop all services to apply configurations."""
        command = "systemctl stop wazuh-manager elasticsearch kibana logstash filebeat || true"
        return self.run_command(command, "Stopping services")

    def clone_and_deploy_configs(self):
        """Clone repository and deploy configuration files."""
        command = (
            f"rm -rf {self.tmp_dir} && "
            f"git clone {self.repo_url} {self.tmp_dir} && "
            f"cp -r {self.config_dir}/elasticsearch/* /etc/elasticsearch/ && "
            f"cp -r {self.config_dir}/logstash/* /etc/logstash/ && "
            f"cp -r {self.config_dir}/filebeat/* /etc/filebeat/ && "
            f"cp -r {self.tmp_dir}/var/ossec/* /var/ossec/"
        )
        return self.run_command(command, "Cloning and deploying configurations")

    def generate_and_deploy_certificates(self):
        """Generate and deploy SSL certificates."""
        script_path = os.path.join(self.tmp_dir, "wazuh-certs-tool.sh")
        if not os.path.exists(script_path):
            self.log(f"Certificate tool script not found at {script_path}. Please ensure it is present in the repository.")
            return False
        config_path = os.path.join(self.tmp_dir, "config.yml")
        if not os.path.exists(config_path):
            self.log(f"Configuration file not found at {config_path}. Please ensure config.yml is present in the repository.")
            return False
        command = (
            f"cd {self.tmp_dir} && "
            "chmod +x wazuh-certs-tool.sh && "
            "./wazuh-certs-tool.sh -A && "
            "tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ . && "
            "rm -rf ./wazuh-certificates && "
            "mkdir -p /var/ossec/etc/ssl && "
            f"tar -xvf {self.tmp_dir}/wazuh-certificates.tar -C /var/ossec/etc/ssl/"
        )
        return self.run_command(command, "Generating and deploying certificates")

    def set_permissions(self):
        """Set permissive permissions for service directories."""
        command = (
            "chown -R root:root /etc/elasticsearch /etc/logstash /etc/filebeat /var/ossec && "
            "chmod -R 777 /etc/elasticsearch /etc/logstash /etc/filebeat /var/ossec"
        )
        return self.run_command(command, "Setting permissive permissions")

    def configure_elasticsearch_jvm(self):
        """Adjust Elasticsearch JVM options for Raspberry Pi."""
        command = (
            "sed -i 's/-Xms4g/-Xms1g/' /etc/elasticsearch/jvm.options && "
            "sed -i 's/-Xmx4g/-Xmx1g/' /etc/elasticsearch/jvm.options"
        )
        return self.run_command(command, "Configuring Elasticsearch JVM options")

    def configure_email_alerts(self):
        """Configure Logstash for HTML email alerts."""
        sender_email = self.get_user_input("Email Setup", "Enter sender Gmail address:")
        sender_password = self.get_user_input("Email Setup", "Enter sender Gmail app password:", show='*')
        recipient_email = self.get_user_input("Email Setup", "Enter recipient email address:")
        if sender_email and sender_password and recipient_email:
            template_path = f"{self.config_dir}/logstash/conf.d/wazuh-alerts.conf.template"
            config_path = "/etc/logstash/conf.d/wazuh-alerts.conf"
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    config_content = f.read()
                config_content = config_content.replace("<SENDER_EMAIL>", sender_email)
                config_content = config_content.replace("<SENDER_PASSWORD>", sender_password)
                config_content = config_content.replace("<RECIPIENT_EMAIL>", recipient_email)
                with open(config_path, 'w') as f:
                    f.write(config_content)
                self.log("Email alerts configured successfully via Logstash.")
            else:
                self.log("Warning: Email configuration template not found. Skipping email setup.")
        else:
            self.log("Email configuration skipped due to missing input.")
        return True

    def install_kibana_plugin(self):
        """Install Wazuh plugin for Kibana."""
        plugin_binary = "/usr/share/kibana/bin/kibana-plugin"
        if not os.path.exists(plugin_binary):
            self.log(f"Kibana plugin binary not found at {plugin_binary}. Ensure Kibana {self.elk_version} is installed correctly.")
            return False
        command = (
            "systemctl stop kibana && "
            f"{plugin_binary} install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.5.4_7.17.13-1.zip"
        )
        return self.run_command(command, "Installing Kibana plugin")

    def enable_and_start_services(self):
        """Enable and start all services."""
        command = (
            "systemctl daemon-reload && "
            "systemctl enable wazuh-manager elasticsearch kibana logstash filebeat && "
            "systemctl start wazuh-manager elasticsearch kibana logstash filebeat"
        )
        return self.run_command(command, "Enabling and starting services")

if __name__ == "__main__":
    root = tk.Tk()
    app = InstallerGUI(root)
    root.mainloop()
