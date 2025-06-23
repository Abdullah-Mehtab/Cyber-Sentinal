import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import subprocess
import threading
import queue
import json
from datetime import datetime, timezone
import csv
import psutil
from tkinter import filedialog
import time
import tkinter.font as tkfont
import getpass
from datetime import timedelta
import webbrowser

class WazuhManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Sentinel Console")
        self.root.geometry("1020x690")
        self.root.configure(bg='#1e2526')

        self.active_processes = {}
        self.service_status_vars = {
            'wazuh-manager': [],
            'elasticsearch': [],
            'logstash': [],
            'filebeat': [],
            'packetbeat': [],
            'kibana': [],
            'cowrie': [],
            'suricata': []
        }
        self.alert_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.alert_details = {}
        self.authenticated = False
        self.selected_columns = {
            'alerts': ['severity', 'timestamp', 'agent_name', 'agent_ip', 'rule_id', 'rule_level', 'rule_desc', 'fired_times']
        }
        self.notification_threshold = 12
        
        self.themes = {
            'dark': {
                'bg_color': '#1e2526',
                'fg_color': '#d1d4d4',
                'accent_color': '#3b5998',
                'button_bg': '#2d3536',
                'critical_color': '#D9534F',
                'warning_color': '#F0AD4E',
                'info_color': '#5BC0DE'
            },
            'light': {
                'bg_color': '#f0f0f0',
                'fg_color': '#333333',
                'accent_color': '#3b5998',
                'button_bg': '#e0e0e0',
                'critical_color': '#D9534F',
                'warning_color': '#F0AD4E',
                'info_color': '#5BC0DE'
            },
            'high_contrast': {
                'bg_color': '#000000',
                'fg_color': '#FFFFFF',
                'accent_color': '#FFFF00',
                'button_bg': '#333333',
                'critical_color': '#FF0000',
                'warning_color': '#FFFF00',
                'info_color': '#00FFFF'
            }
        }
        self.current_theme = 'dark'
        
        self.tooltip_label = tk.Label(self.root, text="", background="#ffffe0", relief='solid', borderwidth=1, font=('Helvetica', 10))
        self.tooltip_label.place_forget()
        
        self.show_login()
        
        if self.authenticated:
            self.create_widgets()
            self.setup_style()
            self.update_service_status()
            self.process_alert_queue()
            self.update_metrics()
            self.animate_ticker()
            self.process_status_queue()
            self.start_alerts_tail()
            self.auto_refresh_agents()

    def debug_log(self, message):
        """Write debug information to a log file."""
        with open('agent_debug.log', 'a') as f:
            f.write(f"{datetime.now()}: {message}\n")

    def show_login(self):
        login_window = tk.Toplevel(self.root)
        login_window.title("Login")
        login_window.geometry("300x150")
        login_window.transient(self.root)
        login_window.grab_set()
        
        tk.Label(login_window, text="Password:").pack(pady=10)
        password_entry = tk.Entry(login_window, show="*")
        password_entry.pack(pady=5)
        password_entry.focus_set()
        
        def verify_password():
            if password_entry.get() == "admin":
                self.authenticated = True
                login_window.destroy()
            else:
                messagebox.showerror("Error", "Invalid password")
                password_entry.delete(0, tk.END)
        
        tk.Button(login_window, text="Login", command=verify_password).pack(pady=10)
        password_entry.bind('<Return>', lambda e: verify_password())
        self.root.wait_window(login_window)
        if not self.authenticated:
            self.root.destroy()

    def setup_style(self):
        style = ttk.Style()
        style.theme_create('enterprise', settings={
            "TNotebook": {"configure": {"background": self.themes[self.current_theme]['bg_color'], "foreground": self.themes[self.current_theme]['fg_color']}},
            "TNotebook.Tab": {
                "configure": {"padding": [15, 5], "background": self.themes[self.current_theme]['button_bg'], "foreground": self.themes[self.current_theme]['fg_color'],
                             "font": ('Helvetica', 12, 'bold')},
                "map": {"background": [("selected", self.themes[self.current_theme]['accent_color'])], "foreground": [("selected", self.themes[self.current_theme]['fg_color'])]}
            },
            "TFrame": {"configure": {"background": self.themes[self.current_theme]['bg_color']}},
            "TLabel": {"configure": {"background": self.themes[self.current_theme]['bg_color'], "foreground": self.themes[self.current_theme]['fg_color']}},
            "Treeview": {"configure": {"background": self.themes[self.current_theme]['button_bg'], "fieldbackground": self.themes[self.current_theme]['button_bg'], "foreground": self.themes[self.current_theme]['fg_color']}},
            "Treeview.Heading": {"configure": {"background": self.themes[self.current_theme]['accent_color'], "foreground": self.themes[self.current_theme]['fg_color'], "font": ('Helvetica', 10, 'bold')}},
        })
        style.theme_use('enterprise')

    def create_widgets(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Preferences", command=self.open_settings)
        settings_menu.add_command(label="Configure Columns", command=self.configure_columns)
        
        theme_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Light", command=lambda: self.set_theme('light'), state='disabled')
        theme_menu.add_command(label="Dark", command=lambda: self.set_theme('dark'))
        theme_menu.add_command(label="High Contrast", command=lambda: self.set_theme('high_contrast'), state='disabled')
        
        logo_frame = tk.Frame(self.root, bg=self.themes[self.current_theme]['bg_color'])
        tk.Label(logo_frame, text="Cyber Senti", font=('Helvetica', 16, 'bold'), 
                 bg=self.themes[self.current_theme]['bg_color'], fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT)
        logo_frame.pack(fill=tk.X, pady=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=20)
        self.notebook.bind('<KeyPress>', self.handle_keyboard_navigation)

        self.tabs = {
            'dashboard': ttk.Frame(self.notebook),
            'alerts': ttk.Frame(self.notebook),
            'agents': ttk.Frame(self.notebook),
            'services': ttk.Frame(self.notebook),
            'wazuh': ttk.Frame(self.notebook),
            'elastic': ttk.Frame(self.notebook),
            'logstash': ttk.Frame(self.notebook),
            'filebeat': ttk.Frame(self.notebook),
            'packetbeat': ttk.Frame(self.notebook),
            'cowrie': ttk.Frame(self.notebook),
            'suricata': ttk.Frame(self.notebook)
        }

        self.notebook.add(self.tabs['dashboard'], text='Dashboard')
        for name, frame in list(self.tabs.items())[1:]:
            self.notebook.add(frame, text=name.capitalize())

        self.create_dashboard_tab()
        self.create_alerts_tab()
        self.create_agents_tab()
        self.create_services_tab()
        self.create_service_tab('wazuh', 'Wazuh Manager', 'wazuh-manager', 'sudo tail -f /var/ossec/logs/ossec.json | jq .')
        self.create_service_tab('elastic', 'Elasticsearch', 'elasticsearch', 'sudo tail -f /var/log/elasticsearch/elasticsearch.log')
        self.create_service_tab('logstash', 'Logstash', 'logstash', 'sudo tail -f /var/log/logstash/logstash-plain.log')
        self.create_service_tab('filebeat', 'Filebeat', 'filebeat', 'sudo tail -f /var/log/filebeat/filebeat')
        self.create_service_tab('packetbeat', 'Packetbeat', 'packetbeat', 'sudo tail -f /var/log/packetbeat/packetbeat.log')
        self.create_service_tab('cowrie', 'Cowrie', 'cowrie', 'sudo tail -f /var/log/cowrie/cowrie.log')
        self.create_service_tab('suricata', 'Suricata', 'suricata', 'sudo tail -f /var/log/suricata/suricata.log')

    def set_theme(self, theme_name):
        if theme_name == self.current_theme:
            return
        if theme_name in self.themes:
            self.current_theme = theme_name
            self.setup_style()
            self.root.configure(bg=self.themes[self.current_theme]['bg_color'])
            self.notebook.destroy()
            self.create_widgets()
            messagebox.showinfo("Theme Changed", f"Theme changed to {theme_name}")
            self.log_action(f"Changed theme to {theme_name}")
        else:
            messagebox.showerror("Error", "Invalid theme selected")

    def create_dashboard_tab(self):
        tab = self.tabs['dashboard']
        frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'])
        
        tk.Label(frame, text="Dashboard", font=('Helvetica', 18, 'bold'), 
                 bg=self.themes[self.current_theme]['bg_color'], fg=self.themes[self.current_theme]['fg_color']).pack(pady=20)

        metrics_frame = tk.Frame(frame, bg=self.themes[self.current_theme]['button_bg'], relief=tk.RAISED, borderwidth=2)
        tk.Label(metrics_frame, text="Active Agents:", bg=self.themes[self.current_theme]['button_bg'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12)).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.active_agents_label = tk.Label(metrics_frame, text="0", bg=self.themes[self.current_theme]['button_bg'], 
                                           fg='#2ecc71', font=('Helvetica', 12, 'bold'))
        self.active_agents_label.grid(row=0, column=1, sticky='e', padx=10, pady=5)
        tk.Label(metrics_frame, text="Recent Alerts:", bg=self.themes[self.current_theme]['button_bg'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12)).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.recent_alerts_label = tk.Label(metrics_frame, text="0", bg=self.themes[self.current_theme]['button_bg'], 
                                           fg='#e74c3c', font=('Helvetica', 12, 'bold'))
        self.recent_alerts_label.grid(row=1, column=1, sticky='e', padx=10, pady=5)
        metrics_frame.pack(pady=10, padx=10)

        resource_frame = tk.Frame(frame, bg=self.themes[self.current_theme]['button_bg'], relief=tk.RAISED, borderwidth=2)
        tk.Label(resource_frame, text="System Resources", bg=self.themes[self.current_theme]['button_bg'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 14, 'bold')).pack(pady=5)
        self.cpu_label = tk.Label(resource_frame, text="CPU: 0%", bg=self.themes[self.current_theme]['button_bg'], 
                                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12))
        self.cpu_label.pack(pady=2)
        self.ram_label = tk.Label(resource_frame, text="RAM: 0%", bg=self.themes[self.current_theme]['button_bg'], 
                                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12))
        self.ram_label.pack(pady=2)
        self.disk_label = tk.Label(resource_frame, text="Disk: 0%", bg=self.themes[self.current_theme]['button_bg'], 
                                  fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12))
        self.disk_label.pack(pady=2)
        resource_frame.pack(pady=10, padx=10)

        summary_frame = tk.Frame(frame, bg=self.themes[self.current_theme]['button_bg'], relief=tk.RAISED, borderwidth=2)
        tk.Label(summary_frame, text="Executive Summary", bg=self.themes[self.current_theme]['button_bg'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 14, 'bold')).pack(pady=5)
        self.summary_label = tk.Label(summary_frame, text="Attacks/Hour: N/A\nCritical Alerts: 0", 
                                    bg=self.themes[self.current_theme]['button_bg'], 
                                    fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 11))
        self.summary_label.pack(pady=5)
        summary_frame.pack(pady=10, padx=10)

        self.ticker_canvas = tk.Canvas(frame, bg=self.themes[self.current_theme]['bg_color'], 
                                      height=30, highlightthickness=0)
        self.ticker_text = self.ticker_canvas.create_text(0, 15, anchor='w', 
                                                        font=('Helvetica', 12), 
                                                        fill=self.themes[self.current_theme]['fg_color'])
        self.ticker_canvas.pack(fill='x', pady=10)

        kibana_btn = tk.Button(frame, text="Open Kibana", command=self.open_kibana, 
                              bg=self.themes[self.current_theme]['accent_color'], 
                              fg=self.themes[self.current_theme]['fg_color'])
        kibana_btn.pack(pady=10)
        self.add_tooltip(kibana_btn, "Open Kibana dashboard in your browser")

        block_ip_btn = tk.Button(frame, text="Block IP", command=self.block_ip_dashboard, 
                                bg=self.themes[self.current_theme]['accent_color'], 
                                fg=self.themes[self.current_theme]['fg_color'])
        block_ip_btn.pack(pady=10)
        self.add_tooltip(block_ip_btn, "Block an IP address through firewall")
        
        frame.pack(fill='both', expand=True)

    def open_kibana(self):
        kibana_window = tk.Toplevel(self.root)
        kibana_window.title("Open Kibana")
        kibana_window.geometry("300x100")
        tk.Label(kibana_window, text="Click to open Kibana dashboard:").pack(pady=10)
        link_label = tk.Label(kibana_window, text="http://localhost:5601", fg="blue", cursor="hand2")
        link_label.pack(pady=5)
        link_label.bind("<Button-1>", lambda e: webbrowser.open("http://localhost:5601"))

    def block_ip_dashboard(self):
        ip = simpledialog.askstring("Block IP", "Enter IP address to block:")
        if ip:
            try:
                subprocess.run(f"sudo /var/ossec/bin/firewall-drop {ip}", shell=True, check=True)
                messagebox.showinfo("Success", f"IP {ip} blocked")
                self.log_action(f"Blocked IP from dashboard: {ip}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def animate_ticker(self):
        if hasattr(self, 'ticker_canvas'):
            current_text = self.ticker_canvas.itemcget(self.ticker_text, 'text') or ""
            if current_text:
                x = float(self.ticker_canvas.coords(self.ticker_text)[0])
                if x < -self.ticker_canvas.winfo_width():
                    x = self.ticker_canvas.winfo_width()
                self.ticker_canvas.coords(self.ticker_text, x - 2, 15)
            self.root.after(50, self.animate_ticker)

    def create_log_viewer(self, parent, display_name, service_name, log_command):
        frame = tk.Frame(parent, bg=self.themes[self.current_theme]['bg_color'], relief=tk.RAISED, borderwidth=1)
        
        status_frame = tk.Frame(frame, bg=self.themes[self.current_theme]['bg_color'])
        tk.Label(status_frame, text=f"{display_name} Status:", 
                bg=self.themes[self.current_theme]['bg_color'], fg=self.themes[self.current_theme]['fg_color'], 
                font=('Helvetica', 14)).pack(side=tk.LEFT)
        status_label = tk.Label(status_frame, text="Checking...", 
                               font=('Helvetica', 14, 'bold'), bg=self.themes[self.current_theme]['bg_color'], 
                               fg=self.themes[self.current_theme]['fg_color'])
        status_label.pack(side=tk.LEFT, padx=10)
        self.service_status_vars[service_name].append(status_label)
        status_frame.pack(fill='x', pady=10)
        
        container = tk.Frame(frame, bg=self.themes[self.current_theme]['bg_color'])
        container.grid_rowconfigure(0, weight=1)
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        tail_frame = tk.Frame(container, bg=self.themes[self.current_theme]['bg_color'])
        self.create_log_section(tail_frame, "Tail Logs", log_command)
        tail_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        
        journal_frame = tk.Frame(container, bg=self.themes[self.current_theme]['bg_color'])
        journal_command = f'sudo journalctl -u {service_name} -f'
        self.create_log_section(journal_frame, "Journal Logs", journal_command)
        journal_frame.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        
        container.pack(fill='both', expand=True, padx=10, pady=10)
        return frame

    def create_log_section(self, parent, title, command):
        header = tk.Frame(parent, bg=self.themes[self.current_theme]['bg_color'])
        tk.Label(header, text=title, bg=self.themes[self.current_theme]['bg_color'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 12, 'bold')).pack(side=tk.LEFT)
        
        btn_frame = tk.Frame(header, bg=self.themes[self.current_theme]['bg_color'])
        start_btn = tk.Button(btn_frame, text="Start", 
                             command=lambda: self.start_log(command, text_widget),
                             bg=self.themes[self.current_theme]['accent_color'], 
                             fg=self.themes[self.current_theme]['fg_color'], 
                             font=('Helvetica', 10), padx=10, pady=5)
        start_btn.pack(side=tk.LEFT, padx=5)
        self.add_tooltip(start_btn, f"Start {title.lower()} for this service")
        clear_btn = tk.Button(btn_frame, text="Clear", 
                             command=lambda: text_widget.delete(1.0, tk.END),
                             bg=self.themes[self.current_theme]['button_bg'], 
                             fg=self.themes[self.current_theme]['fg_color'], 
                             font=('Helvetica', 10), padx=10, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        self.add_tooltip(clear_btn, "Clear the log display")
        btn_frame.pack(side=tk.RIGHT)
        header.pack(fill='x', pady=5)
        
        text_widget = scrolledtext.ScrolledText(parent, wrap=tk.WORD, 
                                              bg=self.themes[self.current_theme]['button_bg'], 
                                              fg=self.themes[self.current_theme]['fg_color'], 
                                              relief=tk.SUNKEN, borderwidth=2, font=('Helvetica', 11))
        text_widget.pack(fill='both', expand=True, pady=5)
        text_widget.bind('<KeyPress>', self.handle_keyboard_navigation)
        return text_widget

    def create_service_tab(self, tab_name, display_name, service_name, log_command):
        tab = self.tabs[tab_name]
        log_viewer = self.create_log_viewer(tab, display_name, service_name, log_command)
        log_viewer.pack(fill='both', expand=True)

    def create_alerts_tab(self):
        tab = self.tabs['alerts']

        header = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'])
        tk.Label(header, text="Alerts Viewer", font=('Helvetica', 16, 'bold'), 
                 bg=self.themes[self.current_theme]['bg_color'], fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT)

        btn_frame = tk.Frame(header, bg=self.themes[self.current_theme]['bg_color'])
        refresh_btn = tk.Button(btn_frame, text="Refresh Alerts", command=self.refresh_alerts, 
                               bg='#3498db', fg='white', padx=10, pady=5)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        clear_btn = tk.Button(btn_frame, text="Clear", command=self.clear_alerts, 
                             bg=self.themes[self.current_theme]['button_bg'], 
                             fg=self.themes[self.current_theme]['fg_color'], padx=10, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        truncate_btn = tk.Button(btn_frame, text="Truncate File", command=self.truncate_alerts, 
                                bg=self.themes[self.current_theme]['critical_color'], 
                                fg=self.themes[self.current_theme]['fg_color'], padx=10, pady=5)
        truncate_btn.pack(side=tk.LEFT, padx=5)
        export_btn = tk.Button(btn_frame, text="Export CSV", command=self.export_alerts_csv, 
                              bg='#2ecc71', fg='white', padx=10, pady=5)
        export_btn.pack(side=tk.LEFT, padx=5)
        btn_frame.pack(side=tk.RIGHT)
        header.pack(fill='x', padx=15, pady=15)

        self.add_tooltip(refresh_btn, "Refresh alerts from file")
        self.add_tooltip(clear_btn, "Clear all alerts")
        self.add_tooltip(truncate_btn, "Truncate the alerts file")
        self.add_tooltip(export_btn, "Export alerts to CSV")

        filter_frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'])
        tk.Label(filter_frame, text="Severity:", bg=self.themes[self.current_theme]['bg_color'], 
                 fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT, padx=5)
        self.severity_filter = ttk.Combobox(filter_frame, values=["All", "High", "Medium", "Low"], state="readonly")
        self.severity_filter.set("All")
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        tk.Label(filter_frame, text="Time Range:", bg=self.themes[self.current_theme]['bg_color'], 
                 fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT, padx=5)
        self.time_filter = ttk.Combobox(filter_frame, values=["Last 15 min", "Last Hour", "Today", "All"], state="readonly")
        self.time_filter.set("All")
        self.time_filter.pack(side=tk.LEFT, padx=5)
        
        tk.Label(filter_frame, text="Agent:", bg=self.themes[self.current_theme]['bg_color'], 
                 fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT, padx=5)
        agent_names = self.get_agent_names()
        self.agent_filter = ttk.Combobox(filter_frame, values=["All"] + agent_names, state="readonly")
        self.agent_filter.set("All")
        self.agent_filter.pack(side=tk.LEFT, padx=5)
        if not agent_names:
            messagebox.showwarning("No Agents", "No agents found. Check agent_debug.log for details.")
        
        tk.Button(filter_frame, text="Apply Filter", command=self.apply_filter, 
                 bg=self.themes[self.current_theme]['button_bg'], 
                 fg=self.themes[self.current_theme]['fg_color']).pack(side=tk.LEFT, padx=5)
        filter_frame.pack(fill='x', padx=15, pady=10)

        tree_frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'])
        self.alert_treeview = ttk.Treeview(tree_frame, columns=self.selected_columns['alerts'], show='headings')
        for col in self.selected_columns['alerts']:
            self.alert_treeview.heading(col, text=col.replace('_', ' ').title())
            self.alert_treeview.column(col, width=100 if col != 'rule_desc' else 300)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.alert_treeview.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.alert_treeview.xview)
        self.alert_treeview.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.alert_treeview.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.pack(fill='both', expand=True, padx=15, pady=15)

        self.alert_treeview.tag_configure('high', foreground=self.themes[self.current_theme]['critical_color'])
        self.alert_treeview.tag_configure('medium', foreground=self.themes[self.current_theme]['warning_color'])
        self.alert_treeview.tag_configure('low', foreground=self.themes[self.current_theme]['info_color'])
        self.alert_treeview.tag_configure('new', background='#90EE90')

        self.alert_treeview.bind('<Double-1>', self.show_alert_details)
        self.alert_treeview.bind('<Button-3>', self.show_context_menu)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Block IP", command=self.block_ip)
        self.context_menu.add_command(label="Isolate Agent", command=self.isolate_agent)
        self.context_menu.add_command(label="Run Scan", command=self.run_scan)
        self.context_menu.add_command(label="Add to Watchlist", command=self.add_to_watchlist)

    def get_agent_names(self):
        try:
            output = subprocess.check_output("sudo /var/ossec/bin/agent_control -l", shell=True, stderr=subprocess.STDOUT).decode()
            self.debug_log(f"Raw agent_control output:\n{output}")
            agents = []
            for line in output.split('\n'):
                if line.strip().startswith("ID:"):
                    try:
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 2 and "Name:" in parts[1]:
                            name = parts[1].split("Name:")[1].strip()
                            agents.append(name)
                    except Exception as e:
                        self.debug_log(f"Error parsing line '{line}': {str(e)}")
            self.debug_log(f"Parsed agent names: {agents}")
            if not agents:
                self.debug_log("No agents found in output.")
            return agents
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {str(e)}\nOutput: {e.output.decode()}"
            self.debug_log(error_msg)
            messagebox.showerror("Error", "Failed to get agent names. Check agent_debug.log for details.")
            return []
        except Exception as e:
            self.debug_log(f"Unexpected error in get_agent_names: {str(e)}")
            messagebox.showerror("Error", "Failed to get agent names. Check agent_debug.log for details.")
            return []

    def show_context_menu(self, event):
        item = self.alert_treeview.identify_row(event.y)
        if item:
            self.alert_treeview.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def block_ip(self):
        item_id = self.alert_treeview.selection()[0] if self.alert_treeview.selection() else None
        alert = self.alert_details.get(item_id) if item_id else None
        if alert:
            ip = alert.get('agent', {}).get('ip', '')
            if ip:
                if messagebox.askyesno("Confirm", f"Block IP {ip}?"):
                    self.run_command(f"sudo /var/ossec/bin/firewall-drop {ip}", self.agent_output)
                    self.log_action(f"Blocked IP: {ip}")

    def isolate_agent(self):
        item_id = self.alert_treeview.selection()[0] if self.alert_treeview.selection() else None
        alert = self.alert_details.get(item_id) if item_id else None
        if alert:
            agent_id = alert.get('agent', {}).get('id', '')
            if agent_id:
                if messagebox.askyesno("Confirm", f"Isolate agent {agent_id}?"):
                    self.run_command(f"sudo /var/ossec/bin/agent_control -s {agent_id}", self.agent_output)
                    self.log_action(f"Isolated agent: {agent_id}")

    def run_scan(self):
        item_id = self.alert_treeview.selection()[0] if self.alert_treeview.selection() else None
        alert = self.alert_details.get(item_id) if item_id else None
        if alert:
            agent_id = alert.get('agent', {}).get('id', '')
            if agent_id:
                if messagebox.askyesno("Confirm", f"Run scan on agent {agent_id}?"):
                    self.run_command(f"sudo /var/ossec/bin/syscheck_control -r {agent_id}", self.agent_output)
                    self.log_action(f"Ran scan on agent: {agent_id}")

    def add_to_watchlist(self):
        item_id = self.alert_treeview.selection()[0] if self.alert_treeview.selection() else None
        alert = self.alert_details.get(item_id) if item_id else None
        if alert:
            ip = alert.get('agent', {}).get('ip', '')
            if ip:
                with open('watchlist.txt', 'a') as f:
                    f.write(f"{ip}\n")
                messagebox.showinfo("Success", f"IP {ip} added to watchlist")
                self.log_action(f"Added IP to watchlist: {ip}")

    def apply_filter(self):
        # Refresh agent filter values
        self.agent_filter['values'] = ["All"] + self.get_agent_names()
        
        severity = self.severity_filter.get() or "All"
        time_range = self.time_filter.get() or "All"
        agent = self.agent_filter.get() or "All"
        
        time_threshold = None
        if time_range != "All":
            now = datetime.now(timezone.utc)
            if time_range == "Last 15 min":
                time_threshold = now - timedelta(minutes=15)
            elif time_range == "Last Hour":
                time_threshold = now - timedelta(hours=1)
            elif time_range == "Today":
                time_threshold = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        for item in self.alert_treeview.get_children():
            alert = self.alert_details.get(item)
            if not alert:
                continue
            rule_level = alert.get('rule', {}).get('level', '')
            try:
                level = int(rule_level) if rule_level else 0
            except ValueError:
                level = 0
            if level >= 12:
                alert_severity = '!'
            elif level >= 7:
                alert_severity = '?'
            else:
                alert_severity = 'i'
            
            timestamp_str = alert.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError:
                timestamp = None
            
            agent_name = alert.get('agent', {}).get('name', '')
            
            match_severity = severity == "All" or \
                            (severity == "High" and alert_severity == '!') or \
                            (severity == "Medium" and alert_severity == '?') or \
                            (severity == "Low" and alert_severity == 'i')
            
            match_time = not time_threshold or (timestamp and timestamp >= time_threshold)
            
            match_agent = agent == "All" or agent_name == agent
            
            if match_severity and match_time and match_agent:
                self.alert_treeview.reattach(item, '', tk.END)
            else:
                self.alert_treeview.detach(item)

    def export_alerts_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", file_types=[("CSV files", "*.csv")])
                                                 
        if file_path:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(self.selected_columns['alerts'])
                for item in self.alert_treeview.get_children():
                    writer.writerow(self.alert_treeview.item(item, 'values') or [])
            messagebox.showinfo("Success", f"Alerts exported to {file_path}")
            self.log_action(f"Exported alerts to {file_path}")

    def start_alerts_tail(self):
        command = 'sudo tail -f /var/ossec/logs/alerts/alerts.json'
        def callback(line):
            self.alert_queue.put(line)
        self.start_log(command, callback=callback)

    def process_alert_queue(self):
        while not self.alert_queue.empty():
            line = self.alert_queue.get()
            try:
                alert = json.loads(line)
                raw_timestamp = alert.get('timestamp', '')
                try:
                    dt = datetime.strptime(raw_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                    timestamp = dt.strftime("%B %d, %Y %H:%M:%S")
                    relative_time = self.get_relative_time(dt)
                except ValueError:
                    timestamp = raw_timestamp
                    relative_time = "Unknown"
                
                agent_name = alert.get('agent', {}).get('name', '')
                agent_ip = alert.get('agent', {}).get('ip', '')
                rule_id = alert.get('rule', {}).get('id', '')
                rule_level = alert.get('rule', {}).get('level', '')
                rule_desc = alert.get('rule', {}).get('description', '')
                fired_times = alert.get('rule', {}).get('firedtimes', '')
                
                try:
                    level = int(rule_level) if rule_level else 0
                except ValueError:
                    level = 0
                    
                if level >= 12:
                    severity = '!'
                    tag = 'high'
                    if level >= self.notification_threshold:
                        self.show_notification(f"Critical Alert: {rule_desc}")
                elif level >= 7:
                    severity = '?'
                    tag = 'medium'
                else:
                    severity = 'i'
                    tag = 'low'
                
                values = []
                for col in self.selected_columns['alerts']:
                    if col == 'severity':
                        values.append(severity)
                    elif col == 'timestamp':
                        values.append(timestamp)
                    elif col == 'agent_name':
                        values.append(agent_name)
                    elif col == 'agent_ip':
                        values.append(agent_ip)
                    elif col == 'rule_id':
                        values.append(rule_id)
                    elif col == 'rule_level':
                        values.append(rule_level)
                    elif col == 'rule_desc':
                        values.append(rule_desc)
                    elif col == 'fired_times':
                        values.append(fired_times)
                
                item_id = self.alert_treeview.insert('', 0, 
                                                    values=tuple(values), 
                                                    tags=(tag, 'new'))
                self.alert_details[item_id] = alert
                self.alert_treeview.see(item_id)
                
                recent_alerts = len(self.alert_treeview.get_children())
                self.recent_alerts_label.config(text=str(recent_alerts))
                self.ticker_canvas.itemconfig(self.ticker_text, text=f"Latest Alert: {rule_desc} from {agent_name} ({relative_time})")
                
                self.root.after(5000, lambda: self.alert_treeview.item(item_id, tags=(tag,)))
                
                critical_count = len([item for item in self.alert_treeview.get_children() 
                                    if self.alert_treeview.item(item, 'values')[0] == '!'])
                self.summary_label.config(text=f"Attacks/Hour: N/A\nCritical Alerts: {critical_count}")
                
            except json.JSONDecodeError:
                pass
        self.root.after(100, self.process_alert_queue)

    def get_relative_time(self, dt):
        now = datetime.now(timezone.utc)
        delta = now - dt
        if delta.total_seconds() < 60:
            return "Just now"
        elif delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() // 60)} min ago"
        elif delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() // 3600)} hours ago"
        else:
            return dt.strftime("%B %d, %Y %H:%M:%S")

    def show_notification(self, message):
        notification = tk.Toplevel(self.root)
        notification.title("Critical Alert")
        notification.geometry("300x100")
        notification.attributes('-topmost', True)
        tk.Label(notification, text=message or "No message", wraplength=280, 
                bg=self.themes[self.current_theme]['critical_color'], 
                fg=self.themes[self.current_theme]['fg_color']).pack(pady=10, padx=10)
        notification.after(5000, notification.destroy)

    def clear_alerts(self):
        for item in self.alert_treeview.get_children():
            self.alert_treeview.delete(item)
        self.alert_details.clear()
        self.recent_alerts_label.config(text="0")
        self.ticker_canvas.itemconfig(self.ticker_text, text="")
        self.summary_label.config(text="Attacks/Hour: N/A\nCritical Alerts: 0")

    def refresh_alerts(self):
        self.clear_alerts()
        try:
            with open('/var/ossec/logs/alerts/alerts.json', 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line)
                        raw_timestamp = alert.get('timestamp', '')
                        try:
                            dt = datetime.strptime(raw_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                            timestamp = dt.strftime("%B %d, %Y %H:%M:%S")
                        except ValueError:
                            timestamp = raw_timestamp
                        
                        agent_name = alert.get('agent', {}).get('name', '')
                        agent_ip = alert.get('agent', {}).get('ip', '')
                        rule_id = alert.get('rule', {}).get('id', '')
                        rule_level = alert.get('rule', {}).get('level', '')
                        rule_desc = alert.get('rule', {}).get('description', '')
                        fired_times = alert.get('rule', {}).get('firedtimes', '')
                        
                        try:
                            level = int(rule_level) if rule_level else 0
                        except ValueError:
                            level = 0
                            
                        if level >= 12:
                            severity = '!'
                            tag = 'high'
                        elif level >= 7:
                            severity = '?'
                            tag = 'medium'
                        else:
                            severity = 'i'
                            tag = 'low'
                        
                        values = []
                        for col in self.selected_columns['alerts']:
                            if col == 'severity':
                                values.append(severity)
                            elif col == 'timestamp':
                                values.append(timestamp)
                            elif col == 'agent_name':
                                values.append(agent_name)
                            elif col == 'agent_ip':
                                values.append(agent_ip)
                            elif col == 'rule_id':
                                values.append(rule_id)
                            elif col == 'rule_level':
                                values.append(rule_level)
                            elif col == 'rule_desc':
                                values.append(rule_desc)
                            elif col == 'fired_times':
                                values.append(fired_times)
                        
                        item_id = self.alert_treeview.insert('', 'end', 
                                                            values=tuple(values), 
                                                            tags=(tag,))
                        self.alert_details[item_id] = alert
                    except json.JSONDecodeError:
                        pass
            recent_alerts = len(self.alert_treeview.get_children())
            self.recent_alerts_label.config(text=str(recent_alerts))
            critical_count = len([item for item in self.alert_treeview.get_children() 
                                  if self.alert_treeview.item(item, 'values')[0] == '!'])
            self.summary_label.config(text=f"Attacks/Hour: N/A\nCritical Alerts: {critical_count}")
            self.apply_filter()
            messagebox.showinfo("Success", "Alerts refreshed")
            self.log_action("Refreshed alerts")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh alerts: {str(e)}")

    def show_alert_details(self, event):
        item_id = self.alert_treeview.selection()[0] if self.alert_treeview.selection() else None
        alert = self.alert_details.get(item_id) if item_id else None
        if alert:
            details_window = tk.Toplevel(self.root)
            details_window.title("Alert Details")
            details_window.geometry("600x400")
            text_widget = scrolledtext.ScrolledText(details_window, wrap=tk.WORD, 
                                                  bg=self.themes[self.current_theme]['button_bg'], 
                                                  fg=self.themes[self.current_theme]['fg_color'])
            text_widget.pack(fill='both', expand=True)
            pretty_json = json.dumps(alert, indent=2)
            text_widget.insert(tk.END, pretty_json)
            text_widget.config(state=tk.DISABLED)

    def truncate_alerts(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to truncate the alerts file?"):
            try:
                subprocess.run("sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json", 
                            shell=True, check=True)
                messagebox.showinfo("Success", "Alerts file truncated")
                self.clear_alerts()
                self.log_action("Truncated alerts file")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def start_log(self, command, widget=None, callback=None):
        if command in self.active_processes:
            self.stop_log(command)
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        self.active_processes[command] = process
        def read_output():
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                if callback:
                    callback(line)
                elif widget:
                    widget.insert(tk.END, line)
                    widget.see(tk.END)
            process.poll()
        threading.Thread(target=read_output, daemon=True).start()

    def stop_log(self, command):
        if command in self.active_processes:
            self.active_processes[command].terminate()
            del self.active_processes[command]

    def update_service_status(self):
        def check_status(service, labels):
            try:
                status = subprocess.check_output(
                    f"sudo systemctl is-active {service}.service", 
                    shell=True, 
                    stderr=subprocess.STDOUT
                ).decode().strip().lower()
                color = '#2ecc71' if status == 'active' else '#e74c3c'
                status_text = 'ACTIVE' if status == 'active' else 'INACTIVE'
                self.status_queue.put((labels, status_text, color))
            except Exception:
                self.status_queue.put((labels, "ERROR", '#e74c3c'))
        
        for service, labels in self.service_status_vars.items():
            if labels:
                threading.Thread(target=check_status, args=(service, labels), daemon=True).start()
        
        cpu_percent = psutil.cpu_percent()
        self.cpu_label.config(text=f"CPU: {cpu_percent}%")
        mem = psutil.virtual_memory()
        self.ram_label.config(text=f"RAM: {mem.percent}%")
        disk = psutil.disk_usage('/')
        self.disk_label.config(text=f"Disk: {disk.percent}%")
        
        self.status_after_id = self.root.after(3000, self.update_service_status)

    def process_status_queue(self):
        while not self.status_queue.empty():
            labels, status_text, color = self.status_queue.get()
            for label in labels:
                label.config(text=status_text, fg=color)
        self.root.after(100, self.process_status_queue)

    def update_metrics(self):
        try:
            output = subprocess.check_output("sudo /var/ossec/bin/agent_control -l", 
                                          shell=True, stderr=subprocess.STDOUT).decode()
            active_count = sum(1 for line in output.split('\n') if 'Active' in line and 'ID:' in line)
            self.active_agents_label.config(text=str(active_count))
        except Exception as e:
            self.active_agents_label.config(text="Error", fg=self.themes[self.current_theme]['critical_color'])
            self.log_action(f"Error updating metrics: {str(e)}")
        self.root.after(3000, self.update_metrics)

    def control_service(self, service, action):
        if action == 'start':
            result = subprocess.run(f"sudo systemctl is-active {service}.service", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                messagebox.showinfo("Info", f"{service} is already active")
                return
        if messagebox.askyesno("Confirm", f"Are you sure you want to {action} {service}?"):
            command = f"sudo systemctl {action} {service}"
            self.run_command(command)
            self.log_action(f"Service {service} {action}")

    def run_command(self, command, output_widget=None):
        result_queue = queue.Queue()

        def worker():
            try:
                result = subprocess.run(command, shell=True, 
                                    capture_output=True, text=True)
                output = result.stdout or result.stderr or ""
                result_queue.put(('success', output))
            except Exception as e:
                result_queue.put(('error', str(e)))

        if output_widget:
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            self.root.after(100, lambda: self.process_command_result(result_queue, output_widget, command))
            return None
        else:
            worker()
            result_type, result = result_queue.get()
            if result_type == 'success':
                return result
            else:
                raise Exception(result)

    def process_command_result(self, result_queue, output_widget, command):
        try:
            result_type, result = result_queue.get_nowait()
            if result_type == 'success':
                if "manage_agents -e" in command:
                    # Don't overwrite the result, just show it directly
                    output_widget.insert(tk.END, f"Extracted Key:\n{result}\n")
                else:
                    output_widget.insert(tk.END, result + '\n')
            else:
                messagebox.showerror("Error", result)
                self.log_action(f"Command error: {result}")
        except queue.Empty:
            self.root.after(100, lambda: self.process_command_result(result_queue, output_widget, command))


    def create_agents_tab(self):
        tab = self.tabs['agents']
        
        list_frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'], relief=tk.RAISED, borderwidth=1)
        tk.Label(list_frame, text="List of Agents", bg=self.themes[self.current_theme]['bg_color'], 
                 fg=self.themes[self.current_theme]['fg_color'], font=('Helvetica', 14, 'bold')).pack(pady=5)
        tree_frame = tk.Frame(list_frame, bg=self.themes[self.current_theme]['bg_color'])
        self.agent_treeview = ttk.Treeview(tree_frame, columns=('ID', 'Name', 'IP', 'Status'), show='headings')
        for col in ('ID', 'Name', 'IP', 'Status'):
            self.agent_treeview.heading(col, text=col)
            self.agent_treeview.column(col, width=100 if col != 'Status' else 150)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.agent_treeview.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.agent_treeview.xview)
        self.agent_treeview.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.agent_treeview.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        list_frame.pack(side=tk.LEFT, fill='both', expand=True, padx=15, pady=15)
        
        control_frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'], relief=tk.RAISED, borderwidth=1)
        tk.Label(control_frame, text="Agent Management", bg=self.themes[self.current_theme]['bg_color'], 
                fg=self.themes[self.current_theme]['fg_color'], 
                font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        buttons = [
            ("Add Agent", self.add_agent, "Add a new agent"),
            ("Remove Agent", self.remove_agent, "Remove an existing agent"),
            ("List all agents", self.refresh_agents, "Refresh the agent list"),
            ("Extract Key", self.extract_key, "Extract agent key (output masked)")
        ]
        for text, cmd, tip in buttons:
            btn = tk.Button(control_frame, text=text, command=cmd, 
                           bg=self.themes[self.current_theme]['button_bg'], 
                           fg=self.themes[self.current_theme]['fg_color'], 
                           font=('Helvetica', 10), padx=10, pady=5)
            btn.pack(fill='x', pady=5)
            self.add_tooltip(btn, tip)
        
        self.agent_output = scrolledtext.ScrolledText(control_frame, height=10, 
                                                    bg=self.themes[self.current_theme]['button_bg'], 
                                                    fg=self.themes[self.current_theme]['fg_color'], 
                                                    relief=tk.SUNKEN, borderwidth=2, font=('Helvetica', 11))
        self.agent_output.pack(fill='x', pady=10)
        control_frame.pack(side=tk.RIGHT, fill='y', padx=15, pady=15)

        # Initial refresh to populate agents
        self.refresh_agents()

    def auto_refresh_agents(self):
        self.refresh_agents()
        self.root.after(3000, self.auto_refresh_agents)

    def refresh_agents(self):
        self.agent_treeview.delete(*self.agent_treeview.get_children())
        try:
            output = self.run_command("sudo /var/ossec/bin/agent_control -l")
            self.debug_log(f"refresh_agents raw output:\n{output}")
            if output:
                agent_count = 0
                for line in output.split('\n'):
                    if line.strip().startswith("ID:"):
                        try:
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) >= 4:
                                id_part = parts[0]
                                name_part = parts[1]
                                ip_part = parts[2]
                                status = ", ".join(parts[3:]).strip()
                                id = id_part.split("ID:")[1].strip() if "ID:" in id_part else "Unknown"
                                name = name_part.split("Name:")[1].strip() if "Name:" in name_part else "Unknown"
                                ip = ip_part.split("IP:")[1].strip() if "IP:" in ip_part else "Unknown"
                                self.agent_treeview.insert('', 'end', values=(id, name, ip, status))
                                agent_count += 1
                            else:
                                self.debug_log(f"Skipping malformed line: {line}")
                        except Exception as e:
                            self.debug_log(f"Error parsing agent line '{line}': {str(e)}")
                self.debug_log(f"Inserted {agent_count} agents into treeview")
                if agent_count == 0:
                    messagebox.showwarning("No Agents", "No agents found. Check agent_debug.log for details.")
            else:
                self.debug_log("Empty output from agent_control command")
                messagebox.showwarning("No Agents", "No agents found. Check agent_debug.log for details.")
            self.log_action("Refreshed agents list")
        except Exception as e:
            self.debug_log(f"Error in refresh_agents: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh agents: {str(e)}")
            self.log_action(f"Error refreshing agents: {str(e)}")

    def create_services_tab(self):
        tab = self.tabs['services']
        
        services = [
            ('Wazuh Manager', 'wazuh-manager'),
            ('Elasticsearch', 'elasticsearch'),
            ('Logstash', 'logstash'),
            ('Packetbeat', 'packetbeat'),
            ('Filebeat', 'filebeat'),
            ('Kibana', 'kibana'),
            ('Cowrie', 'cowrie'),
            ('Suricata', 'suricata')
        ]
        
        main_frame = tk.Frame(tab, bg=self.themes[self.current_theme]['bg_color'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        for i, (name, service) in enumerate(services):
            frame = tk.Frame(main_frame, bg=self.themes[self.current_theme]['button_bg'], 
                            padx=15, pady=15, relief=tk.RAISED, borderwidth=1)
            tk.Label(frame, text=name, bg=self.themes[self.current_theme]['button_bg'], 
                    fg=self.themes[self.current_theme]['fg_color'], 
                    font=('Helvetica', 14, 'bold')).pack(pady=5)
            
            status_label = tk.Label(frame, text="", bg=self.themes[self.current_theme]['button_bg'], 
                                  fg=self.themes[self.current_theme]['fg_color'],
                                  font=('Helvetica', 12, 'bold'))
            status_label.pack(pady=10)
            self.service_status_vars[service].append(status_label)
            
            btn_frame = tk.Frame(frame, bg=self.themes[self.current_theme]['button_bg'])
            start_btn = tk.Button(btn_frame, text="Start", 
                                 command=lambda s=service: self.control_service(s, 'start'),
                                 bg=self.themes[self.current_theme]['accent_color'], 
                                 fg=self.themes[self.current_theme]['fg_color'], 
                                 width=8, font=('Helvetica', 10))
            start_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(start_btn, f"Start {name}")
            stop_btn = tk.Button(btn_frame, text="Stop", 
                                command=lambda s=service: self.control_service(s, 'stop'),
                                bg=self.themes[self.current_theme]['critical_color'], 
                                fg=self.themes[self.current_theme]['fg_color'], 
                                width=8, font=('Helvetica', 10))
            stop_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(stop_btn, f"Stop {name}")
            restart_btn = tk.Button(btn_frame, text="Restart", 
                                   command=lambda s=service: self.control_service(s, 'restart'),
                                   bg=self.themes[self.current_theme]['button_bg'], 
                                   fg=self.themes[self.current_theme]['fg_color'], 
                                   width=8, font=('Helvetica', 10))
            restart_btn.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(restart_btn, f"Restart {name}")
            btn_frame.pack(pady=5)
            
            frame.grid(row=i//3, column=i%3, padx=20, pady=20, sticky='nsew')
            main_frame.rowconfigure(i//3)
            main_frame.columnconfigure(i%3)

    def add_agent(self):
        name = simpledialog.askstring("Add Agent", "Enter agent name:")
        if name:
            self.run_command(f"sudo /var/ossec/bin/manage_agents -a {name}", self.agent_output)
            self.log_action(f"Added agent: {name}")
            self.refresh_agents()  # Refresh agent list after adding

    def remove_agent(self):
        agent_id = simpledialog.askstring("Remove Agent", "Enter agent ID:")
        if agent_id:
            self.run_command(f"sudo /var/ossec/bin/manage_agents -r {agent_id}", self.agent_output)
            self.log_action(f"Removed agent ID: {agent_id}")
            self.refresh_agents()  # Refresh agent list after removing

    def extract_key(self):
        agent_id = simpledialog.askstring("Extract Key", "Enter agent ID:")
        if agent_id:
            self.run_command(f"sudo /var/ossec/bin/manage_agents -e {agent_id}", self.agent_output)
            self.log_action(f"Extracted key for agent ID: {agent_id}")

    def add_tooltip(self, widget, text):
        def enter(event):
            x = event.x_root + 10
            y = event.y_root + 10
            self.tooltip_label.config(text=text)
            self.tooltip_label.place(x=x, y=y)
            self.tooltip_label.lift()
        def leave(event):
            self.tooltip_label.place_forget()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def open_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.configure(bg=self.themes['light']['bg_color'])
        
        tk.Label(settings_window, text="Refresh Interval (ms):", bg=self.themes['light']['bg_color'], 
                 fg=self.themes['light']['fg_color']).pack(pady=5)
        self.refresh_entry = tk.Entry(settings_window, bg='white', fg=self.themes['light']['fg_color'])
        self.refresh_entry.insert(0, "3000")
        self.refresh_entry.pack(pady=5)
        
        tk.Label(settings_window, text="Notification Threshold (Level):", bg=self.themes['light']['bg_color'], 
                 fg=self.themes['light']['fg_color']).pack(pady=5)
        self.threshold_entry = tk.Entry(settings_window, bg='white', fg=self.themes['light']['fg_color'])
        self.threshold_entry.insert(0, str(self.notification_threshold))
        self.threshold_entry.pack(pady=5)
        
        tk.Label(settings_window, text="Wazuh Config Preview:", bg=self.themes['light']['bg_color'], 
                 fg=self.themes['light']['fg_color']).pack(pady=5)
        self.config_text = scrolledtext.ScrolledText(settings_window, height=5, width=40, 
                                                    bg='white', fg=self.themes['light']['fg_color'])
        self.config_text.pack(pady=5)
        tk.Button(settings_window, text="Preview Text", command=self.preview_config, 
                 bg=self.themes['light']['button_bg'], fg=self.themes['light']['fg_color']).pack(pady=5)
        tk.Button(settings_window, text="Apply", command=lambda: self.apply_settings(settings_window), 
                 bg=self.themes['light']['button_bg'], fg=self.themes['light']['fg_color']).pack(pady=10)

    def preview_config(self):
        try:
            with open('/var/ossec/etc/ossec.conf', 'r') as f:
                config = f.read()
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(tk.END, config)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read config: {str(e)}")

    def apply_settings(self, settings_window):
        try:
            interval = int(self.refresh_entry.get())
            threshold = int(self.threshold_entry.get())
            if hasattr(self, 'status_after_id'):
                self.root.after_cancel(self.status_after_id)
            self.status_after_id = self.root.after(interval, self.update_service_status)
            self.notification_threshold = threshold
            messagebox.showinfo("Success", f"Settings updated: Interval={interval}ms, Threshold={threshold}")
            self.log_action(f"Updated settings: Interval={interval}ms, Threshold={threshold}")
            settings_window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Invalid input for interval or threshold")

    def configure_columns(self):
        columns_window = tk.Toplevel(self.root)
        columns_window.title("Configure Columns")
        columns_window.geometry("300x400")
        columns_window.configure(bg=self.themes['light']['bg_color'])
        
        tk.Label(columns_window, text="Select Alert Columns:", bg=self.themes['light']['bg_color'], 
                 fg=self.themes['light']['fg_color']).pack(pady=5)
        available_columns = ['severity', 'timestamp', 'agent_name', 'agent_ip', 
                           'rule_id', 'rule_level', 'rule_desc', 'fired_times']
        self.column_vars = {col: tk.BooleanVar(value=col in self.selected_columns['alerts']) 
                           for col in available_columns}
        
        for col, var in self.column_vars.items():
            tk.Checkbutton(columns_window, text=col.replace('_', ' ').title(), 
                          variable=var, 
                          bg=self.themes['light']['bg_color'],
                          fg=self.themes['light']['fg_color'],
                          selectcolor=self.themes['light']['bg_color']).pack(anchor='w', padx=10)
        
        tk.Button(columns_window, text="Apply", 
                 command=lambda: self.apply_column_config(columns_window),
                 bg=self.themes['light']['button_bg'],
                 fg=self.themes['light']['fg_color']).pack(pady=10)

    def apply_column_config(self, columns_window):
        self.selected_columns['alerts'] = [col for col, var in self.column_vars.items() if var.get()]
        self.tabs['alerts'].destroy()
        self.tabs['alerts'] = ttk.Frame(self.notebook)
        self.notebook.insert(1, self.tabs['alerts'], text='Alerts')
        self.create_alerts_tab()
        self.notebook.select(self.tabs['alerts'])
        self.log_action("Updated alert table columns")
        columns_window.destroy()

    def handle_keyboard_navigation(self, event):
        if event.keysym in ('Up', 'Down', 'Left', 'Right', 'Tab'):
            return 'break'
        return None

    def log_action(self, action):
        with open('audit.log', 'a') as f:
            f.write(f"{datetime.now()}: {getpass.getuser()} - {action}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = WazuhManagerGUI(root)
    if app.authenticated:
        root.mainloop()