import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter.ttk import Style, Button, Label, Entry
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import psutil
import platform 
import threading
import time
import subprocess  # لإعادة فتح MainApp عند الرجوع

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitoring Tool")
        self.root.geometry("400x300")
        self.root.config(bg="#2c3e50")
        
        self.style = Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Arial", 12, "bold"), background="#003366", foreground="white")
        self.style.map("TButton", background=[("active", "#2980b9")])

        Label(root, text="Choose an option:", font=("Arial", 14), background="#2c3e50", foreground="white").pack(pady=20)

        Button(root, text="Log Monitoring", command=self.log_monitoring, style="TButton").pack(pady=10)
        Button(root, text="System Monitoring", command=self.system_monitoring, style="TButton").pack(pady=10)

        # زر الرجوع إلى MainApp
        tk.Button(root, text="Back", command=self.back_to_main, bg="red", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

    def back_to_main(self):
        """Return to the previous application (if applicable)."""
        self.root.destroy()
        subprocess.Popen(["python3", "main.py"])  # فتح MainApp من جديد

    def log_monitoring(self):
        self.ask_telegram_settings("Log Monitoring")

    def system_monitoring(self):
        self.ask_telegram_settings("System Monitoring")

    def ask_telegram_settings(self, monitoring_type):
        window = tk.Toplevel(self.root)
        window.title("Telegram Settings")
        window.geometry("400x200")
        window.config(bg="#2c3e50")

        Label(window, text=f"Enable Telegram Alerts for {monitoring_type}?", font=("Arial", 12), background="#2c3e50", foreground="white").pack(pady=10)

        Button(window, text="Yes", command=lambda: self.enable_telegram(window, monitoring_type), style="TButton").pack(pady=10)
        Button(window, text="No", command=lambda: self.start_monitoring_without_alerts(window, monitoring_type), style="TButton").pack(pady=10)

    def enable_telegram(self, parent_window, monitoring_type):
        parent_window.destroy()
        self.get_telegram_details(monitoring_type)

    def get_telegram_details(self, monitoring_type):
        window = tk.Toplevel(self.root)
        window.title("Telegram Details")
        window.geometry("400x250")
        window.config(bg="#2c3e50")

        Label(window, text="Enter Telegram Bot Token:", background="#2c3e50", foreground="white").pack(pady=5)
        token_entry = Entry(window, width=40)
        token_entry.pack(pady=5)

        Label(window, text="Enter Chat ID:", background="#2c3e50", foreground="white").pack(pady=5)
        chat_id_entry = Entry(window, width=40)
        chat_id_entry.pack(pady=5)

        Button(window, text="Start Monitoring", 
               command=lambda: self.start_monitoring_with_alerts(window, monitoring_type, token_entry.get(), chat_id_entry.get()), 
               style="TButton").pack(pady=20)

    def start_monitoring_with_alerts(self, parent_window, monitoring_type, bot_token, chat_id):
        parent_window.destroy()
        if monitoring_type == "Log Monitoring":
            LogMonitorApp(self.root, bot_token, chat_id).start()
        elif monitoring_type == "System Monitoring":
            SystemMonitorApp(self.root, bot_token, chat_id).start()

    def start_monitoring_without_alerts(self, parent_window, monitoring_type):
        parent_window.destroy()
        if monitoring_type == "Log Monitoring":
            LogMonitorApp(self.root).start()
        elif monitoring_type == "System Monitoring":
            SystemMonitorApp(self.root).start()


import platform  # لإضافة ميزة الكشف عن التوزيعة

class LogMonitorApp:
    def __init__(self, root, bot_token=None, chat_id=None):
        self.root = root
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.observer = None

    def get_log_path(self):
        """تحديد مسار ملف السجل بناءً على توزيعة Linux النشطة."""
        try:
            distro = platform.uname().system.lower()
            if "ubuntu" in distro or "debian" in distro:
                return "/var/log/syslog"
            elif "centos" in distro or "red hat" in distro:
                return "/var/log/messages"
            else:
                return "/var/log/syslog"  # المسار الافتراضي
        except Exception:
            return "/var/log/syslog"  # في حال حدوث خطأ

    def start(self):
        window = tk.Toplevel(self.root)
        window.title("Log Monitoring")
        window.geometry("700x500")
        window.config(bg="#2c3e50")

        self.log_display = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=80, height=20, bg="#34495e", fg="white")
        self.log_display.pack(pady=10)

        self.start_button = Button(window, text="Start Monitoring", style="TButton", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = Button(window, text="Stop Monitoring", style="TButton", state=tk.DISABLED, command=self.stop_monitoring)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.send_alert_button = Button(window, text="Send All Alerts", style="TButton", state=tk.DISABLED, command=self.send_all_alerts)
        self.send_alert_button.pack(side=tk.LEFT, padx=5)

    def start_monitoring(self):
        log_path = self.get_log_path()  # استدعاء الدالة لتحديد المسار
        self.log_display.insert(tk.END, f"Monitoring started for log file: {log_path}\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.send_alert_button.config(state=tk.NORMAL)

        self.observer = Observer()
        event_handler = LogHandler(self.log_display, self.bot_token, self.chat_id)
        self.observer.schedule(event_handler, log_path, recursive=False)
        self.observer.start()

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.log_display.insert(tk.END, "Monitoring stopped.\n")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def send_all_alerts(self):
        if self.bot_token and self.chat_id:
            all_logs = self.log_display.get("1.0", tk.END).strip()  # قراءة كل النصوص الظاهرة
            if all_logs:
                self.send_telegram_alert(all_logs)
                self.log_display.insert(tk.END, "All displayed logs sent via Telegram.\n")
            else:
                messagebox.showinfo("No Logs", "No logs to send.")
        else:
            messagebox.showwarning("Error", "Telegram details are missing!")

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": message}
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            messagebox.showinfo("Success", "Alert sent successfully.")
        else:
            messagebox.showerror("Error", f"Failed to send alert: {response.text}")

class LogHandler(FileSystemEventHandler):
    def __init__(self, log_display, bot_token, chat_id):
        self.log_display = log_display
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.suspicious_keywords = [
            "error", "failed", "exception", "critical", "fatal", "warning",
            "panic", "segfault", "denied", "unauthorized", "timeout",
            "unreachable", "refused", "invalid", "missing", "breach",
            "attack", "malware", "exploit", "vulnerability", "slow",
            "overload", "unresponsive", "degraded"
        ]

    def on_modified(self, event):
        try:
            with open(event.src_path, 'r') as file:
                lines = file.readlines()
                latest_log = lines[-1].strip()

                self.log_display.insert(tk.END, f"{latest_log}\n")
                self.log_display.see(tk.END)

                if any(keyword in latest_log.lower() for keyword in self.suspicious_keywords):
                    if self.bot_token and self.chat_id:
                        self.send_telegram_alert(latest_log)
        except Exception as e:
            self.log_display.insert(tk.END, f"Error: {str(e)}\n")
            self.log_display.see(tk.END)

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": message}
        requests.post(url, data=payload)


class SystemMonitorApp:
    def __init__(self, root, bot_token=None, chat_id=None):
        self.root = root
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.monitoring = False

    def start(self):
        window = tk.Toplevel(self.root)
        window.title("System Monitoring")
        window.geometry("700x500")
        window.config(bg="#2c3e50")

        self.system_display = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=80, height=20, bg="#34495e", fg="white")
        self.system_display.pack(pady=10)

        self.start_button = Button(window, text="Start Monitoring", command=self.start_monitoring, style="TButton")
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = Button(window, text="Stop Monitoring", state=tk.DISABLED, command=self.stop_monitoring, style="TButton")
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def start_monitoring(self):
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.system_display.insert(tk.END, "System monitoring started...\n")

        self.thread = threading.Thread(target=self.monitor_system)
        self.thread.daemon = True
        self.thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.system_display.insert(tk.END, "System monitoring stopped.\n")

    def monitor_system(self):
        while self.monitoring:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            disk_usage = psutil.disk_usage('/')

            message = (
                f"CPU Usage: {cpu_usage}%\n"
                f"Memory Usage: {memory_info.percent}%\n"
                f"Disk Usage: {disk_usage.percent}%\n"
                f"Available Memory: {memory_info.available / (1024 * 1024):.2f} MB\n"
                f"Free Disk Space: {disk_usage.free / (1024 * 1024 * 1024):.2f} GB\n\n"
            )

            self.system_display.insert(tk.END, message)
            self.system_display.see(tk.END)

            if (cpu_usage > 80 or memory_info.percent > 80 or disk_usage.percent > 90) and self.bot_token and self.chat_id:
                alert_message = f"High system usage detected!\n{message}"
                self.send_telegram_alert(alert_message)

            time.sleep(5)

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": message}
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            self.system_display.insert(tk.END, "Alert sent via Telegram.\n")
        else:
            self.system_display.insert(tk.END, f"Failed to send alert: {response.text}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
