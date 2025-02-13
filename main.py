import tkinter as tk
from tkinter.ttk import Button, Style
import subprocess
from tkinter import messagebox

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BAAD Tool")
        self.root.geometry("400x300")
        self.root.config(bg="#2c3e50")
        
        self.style = Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Arial", 12, "bold"), background="#003366", foreground="white")
        self.style.map("TButton", background=[("active", "#2980b9")])

        # إنشاء شريط العنوان الثابت (Sticky Header)
        self.header_frame = tk.Frame(root, bg="#34495e", height=50)
        self.header_frame.pack(fill="x", side="top")
        
        tk.Label(self.header_frame, text="BAAD Tool", font=("Arial", 16, "bold"), fg="white", bg="#34495e").pack(pady=10)

        # إضافة الأزرار مع تحسينات التفاعل
        self.add_button("Encryption", self.open_crypto)
        self.add_button("Hash and Integrity", self.open_hash)
        self.add_button("Logs and System Monitoring", self.open_monitoring)

    def open_crypto(self):
        """فتح نافذة التشفير"""
        self.root.destroy()  # إغلاق نافذة الـ Main
        try:
            subprocess.Popen(["python3", "crypto.py"])  # استدعاء ملف التشفير
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open crypto.py: {str(e)}")

    def open_hash(self):
        """فتح نافذة الهاش"""
        self.root.destroy()  # إغلاق نافذة الـ Main
        try:
            subprocess.Popen(["python3", "hashh.py"])  # استدعاء ملف الهاش
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open hashh.py: {str(e)}")

    def open_monitoring(self):
        """فتح نافذة مراقبة النظام"""
        self.root.destroy()  # إغلاق نافذة الـ Main
        try:
            subprocess.Popen(["python3", "data_analysis.py"])  # استدعاء ملف مراقبة النظام
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open data_analysis.py: {str(e)}")

    def add_button(self, text, command):
        """إضافة الأزرار مع تحسين التفاعل"""
        button_frame = tk.Frame(self.root, bg="#2c3e50")
        button_frame.pack(pady=10, fill="x")
        
        button = Button(button_frame, text=text, style="TButton", command=command)
        button.pack(pady=10, padx=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
