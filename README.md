# 🔒 BAAD Tool - Comprehensive Data Protection  


---


## 📌 Overview  
**BAAD Security Tool** is a powerful Linux-based security tool designed for:  
✅ **Real-time Log Monitoring** using the `watchdog` library.  
✅ **Automatic Detection of Suspicious Activities** based on predefined keywords.  
✅ **Telegram Alerts** for instant notification of security threats.  
✅ **User-Friendly GUI** built with `Tkinter`.  

This tool is built **exclusively for Linux** and is ideal for system administrators and security professionals looking for an easy-to-use, automated security monitoring solution.  

---

## 🛠️ System Requirements  
Ensure your Linux system meets the following requirements:  
- **OS**: Linux (Ubuntu, Debian, Kali, CentOS, etc.)  
- **Python**: 3.8+  
- **Dependencies**: Listed in `requirements.txt`  

---

## 📥 Installation & Setup  

### 1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/YOUR_USERNAME/BAAD-Security-Tool.git
cd BAAD-Security-Tool
```

### 2️⃣ **Install Dependencies**  
```bash
pip install -r requirements.txt
```

### 3️⃣ **Grant Execution Permissions (for Linux users)**  
```bash
chmod +x main.py
chmod +x hash.py
chmod +x crypto.py
```

---

## ▶️ Usage  

### **Start the Main Tool**  
```bash
python main.py
```
or (if you granted execution permissions):  
```bash
./main.py
```



---

## 📊 Example Output  
When running the tool, you will see logs like:  
```bash
[INFO] Monitoring started...
[ALERT] Suspicious activity detected in /var/log/syslog
[INFO] Sending Telegram alert...
[INFO] Monitoring stopped.
```

---

## 🔧 Configuration  

### **To configure Telegram notifications:**  
1. Create a bot using [BotFather](https://t.me/botfather).  
2. Get your **BOT_TOKEN** and **CHAT_ID**.  
3. Open `config.json` and update:  
```json
{
  "TELEGRAM_BOT_TOKEN": "your_bot_token_here",
  "CHAT_ID": "your_chat_id_here"
}
```

---

## 🚀 Future Enhancements  
✔️ Expand support for multiple log files.  
✔️ Improve keyword detection with regex filtering.  
✔️ Introduce log anomaly detection using machine learning.  
✔️ Add support for email notifications.  

---

## 🛡️ Disclaimer  
This tool is intended for **legal security monitoring** and **ethical use only**.  
The author is **not responsible** for any misuse or illegal activities.  

---

## 🤝 Contributing  
Contributions are welcome!  
1. **Fork** the repository.  
2. **Create a new branch** for your feature or bug fix.  
3. **Submit a pull request**.  

---

## 📧 Contact  
For support or inquiries:  
📩 **Email**: baraa.sahmoud02@gmail.com  
🔗 **GitHub Issues**: [Open an issue](https://github.com/BaraaS002/BAAD-Tool/issues)  
```

---

