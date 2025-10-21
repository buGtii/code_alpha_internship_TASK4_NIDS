# 🛡️ Task 4 — Network Intrusion Detection System (Suricata)

**Intern:** Muhammad Faisal  
**Program:** CodeAlpha Cybersecurity Internship  
**Task Name:** Implementing Network Intrusion Detection System  
**Platform:** Kali Linux (VirtualBox)

---

## 🎯 Objective
To deploy and test a **Network Intrusion Detection System (NIDS)** using **Suricata** that monitors, detects, and alerts on suspicious network traffic such as phishing form submissions, port scans, and SQL injection attempts.

---

## ⚙️ Tools Used
- **Suricata** – IDS Engine  
- **suricata-update** – Rule management tool  
- **Nmap** – Network scanner  
- **Nikto** – Web vulnerability scanner  
- **Curl** – HTTP request simulator  
- **jq** – JSON log parser  

---

## 🧠 Steps Performed

1. **Installed Suricata**
   ```bash
   sudo apt update && sudo apt install suricata jq -y
   suricata --build-info

2. Configured interface in /etc/suricata/suricata.yaml

interface: eth0


3. Enabled JSON output logging in eve.json


4. Added custom detection rules
File: /etc/suricata/rules/local.rules

alert http any any -> any any (msg:"PHISHING_DEMO_HTTP_POST"; flow:established,to_server; http.method; content:"POST"; nocase; http.uri; content:"/log"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"POSSIBLE_NMAP_TCP_SCAN"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)


5. Updated Rules

sudo suricata-update
sudo systemctl restart suricata


6. Generated Traffic for Testing

curl -X POST http://testphp.vulnweb.com/login.php -d "username=victim&password=12345"
sudo nmap -sS -T4 testphp.vulnweb.com
nikto -h http://testphp.vulnweb.com
curl "http://testphp.vulnweb.com/listproducts.php?cat=1' OR '1'='1"


7. Viewed Alerts

sudo jq -r 'select(.event_type=="alert") | "\(.timestamp) \(.src_ip) -> \(.dest_ip) \(.alert.signature)"' /var/log/suricata/eve.json | tail -n 20



 Example Alerts

2025-10-21T09:14:01Z 192.168.0.12 -> 34.253.12.11 PHISHING_DEMO_HTTP_POST
2025-10-21T09:14:15Z 192.168.0.12 -> 34.253.12.11 POSSIBLE_NMAP_TCP_SCAN
2025-10-21T09:14:15Z 192.168.0.12 -> 34.253.12.11 POSSIBLE_NIKTO_SCAN
2025-10-21T09:14:22Z 192.168.0.12 -> 34.253.12.11 ET INFO Suspicious User-Agent SQLmap/1.0


---

Screenshots

File Name	Description

TASK4_suricata_running.png	Suricata running successfully
TASK4_local_rules.png	Local custom detection rules
TASK4_alerts_tail.png	Alerts displayed from eve.json
TASK4_nmap_scan.png	Nmap scan simulation
TASK4_nikto_scan.png	Nikto web scan results


Status

 Task Completed Successfully
Suricata IDS deployed and tested on Kali Linux. Alerts successfully triggered and analyzed from simulated attack traffic.



Recommendations

Update rulesets regularly using sudo suricata-update

Integrate with EveBox or Elastic Stack (ELK) for visual analysis

Tune rule thresholds to minimize false positives

Expand to IPS (inline) mode for active blocking in future tasks
