# **SOAR Project with Wazuh, Shuffle, and TheHive**

## **Introduction**
This document provides a structured guide to building a **Security Orchestration, Automation, and Response (SOAR)** project using **Wazuh, TheHive, and Shuffle**. The project aims to create a fully functional **home SOC lab** that mimics a real SOC environment.

- To obtain a full video walkthrough to this project, thanks to **MYDFIR** here: [https://youtu.be/Lb_ukgtYK_U?si=zc0NMNwn1TfoX069]
---

## **Logical Architecture**

The SOAR lab consists of multiple interconnected components that simulate a real-world SOC environment. Below is a breakdown of the architecture:
![Wazuh-SOAR-Logical-Diagram drawio](https://github.com/user-attachments/assets/e3455032-f092-4eeb-a2c3-9e2bc9f527d0)

### **Infrastructure Setup**
- **Windows 10 Server (Wazuh Agent):** Locally virtualized using **QEMU**.
- **Ubuntu Server (Wazuh Agent):** Hosted on **Vultr Cloud**.
- **Router:** Connects endpoints to the **Wazuh Manager** and other components.
- **Internet:** Used for **alert forwarding, email notifications, and OSINT enrichment**.

### **Component Interactions & Workflow**
1. **Windows 10 Server & Ubuntu Server (Wazuh Agents)**
   - These endpoints send **security events** to the **Wazuh Manager**.

2. **Wazuh Manager**
   - Receives security events from endpoints.
   - Analyzes logs and generates alerts.
   - Triggers response actions based on **defined security policies**.

3. **Shuffle (SOAR Automation Tool)**
   - Receives alerts from **Wazuh Manager**.
   - Enriches **Indicators of Compromise (IOCs)** using **OSINT sources**.
   - Sends alerts and executes **automated response actions**.

4. **TheHive (Case Management Platform)**
   - Receives alerts from **Shuffle**.
   - Creates **cases for SOC analysts to investigate**.

5. **Email Notifications**
   - Shuffle sends **email alerts** to **SOC Analysts**.
   - Notifications include **alert details and recommended response actions**.

6. **SOC Analyst Response**
   - Analysts receive alerts and take **action if necessary**.
   - Responses can be **automated using Shuffle** or **manually handled within TheHive**.

7. **Response Actions Execution**
   - Shuffle and Wazuh perform **automated containment** or **mitigation steps**.
   - These may include **blocking IPs, disabling compromised accounts, or isolating affected hosts**.

---

## **Setting Up Machines**

### **1. Windows Virtual Machine Setup**
**Step 1: Install Windows on a Virtual Machine**
- Use **QEMU/KVM, VMware, or VirtualBox**.
- Allocate at least **4GB RAM, 2 CPU cores, and 50GB storage**.
- ![Win10-Virtual-QemuKVM-Installation](https://github.com/user-attachments/assets/939b22c6-e0e7-4ac6-98fd-a65ab8e0dc1e)
- Install **Sysmon for Windows** (for event logging & monitoring).
![Sysmon-Installation-in-WindowsServer](https://github.com/user-attachments/assets/7049f753-f8a4-42b8-832c-fb3c6fa6d514)

### **2. Linux Ubuntu Server (Vultr Cloud) Setup**
**Step 1: Deploy Ubuntu on Vultr Cloud**
- Choose **Ubuntu 22.04 LTS** for stability.
- Allocate at least **2 vCPUs, 4GB RAM, and 60GB SSD**.
![Linux-Server](https://github.com/user-attachments/assets/38fab760-f64b-471d-913e-b951a0b97814)

---

## **Wazuh Server and TheHive Server Setup**
Follow the steps in this (YouTube)[https://youtu.be/VuSKMPRXN1M?si=PT3CaLDnn13xGDyR] guide to install **Wazuh and TheHive** on a cloud server, including full configuration guidance.

### **Prerequisites**
- A cloud server (**Vultr, AWS, Azure, or GCP**).
- **Ubuntu 20.04 or 22.04** (recommended OS for Wazuh).
- **SSH access** to the cloud server.

---

## **Rules and Rulesets in Wazuh**

### **What Are Wazuh Rules?**
Wazuh rules define **how logs and events are analyzed** to detect threats. These rules categorize and flag **suspicious activities** based on predefined patterns.

### **Types of Rules in Wazuh**
1. **Sysmon Rules** – Detects **suspicious process creation, registry changes, and network connections**.
2. **Authentication Rules** – Identifies **failed login attempts, privilege escalation, and unauthorized access**.
3. **Malware Detection Rules** – Flags **known malware behavior and execution patterns**.
4. **Custom Rules** – Allows **users to define their own detection criteria**.

### **How Rulesets Work**
- **Default Rulesets:** Provided by Wazuh to detect common attack vectors for example in our case, Wazuh can automatically detect authentication failues and success.
- **Custom Rulesets:** Organizations can modify or create new rules based on specific security needs. In my case I used custom rules to later detect mimikatz. Custom rules are created by editing the local_rules.xml file within wazuh. Keep note of restarting your Wazuh manager after every addition of custom rules
- **Alert Levels:** Severity ranges from **1-15** to prioritize incidents.

- Below is the custom rule which I used to detect mimikatz running on my Windows endpoint. This rule checks for mimikatz by tracking the process images.

```xml
<group name="windows, sysmon, sysmon_process-anomalies">
   <rule id="100000" level="12">
     <if_group>sysmon_event1</if_group>
     <field name="win.eventdata.image">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process - mimikatz.exe</description>
   </rule>
   <rule id="100001" level="12">
     <if_group>sysmon_event8</if_group>
     <field name="win.eventdata.sourceImage">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process mimikatz.exe created a remote thread</description>
   </rule>

   <rule id="100002" level="12">
     <if_group>sysmon_event_10</if_group>
     <field name="win.eventdata.sourceImage">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process mimikatz.exe accessed $(win.eventdata.targetImage)</description>
   </rule>
</group>
```

---

## **Alerts in Wazuh**

### **What Are Alerts in Wazuh?**
Alerts are notifications generated when Wazuh detects an *event that matches a rule*. These alerts help security analysts identify potential threats and take action.

### **How Alerts Are Generated**
- **Log Analysis:** Wazuh scans system logs for anomalies.
- **Correlation Engine:** Matches logs against predefined rules.
- **Severity Levels:** Alerts are classified based on **impact**.
- **Visualization:** Dashboards display alerts for **easy real-time analysis**.

---

## **Telemetry: Generating Security Events**

### **What is Telemetry in Security Monitoring?**
Telemetry in cybersecurity refers to the process of collecting, processing, and analyzing security-related data from various endpoints to detect malicious activity. This allows security teams to respond quickly to potential threats and intrusions.

### **Using Mimikatz for Credential Dumping**
- **Mimikatz** is a tool that extracts credentials from memory in **Windows systems**.Attackers often use it to dump plaintext passwords, hash values, and Kerberos tickets.
- I installed mimikatz on my windows endpoint just for telemetry and triggering of custom alerts which one can create custom rules in wazuh by adding them in the local_rules.xml.

### **How Wazuh Detects Mimikatz Activity**
- Wazuh monitors system logs and processes for suspicious activity related to credential dumping. It uses:
- **·	Sysmon Event Logs**: Detects execution of mimikatz.exe.
- **·	Windows Security Logs**: Identifies suspicious authentication attempts.
- **·	Rule-Based Alerts**: Flags processes that match known attack patterns.
- Based on our previously defined custom rule to detect mimikatz and then running it on my windows endpoint as we can see below, by just running mimikatz Wazuh has been able to detect the event and has created and alert.
![Wazuh-Mimikatz-Detected-Events](https://github.com/user-attachments/assets/157d1352-882b-47a8-94e3-87a2b97ef393)


# SSH Brute Force Attacks

Brute force attacks involve systematically trying multiple username-password combinations to gain unauthorized access to a system.

## How Wazuh Detects SSH Brute Force Attacks

- Failed Authentication Attempts: Wazuh monitors multiple failed login attempts from the same IP.
- Log Correlation: It detects unusual login behavior across different endpoints.
- Rule Thresholds: Wazuh flags IPs that exceed predefined login failure limits.
![Authentication-Monitoring-On-Linux(SSH-BruteForce)](https://github.com/user-attachments/assets/f933a4f4-4df7-4ad7-9ad6-7ca661565ee4)

From the screenshot:
- 104 Authentication Failures detected
- Top Alerts include failed SSH login attempts(Because my linux machine was exposed to the Internet)
- Threat Hunting Dashboard provides insights into attack patterns

By correlating logs, Wazuh can identify brute force attempts and block malicious IPs.

# Automation with Shuffle, TheHive, and Wazuh

## Shuffle

Shuffle is an open-source Security Orchestration, Automation, and Response (SOAR) platform. It allows security teams to automate repetitive tasks and integrate security tools through a drag-and-drop workflow builder.
(https://shuffler.io)

### How It Helps

- Eliminates manual security processes by automating workflows.
- Connects multiple security tools without complex coding.
- Speeds up threat response by automating alerts, case management, and incident handling.

### How Shuffle Works

- Triggers (Webhooks, alerts, or scheduled tasks) initiate workflows.
- Processing actions (Regex, lookups, parsing) extract and analyze data.
- Integrations (TheHive, Wazuh, VirusTotal, email) automate responses.

## TheHive

TheHive is an open-source Security Incident Response Platform used by SOC teams to manage, analyze, and respond to cybersecurity incidents.

### How It Helps

- Centralized Incident Management: Aggregates and tracks all alerts in one place.
- Collaboration Features: Allows multiple analysts to work on cases simultaneously.
- Automated Workflows: Can trigger actions when alerts are received from Wazuh or Shuffle.

### How TheHive Works

- Receives alerts from SIEM tools (like Wazuh).
- Creates cases with full context (IP, attack vector, timestamps).
- Triggers response actions (assign analysts, execute scripts, notify teams).

## Wazuh Integration with Shuffle & TheHive

For a full step-by-step integration guide, refer to: (YouTube: Automating SOC with Wazuh & TheHive)[https://youtu.be/GNXK00QapjQ?si=tHotMuof_zpQeiB0]

## My use case: Mimikatz Workflow with Shuffle

I automated the detection and response for Mimikatz credential dumping attacks.
![SOAR-SOC-Workflow-Shuffle](https://github.com/user-attachments/assets/eb12e861-a2ef-45c0-b1f8-de89da1b266d)

🔗 **Workflow Breakdown:**
1. Webhook Trigger – Detects a Mimikatz execution event from Wazuh logs.
2. Regex Matching – Extracts SHA256 hash values from the logs.
3. VirusTotal Lookup – Checks if the detected hash is known malware.
4. TheHive Alert Creation – Sends an automated alert to TheHive.
5. Email Notification – Notifies SOC analysts via automated emails from Shuffle.

I later then rerun mimikatz on my windows endpoint now for triggering the automation workflow and it clearly did end up creating an alert on TheHive and enriching the IOCs and eventually sending an email to me.
![TheHIVE-Alerts-SOAR](https://github.com/user-attachments/assets/16db335c-6b6a-430b-a5e9-5cd358430752)

**Above: An alert recieved on suspicious processed detected (mimikatz)**
![SOAR-Shuffle-Emailing-Workflow](https://github.com/user-attachments/assets/90c1b9d5-a4ce-4576-b651-458483a34179)

**Above: Succesful Email recieved from the automation process.**

## Why is SOAR Important?

- Reduces Response Time – Automates security workflows, cutting incident response time from hours to seconds.
- Minimizes Analyst Fatigue – Reduces repetitive manual tasks like triaging alerts and blocking IPs.
- Improves SOC Efficiency – Allows faster, data-driven decisions by integrating various security tools.
- Enhances Threat Intelligence – Automatically enriches alerts with data from VirusTotal, Wazuh, TheHive, and other security sources.

## How SOAR Helps SOC Teams

| Challenge | How SOAR Solves It |
| --- | --- |
| Too Many Alerts ⚠️ | Automatically filters and prioritizes real threats. |
| Slow Incident Response 🕒 | Automates remediation actions like blocking IPs or isolating endpoints. |
| Limited SOC Staff 👨‍💻 | Reduces manual workload, allowing analysts to focus on critical investigations. |
| Lack of Tool Integration 🔧 | Connects SIEM (Wazuh), case management (TheHive), and security tools. |
