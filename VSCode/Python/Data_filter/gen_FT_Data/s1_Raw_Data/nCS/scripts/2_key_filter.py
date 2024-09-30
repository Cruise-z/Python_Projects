import json
import os
import re

'''
Prompt:
现需要通过关键词筛选的方法对一个较大的数据集进行分类，需要分类出其中与网络安全相关/不相关的部分，现在需要你给出与网络安全强相关的关键词。关键词按照如下小分类生成：
1.perimeter
2.physical-security
3.cybersecurity-careers
4.identity-access-management-security
5.cyber-risk
6.endpoint-security
7.ics-ot-security
8.vulnerabilities-threats
9.cloud-security
10.threat-intelligence'
11.application-security
12.cybersecurity-analytics
13.cyberattacks-data-breaches
要求：
1.生成关键词与网络空间安全强相关
2.覆盖网络安全的领域尽量广，内容更为完备
3.不少于1000词, 生成英文的关键词, 关键词的全称和缩写分别存放，不是以全称(缩写)的形式组织，方便后续筛选
4.关键词有长有短，尽量缩短关键词(比如合理的截断等等)，使得可以匹配成功的概率尽量提高
4.生成的关键词以python列表的方式组织起来
'''

keywords = [
    "Cybersecurity", "password", 
    "Firewalls", "IDS", "IPS", "DMZ", "Network Segmentation", "NAC", "VPN", "SSL", "TLS", "NAT", "Proxies", 
    "Content Filtering", "Stateful Inspection", "Packet Filtering", "Honeypots", "Bastion Hosts", "Demarcation Point", 
    "Perimeter Network", "BGP Security", "Port Knocking", "NGFW", "DPI", "SSH", "Secure Web Gateway", "Remote Access Control", 
    "UTM", "Network Border", "Anomaly Detection", "NIDS", "NIPS", "Perimeter Defense", "Zone-Based Firewalls", 
    "NSM", "Perimeter Control", "Threat Hunting", "Application Layer Gateway", "Network Hardening", "Network Assessment", 
    "VLAN Segmentation", "SIEM", "Firewall Policy", "Border Router Security", "WIDS", "Perimeter Rules", "Network Demilitarization", 
    "DMZ Architecture", "Gateway Security", "Network Boundaries", "Defense in Depth", "Traffic Control",

    "Access Control Systems", "Biometric Security", "Surveillance", "Security Guards", "PSIM", "Mantraps", 
    "Motion Sensors", "Key Card Access", "Security Fencing", "Security Bollards", "Intrusion Alarms", "Secure Facilities", 
    "Security Lighting", "Physical Locks", "CCTV", "Entry Points", "Server Rooms", "Data Center Security", 
    "Environmental Controls", "Security Badging", "Guard Patrols", "Access Points", "Intrusion Detection", "Security Gates", 
    "Electronic Access", "Security Barriers", "Physical Assessment", "Access Auditing", "PIDS", "Controlled Access", 
    "Physical Policy", "Security Planning", "Access Policy", "Storage Security", "Locked Cabinets", "Video Surveillance", 
    "Security Patrols", "Emergency Planning", "Building Security", "Physical Training", "Perimeter Fencing", "Parking Security", 
    "Security Turnstiles", "Loading Docks", "Incident Response", "Physical Auditing", "Biometrics Access", "Identification Badges", 
    "Zone Classification", "Controlled Rooms",

    "Security Analyst", "Security Engineer", "Security Architect", "Security Consultant", "Penetration Tester", 
    "Ethical Hacker", "Security Researcher", "Incident Responder", "Forensic Analyst", "Threat Hunter", "SOC Analyst", 
    "Cybersecurity Manager", "CISO", "Vulnerability Analyst", "Risk Analyst", "Security Auditor", "Malware Analyst", 
    "Red Team", "Blue Team", "Cryptographer", "Cybersecurity Specialist", "Network Security Engineer", "Cloud Security Engineer", 
    "App Security Engineer", "IAM Specialist", "Cybersecurity Consultant", "InfoSec Officer", "Compliance Analyst", 
    "Cybersecurity Instructor", "Security Manager", "Awareness Trainer", "Cybersecurity Architect", "Systems Administrator", 
    "Cybersecurity Tech", "Assurance Analyst", "Security Developer", "IT Security Specialist", "Project Manager", 
    "Forensics Investigator", "Risk Analyst", "Defense Analyst", "Incident Specialist", "Policy Advisor", "Governance Specialist", 
    "Network Defense", "Ops Manager", "Infrastructure Engineer", "Systems Analyst", "Compliance Manager", "Data Protection Officer",

    "MFA", "SSO", "IdP", "PAM", "RBAC", "IGA", "Password Management", "ACLs", "User Provisioning", "Identity Federation", 
    "Lifecycle Management", "User Auth", "Biometric Auth", "Access Management", "Identity Verification", "IAM Policy", 
    "Auth Tokens", "Directory Services", "LDAP", "Digital Certificates", "PKI", "Zero Trust", "Credential Management", 
    "Identity Repos", "ABAC", "Identity Sync", "FIM", "Identity Assurance", "JIT Access", "Adaptive Auth", "Identity Auditing", 
    "SAML", "OAuth", "OpenID Connect", "Kerberos Auth", "User Deprovisioning", "Dynamic Access", "Access Reviews", 
    "Privilege Protection", "Identity Fraud", "Access Analytics", "CA", "Passwordless Auth", "Identity Theft", 
    "Lockout Policies", "Contextual Access", "Access Policies", "Identity Encryption", "IBE", "Credential Stuffing",

    "Risk Assessment", "Threat Modeling", "Risk Mitigation", "Security Assessment", "RMF", "Risk Tolerance", 
    "Cyber Insurance", "Risk Register", "BIA", "Risk Appetite", "Risk Treatment", "Risk Analysis", "TPRM", "Supply Chain Risk", 
    "Residual Risk", "Control Measures", "Quantitative Analysis", "Qualitative Analysis", "Risk Indicators", "Risk Scoring", 
    "Vulnerability Management", "Cyber Resilience", "Risk Acceptance", "Threat Landscape", "ERM", "Risk Monitoring", 
    "Risk Reporting", "Threat Modeling", "Risk Evaluation", "Threat Analysis", "Risk Quantification", "Scenario Analysis", 
    "Risk Exposure", "Inherent Risk", "Risk Communication", "Regulatory Risk", "Compliance Risk", "Scenario Planning", 
    "Control Risk", "Threat Exposure", "Risk Map", "Asset Identification", "Impact Analysis", "Threat Intelligence", 
    "Control Effectiveness", "Risk Frameworks", "Cyber Hygiene", "Threat Surface", "Hunting Risk", "Incident Risk",

    "Antivirus", "EDR", "MDM", "Device Encryption", "EPP", "HIPS", "Disk Encryption", "Endpoint Firewall", 
    "App Whitelisting", "Device Control", "HIDS", "Patch Management", "Secure Boot", "Endpoint Policy", "DLP", 
    "Backup Solutions", "USB Security", "Endpoint NAC", "Personal Firewalls", "Malware Protection", "Endpoint Hardening", 
    "Device Auth", "MAM", "Endpoint Forensics", "Behavior Analytics", "Endpoint Compliance", "Remote Wipe", 
    "Host Firewall", "Sandboxing", "Endpoint Config", "UBA", "Endpoint Visibility", "Browser Isolation", "VDI Security", 
    "Remote Access", "Endpoint Encryption", "BYOD Security", "ZTNA", "Endpoint Intelligence", "Fingerprinting", 
    "Host Hardening", "Incident Response", "Email Security", "Malware Sandboxing", "Threat Containment", 
    "Device Integrity", "MDR", "Privilege Management", "Threat Prevention",

    "ICS Security", "OT Security", "SCADA Security", "PLC Security", "HMI Security", "SCADA", "Network Segmentation", 
    "Modbus Security", "DCS Security", "Threat Detection", "Field Device Security", "Incident Response", "Risk Management", 
    "OT Monitoring", "Patch Management", "Asset Management", "Network Protocols", "OT Endpoint Security", "System Policies", 
    "Anomaly Detection", "Cybersecurity Standards", "ISA/IEC 62443", "NERC CIP", "Industrial Firewall", "Network Security", 
    "Network Isolation", "Security Monitoring", "Incident Plan", "Device Auth", "Security Assessment", 
    "Remote Access Security", "Vulnerability Management", "Intrusion Detection", "Threat Intelligence", "Security Auditing", 
    "Device Encryption", "Remote Access", "Awareness Training", "Infrastructure Protection", "Network Defense", 
    "Data Integrity", "Cybersecurity Training", "Anomaly Detection", "Threat Modeling", "Secure Communication", 
    "Incident Management", "Security Testing", "Forensics",

    "Zero-Day", "CVE", "Buffer Overflow", "SQL Injection", "XSS", "CSRF", "MITM", "DoS", "DDoS", "Phishing", 
    "Ransomware", "Trojan", "Spyware", "Adware", "Rootkits", "Malware", "Backdoors", "Command Injection", "Directory Traversal", 
    "Privilege Escalation", "RCE", "DNS Spoofing", "ARP Spoofing", "Cryptojacking", "File Inclusion", "Drive-by Downloads", 
    "Weak Encryption", "Insecure Deserialization", "IDOR", "DLL Hijacking", "HTTP Splitting", "Clickjacking", "Code Injection", 
    "Buffer Exploits", "Session Fixation", "Transport Protection", "Authorization", "Weak Passwords", "Insecure APIs", 
    "Brute Force", "Credential Reuse", "Redirects", "Session Hijacking", "File Uploads", "Misconfiguration", 
    "Broken Auth", "Data Exposure", "CORS", "Parameter Pollution", "XXE", "JWT Attacks", "Heap Spraying", "Cache Poisoning", 
    "Watering Hole", "Bashware", "BlueBorne", "Poodle", "Heartbleed", "Shellshock", "EternalBlue", "Spectre", "Meltdown", 
    "Rowhammer", "Session Replay", "Padding Oracle", "Click Fraud", "Shadow IT", "Rogue APs", "BlueSnarfing", "Keyloggers", 
    "Malvertising", "Eavesdropping", "Formjacking", "Exploit Kits", "Typosquatting",

    "CASB", "Cloud IAM", "Cloud Encryption", "Cloud DLP", "CSPM", "Cloud Infrastructure", "Cloud Detection", "Cloud Storage", 
    "Cloud Compliance", "Cloud Policies", "CWPP", "Cloud App Security", "Cloud-Native Security", "Cloud Firewall", "Cloud Controls", 
    "API Gateway", "Multi-Cloud", "Serverless", "Container Security", "Cloud Auditing", "Cloud IAM", "VPC Security", 
    "Cloud Frameworks", "Key Management", "Cloud Privacy", "Cloud Networking", "Cloud Communications", "Cloud Assessment", 
    "Cloud Incident Response", "Cloud Training", "Shared Responsibility", "Cloud Orchestration", "Cloud Deployment", 
    "Cloud Access", "Cloud Monitoring", "Cloud Infrastructure", "Cloud Governance", "Cloud Architecture", "Cloud Analytics", 
    "Cloud Auditing", "Cloud Threat Intelligence", "Cloud Pen Testing", "Cloud Risk Management", "Cloud Best Practices", 
    "Cloud Development", "Cloud Data Security", "Cloud Access Controls", "Cloud Threats", "Cloud Logging", "Cloud Migration", 
    "Cloud Policy Enforcement", "Cloud Tools", "SaaS Security", "Cloud Automation", "Cloud Compliance", "Cloud Workload Security", 
    "Cloud Hardening", "Cloud Testing", "Cloud Containers", "Cloud Networking", "Cloud Vulnerability Management", 
    "Cloud Intrusion Detection", "Cloud Integrity", "Cloud Collaboration", "Cloud KMS", "Cloud Posture", "Cloud Backup", 
    "Cloud Compliance Monitoring", "Cloud Classification", "Cloud Pen Testing", "Cloud Assessment Tools", "Cloud Visibility", 
    "Cloud API Management", "Cloud Access Management", "Cloud Threat Modeling",

    "Threat Feeds", "OSINT", "Threat Indicators", "IOCs", "TIP", "Threat Hunting", "Tactical Intelligence", "Strategic Intelligence", 
    "Intelligence Sharing", "CTI", "Threat Profiling", "Intelligence Reports", "TTPs", "Intelligence Lifecycle", "Threat Analysis", 
    "Threat Attribution", "Threat Contextualization", "Intelligence Automation", "Threat Detection", "Intelligence API", 
    "Intelligence Frameworks", "Threat Correlation", "Intelligence Gathering", "Threat Landscape", "Intelligence Platforms", 
    "Threat Sharing", "Intelligence Management", "Threat Enrichment", "Indicator Management", "Threat Analytics", 
    "Intelligence Aggregation", "Intelligence Collection", "Intelligence Integration", "Intelligence Curation", "Threat Reporting", 
    "Intelligence Tools", "Intelligence Analysis", "Intelligence Visualization", "Feed Management", "Intelligence Dissemination", 
    "Intelligence Use Cases", "SOC Intelligence", "SIEM Integration", "Intelligence Sources", "Intelligence Standards", 
    "Intelligence Workflows", "Contextualization Tools", "Incident Response Intelligence", "Intelligence Metrics", 
    "Vulnerability Intelligence", "Playbooks", "Platforms Integration", "Red Team Intelligence", "Cyber Defense", 
    "Risk Management", "Malware Analysis", "Network Security", "Intelligence Indicators", 
    "Threat Feeds", "Threat Network", "Threat Detection", "Intelligence Assessment", "Enrichment Tools", 
    "Data Collection", "Reporting Tools", "Analysis Tools", "Risk Management Intelligence", "Endpoint Intelligence", 
    "API Integration", "Management Tools", "Automation Tools", "OT Intelligence", "Cloud Intelligence", "ICS Intelligence", 
    "App Security Intelligence", "Vulnerability Analysis", "Breach Analysis", "SOC Analysts", "Incident Teams", 
    "Red Team Ops", "Blue Team Ops", "Data Integration", "Feed Analysis", "Security Engineers", 
    "Consultants", "Architects", "CISOs", "Security Analysts", "Hackers", "Testers", "Malware Researchers", 
    "Forensics", "Frameworks", "Security Policies", "Security Strategy",

    "SDLC", "SAST", "DAST", "RASP", "AST", "Code Review", "App Hardening", "Coding Practices", "Software Design", 
    "App Whitelisting", "Code Signing", "WAF", "App Scanning", "App Testing", "Threat Modeling Apps", "API Development", 
    "Mobile App Dev", "App Policies", "App Frameworks", "OWASP", "Code Analysis", "App Deployment", "App Assessments", 
    "App Compliance", "Coding Standards", "Software Deployment", "App Architecture", "App Controls", "App Best Practices", 
    "Software Config", "SCA", "App Monitoring", "App Training", "App Awareness", "Testing Tools", "App Risk Management", 
    "App Threat Modeling", "Software Libraries", "App Auditing", "App Metrics", "Software Updates", "DevOps", "CI/CD", 
    "App Integration", "App Automation", "App Logging", "App Patching", "Agile", "Web Apps", "Mobile Apps", "Desktop Apps", 
    "Cloud Apps", "App Governance", "App Remediation", "Incident Response", "Microservices", "App Auth", 
    "App Authorization", "Design Patterns", "App Config", "APIs", "Testing Frameworks", "Tools Integration", "Program Management", 
    "Software Dev", "Software Maintenance", "Software Ops", "Software Testing", "Web Services", "REST APIs", "SOAP APIs", 
    "Microservices Apps", "Containerized Apps", "Serverless Apps", "Web Browsers", "Web Servers", "CMS", "E-commerce", 
    "Payment Gateways", "Financial Apps", "Healthcare Apps", "IoT Apps", "Automotive Apps", "Smart Home Apps", 
    "Industrial Apps", "Enterprise Apps", "SaaS", "Cloud-Native Apps", "Multi-Tenant Apps", "Blockchain Apps", 
    "AI Apps", "ML Apps", "Big Data Apps", "Data Analytics Apps", "BI Apps", "Mobile Payments", "Digital Wallets", 
    "Cryptocurrencies", "Smart Contracts", "Distributed Apps", "VR Apps", "AR Apps", "Gaming Apps", "Social Media Apps", 
    "Communication Apps", "Messaging Apps", "Video Streaming", "Live Streaming", "Collaborative Apps", "Remote Work", 
    "Video Conferencing", "E-learning", "Online Education", "LMS", "Online Assessment", "E-book Readers", "Digital Publishing", 
    "News Apps", "Weather Apps", "Travel Apps", "Transportation Apps", "Logistics Apps", "Supply Chain", "Inventory Management", 
    "Retail Apps", "POS Systems", "CRM Systems", "ERP Systems", "HRMS", "Project Management", "Time Management", 
    "Productivity Apps", "Note-Taking", "Document Management", "File Sharing", "Cloud Storage", "Backup Apps", "Data Sync", 
    "Data Migration", "Data Integration", "Data Transformation", "Data Visualization", "Data Reporting", "Data Processing", 
    "Data Mining", "Data Warehousing", "Data Lakes", "Big Data Platforms", "Distributed Data", "NoSQL", "Relational DBs", 
    "Graph DBs", "In-Memory DBs", "Time Series DBs", "Geospatial DBs", "Columnar DBs", "Object-Oriented DBs", "Blockchain DBs", 
    "Immutable DBs", "Real-Time DBs", "Event-Driven", "Reactive Apps", "Message-Oriented Middleware", "SOA", "Microservices Architecture", 
    "Serverless Architecture", "Edge Computing", "Fog Computing", "Hybrid Cloud Apps", "Multi-Cloud Apps", "Cloud-Native Apps", 
    "Kubernetes Apps", "Docker Apps", "Containerized Apps", "Orchestration Apps", "IaC", "PaaS", "IaaS", "SaaS", "FaaS", 
    "NFV", "SDN", "Virtualization", "Hypervisors", "VMs", "VDI", "Remote Desktop", "Remote Access", "VPN Apps", "Proxy Apps", 
    "Reverse Proxy", "Web Proxy", "Email Security", "Spam Filtering", "Anti-Phishing", "Anti-Spam", "Anti-Virus", "Anti-Malware", 
    "Anti-Rootkit", "Anti-Ransomware", "Anti-Spyware", "Anti-Adware", "Content Filtering", "Web Filtering", "URL Filtering", 
    "DNS Filtering", "Data Filtering", "Data Masking", "Data Encryption", "Data Decryption", "Data Tokenization", 
    "Data Obfuscation", "Data Scrambling", "Data Sanitization", "Data Anonymization", "Data Pseudonymization", "Data Aggregation", 
    "Data Compression", "Data Deduplication", "Data Clustering", "Data Classification", "Data Labeling", "Data Annotation", 
    "Data Cleansing", "Data Normalization", "Data Standardization", "Data Validation", "Data Verification", "Data Quality", 
    "Data Consistency", "Data Integrity", "Data Accuracy", "Data Completeness", "Data Timeliness", "Data Availability", 
    "Data Redundancy", "Data Resilience", "Data Durability", "Data Backup", "Data Recovery", "Data Archiving", "Data Retention", 
    "Data Purging", "Data Deletion", "Data Destruction", "Data Disposal", "Data Shredding", "Data Wiping", "Data Erasure",

    "SIEM", "SOAR", "Anomaly Detection", "UBA", "Network Analysis", "Log Analysis", "Threat Response", "Analytics Platforms", 
    "Data Analytics", "ML Security", "AI Detection", "Data Mining", "Threat Analytics", "Incident Analytics", "Endpoint Analytics", 
    "Real-Time Monitoring", "Network Forensics", "Data Visualization", "APT Detection", "Data Correlation", "Big Data Analytics", 
    "Threat Intelligence Analytics", "Event Correlation", "Predictive Analytics", "Behavior Analytics", "Metrics Analytics", 
    "Risk Analytics", "Vulnerability Analytics", "Data Lakes", "Breach Analysis", "Ops Analytics", "Cloud Analytics", 
    "Insider Threat Analytics", "App Security Analytics", "Phishing Analytics", "Data Exfiltration", "Security Dashboard", 
    "Intrusion Detection", "Pattern Recognition", "Real-Time Detection", "Advanced Analytics", "Hunting Analytics", 
    "Security Intelligence", "Anomaly Detection", "Data Science", "Malware Analytics", "Incident Response", "Log Management", 
    "Packet Analysis", "Audit Analytics", "Alerting and Reporting", "Reporting Tools", "Data-Driven Security", "Analytics Tools", 
    "SOC Analytics", "Automated Analysis", "Research Analytics", "Incident Management", "Ops Analytics", "Defense Analytics", 
    "Behavior Detection", "SIEM Analysis", "Data Aggregation", "Predictive Security", "Forensics", "Real-Time Anomaly", 
    "Data Lake", "Breach Detection", "SIEM Use Cases", "Detection Analytics", "Event Management", "Automated Response", 
    "Security Intelligence", "Behavior Analysis", "Analytics Platforms", "Automation and Analytics", "Data Collection", 
    "Threat Detection", "Threat Intelligence", "Log Analytics", "Data Enrichment", "Automation Tools", "Machine Learning", 
    "Threat Models", "Cybersecurity AI", "Predictive Intelligence", "AI Security", "Data Science", "Anomaly Detection", 
    "Data Analysis", "Security Insights", "Automated Monitoring", "Incident Detection", "Security Data", "Threat Analytics Tools", 
    "Data Management", "Threat Analysis", "ML Models", "SIEM Analytics", "Threat Modeling", "Analysis Tools", "Real-Time Analysis", 
    "Threat Detection", "Monitoring and Analytics", "Data Processing", "Threat Analytics", "Cyber Intelligence", "Cloud Analytics", 
    "Endpoint Analytics", "User Analytics", "Data Automation", "Data Aggregation", "SIEM Data", "Analytics Tools", "Behavioral Analysis", 
    "Data-Driven Detection", "ML Detection", "Data Analytics Tools", "Hunting Analytics", "Automated Analysis", 
    "Data Modeling", "AI Integration", "Real-Time Analytics", "ML Analytics", "Automated Detection", "Analytics Tools", 
    "Event Analysis", "Ops Data", "Network Analysis", "AI Detection", "Predictive Intelligence", "Analytics in SIEM", 
    "Analytics Platforms", "Analytics Tools", "Threat Analysis", "AI Analytics", "Incident Response", "Data Correlation", 
    "Data Science", "Event Analytics", "Cyber Defense", "Data Techniques", "Metrics Analysis", "Cloud Analytics"
]

def contains_keywords(text, keywords):
    """
    检查文本中是否包含任何简化和扩展关键词，并返回第一个匹配的完整关键词。
    :param text: 待检查的文本
    :param keywords: 网络安全相关的关键词集合
    :return: 匹配到的第一个完整关键词，如果没有匹配到则返回None.
    """
    # 对每个关键词进行遍历，查找第一个匹配项
    for keyword in keywords:
        # 使用单词边界\b来确保完整的单词匹配
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            return keyword  # 返回匹配到的第一个关键词
    return None  # 如果没有匹配到任何关键词，则返回None

work_dir = './gen_FT_Data/s1_Raw_Data/nCS'
path = '/fineweb_edu'  # 下载文件位置

# 初始化列表来存储所有的文本数据
texts_nCS = []

# 遍历目录中的所有文件
for i in range(600):
    file_path = os.path.join(work_dir+path, f"{i}.json")
    # 确保文件存在
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            # 加载JSON数据
            data = json.load(file)  
            # 遍历 rows 数组
            rows = data['rows']
            for row in rows:
                content = row['row']['text']
                match = contains_keywords(content, keywords)
                if match is not None:
                    print(match)
                else:
                    print("None")
                    #TODO:[数据标准化]去除换行符制表符等，使之成为一段
                    content = re.sub(r'\s+', ' ', content).strip()
                    texts_nCS.append({"text": content, "label": 0})

# 将数据保存到JSON文件
with open(os.path.join(work_dir, "nCS.json"), 'w', encoding='utf-8') as f:
    json.dump(texts_nCS, f, ensure_ascii=False, indent=4)

