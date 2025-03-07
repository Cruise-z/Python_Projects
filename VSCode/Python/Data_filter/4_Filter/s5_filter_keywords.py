import os
import configparser
#TODO:本地设置当前目录
os.chdir("./4_Filter")
#TODO:服务器上设置当前目录
# os.chdir("./")

# 创建配置解析器
config = configparser.ConfigParser()
# 读取 .ini 文件
config.read('config.ini')
jump_host = config['default']['jump_host']
jump_user = config['default']['jump_user']
target_host = config['default']['target_host']
target_user = config['default']['target_user']
target_passwd = config['default']['target_passwd']
remote_load_path = config['default']['remote_load_path']
remote_cache_path = config['default']['remote_cache_path']
local_path = config['default']['local_path']

os.environ['http_proxy'] = config['proxy']['http_proxy']
os.environ['https_proxy'] = config['proxy']['https_proxy']
#!:服务器配置环境变量
os.environ['HF_ENDPOINT'] = config['proxy']['hf_mirror']
#TODO:设置全局缓存目录，包括模型、数据集及其他相关缓存文件。
# os.environ['HF_HOME'] = remote_cache_path
#TODO:指定Hugging_Face数据集的缓存目录，也就是下载的数据集文件存放的位置。
# os.environ['HF_DATASETS_CACHE'] = remote_load_path

import paramiko
import subprocess
import json
import re
from sshtunnel import SSHTunnelForwarder
from datasets import load_dataset
from tqdm import tqdm  # 导入 tqdm 库


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

# 定义关键词过滤函数
def keyword_filter(example, field:str):
    # print(type(example), example)  # 打印类型和内容
    text = example[field]  # 要筛选的字段是 "text"
    # 遍历关键词列表
    for keyword in keywords:
        # 使用正则匹配关键词（确保是完整单词，忽略大小写）
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            return True  # 找到匹配关键词时返回 True 保留该条记录
    return False  # 没有匹配到关键词则返回 False，过滤掉该记录

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

def get_curl_command(offset, length):
    return [
        "curl",
        "-X", "GET",
        f"https://datasets-server.huggingface.co/rows?dataset=HuggingFaceFW%2Ffineweb-edu&config=default&split=train&offset={offset}&length={length}"
    ]

def remote(jump_host:str, jump_user:str, 
           target_host:str, target_user:str, target_password:str, 
           remote_path:str):
    # 设置SSH客户端使用系统的SSH Agent
    ssh_agent = paramiko.Agent()
    
    # 建立到跳板机的SSH隧道
    with SSHTunnelForwarder(
        (jump_host, 22),
        ssh_username=jump_user,
        ssh_pkey=ssh_agent.get_keys()[0],  # 使用SSH Agent提供的私钥
        remote_bind_address=(target_host, 22)
    ) as tunnel:
        # 设置隧道本地端口
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 连接到内网服务器
        client.connect('127.0.0.1', port=tunnel.local_bind_port, username=target_user, password=target_password)

        # 使用SFTP下载文件
        sftp = client.open_sftp()
        
        # 初始化参数
        batch_size = 1000
        filtered_data = []
        total_written = 0
        
        # 3. 打开远程文件用于追加写入
        with sftp.file(os.path.join(remote_path, f"{spilt_name}.jsonl"), 'a') as remote_file:
            for example in tqdm_ds:
                if keyword_filter(example, "text"):
                    # 取出筛选后的数据，并新增 "label" 字段
                    filtered_item = {"text": example["text"], "label": 0}
                    
                    # 将符合条件的数据加入到 `filtered_data` 列表
                    filtered_data.append(filtered_item)
                    
                    # 当 filtered_data 达到 batch_size 时，批量写入远程文件并清空
                    if len(filtered_data) >= batch_size:
                        # 将数据转换为 JSON 行，并逐行写入远程文件
                        for item in filtered_data:
                            json_data = json.dumps(item, ensure_ascii=False)
                            remote_file.write(json_data.encode('utf-8') + b'\n')
                        
                        # 清空 filtered_data 并更新统计
                        filtered_data = []
                        total_written += batch_size
                        print(f"Written {total_written} entries to {remote_path}/{spilt_name}.jsonl")

            # 处理最后一批不足 batch_size 的数据
            if filtered_data:
                for item in filtered_data:
                    json_data = json.dumps(item, ensure_ascii=False)
                    remote_file.write(json_data.encode('utf-8') + b'\n')
                total_written += len(filtered_data)
                print(f"Written the final {len(filtered_data)} entries to {remote_path}/{spilt_name}.jsonl")

        print(f"Data written to {remote_path}/{spilt_name}.jsonl successfully! Total entries: {total_written}")
        sftp.close()
        client.close()

def write_to_temp_file(temp_file: str, filtered_data: list):
    """将筛选后的数据写入临时文件"""
    with open(temp_file, 'w', encoding='utf-8') as file:
        for item in filtered_data:
            json_data = json.dumps(item, ensure_ascii=False)
            file.write(json_data + '\n')

def append_temp_to_target(temp_file: str, target_file: str):
    """将临时文件的内容追加到目标文件"""
    with open(temp_file, 'r', encoding='utf-8') as temp_file_read:
        with open(target_file, 'a', encoding='utf-8') as target:
            target.write(temp_file_read.read())

def local(tqdm_ds:tqdm, local_path:str, spilt_name:str, log_file_name:str, batch_size:int):
    # 初始化参数
    batch_size = batch_size
    filtered_data = []
    total_written = 0
    
    os.makedirs(local_path, exist_ok=True)
    log_file = os.path.join(local_path, log_file_name)
    temp_file = os.path.join(local_path, f"{spilt_name}_kw.jsonl.tmp")
    target_file = os.path.join(local_path, f"{spilt_name}_kw.jsonl")
    
    # 读取上次中断的位置
    start_index = 0
    if os.path.exists(log_file):
        with open(log_file, 'r') as log:
            start_index = int(log.read().strip())

    # 打开文件用于追加写入
    for idx, example in enumerate(tqdm_ds):
        if idx < start_index:
            continue  # 跳过已处理的索引
        
        if keyword_filter(example, "text"):
            # 取出筛选后的数据，并新增 "label" 字段
            filtered_item = {"text": example["text"], "label": 0}
                    
            # 将符合条件的数据加入到 `filtered_data` 列表
            filtered_data.append(filtered_item)
                    
            # 当 filtered_data 达到 batch_size 时，批量写入文件并清空
            if len(filtered_data) >= batch_size:
                # 将数据转换为 JSON 行，并逐行写入临时文件
                write_to_temp_file(temp_file, filtered_data)
                        
                # 清空 filtered_data 并更新统计
                filtered_data = []
                total_written += batch_size
                print(f"Written {total_written} entries to {local_path}/{spilt_name}_kw.jsonl")
                
                #TODO:写入目标文件并更新日志
                # 将临时文件的内容追加到目标文件
                append_temp_to_target(temp_file, target_file)
                # 更新日志文件
                with open(log_file, 'w') as log:
                    log.write(str(idx + 1))

    # 处理最后一批不足 batch_size 的数据
    if filtered_data:
        # 将数据转换为 JSON 行，并逐行写入临时文件
        write_to_temp_file(temp_file, filtered_data)
                
        total_written += len(filtered_data)
        print(f"Written the final {len(filtered_data)} entries to {local_path}/{spilt_name}_kw.jsonl")
        
    # 将临时文件的内容追加到目标文件
    append_temp_to_target(temp_file, target_file)
    # 更新日志文件
    with open(log_file, 'w') as log:
        log.write(str(len(tqdm_ds)))  # 记录总数

    print(f"Data written to {local_path}/{spilt_name}_kw.jsonl successfully! Total entries: {total_written}")


# 分块下载数据
# 定义 curl 命令的 URL
offset = 0  # 替换为你想要的初始偏移量
length = 100  # 替换为你想要的偏移步长

# 1. 加载数据集（直接加载, 通过tqdm显示总进度）
spilt_name = "CC-MAIN-2013-20"
ds = load_dataset(path="HuggingFaceFW/fineweb-edu",
                  name=spilt_name, 
                  split="train")
# ds = load_dataset("AlaaElhilo/Wikipedia_ComputerScience", split="train")

# 2. 包装数据集的迭代器，添加 tqdm 进度条
total_count = len(ds)  # 适用于非流式加载
print(f"总条数: {total_count}")
tqdm_ds = tqdm(ds, total=total_count, desc="Processing")
# tqdm_ds = tqdm(ds, desc="Processing")

local(tqdm_ds, local_path, spilt_name, log_file_name='log_kw.txt', batch_size=1000)