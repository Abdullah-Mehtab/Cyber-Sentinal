# CyberSentinel - Advanced Network Security Monitoring System

CyberSentinel is a comprehensive security monitoring tool designed for Local Area Networks (LAN) that can detect and alert on various traditional attack vectors in real-time. Built specifically for small businesses, startups, homes, and educational institutions, it provides enterprise-grade security monitoring capabilities without the complexity of enterprise solutions.

## 🎯 Project Overview

Our project addresses the critical need for accessible cybersecurity monitoring in environments where traditional enterprise solutions are either too expensive or too complex. CyberSentinel detects a wide range of real-world attacks including:

- **Aggressive network scans** and reconnaissance activities
- **DDoS attacks** and network flooding
- **Brute force attacks** on services and applications
- **SQL injection attempts** and web-based attacks
- **Shellshock vulnerabilities** and command injection
- **Meterpreter attacks** and advanced persistent threats
- **System-level intrusions** and unauthorized access attempts

## 🏗️ Technical Architecture

### Core Components

1. **Wazuh Manager** - The heart of the system
   - Collects and analyzes security events from agents
   - Generates alerts based on predefined rules
   - Manages agent connections and configurations
   - Stores alerts in `alerts.json` for further processing

2. **ELK Stack Integration**
   - **Elasticsearch**: Stores and indexes all security logs and alerts
   - **Logstash**: Processes, filters, and formats logs; handles HTML email notifications
   - **Kibana**: Provides beautiful visual dashboards for security monitoring
   - **Filebeat/Packetbeat**: Forwards Wazuh alerts to Elasticsearch

3. **Suricata** - Network-based attack detection
   - Detects network-level attacks that Wazuh might miss
   - Generates its own logs and alerts
   - Forwards network alerts to Wazuh for centralized processing
   - Installed on each agent for comprehensive coverage

4. **Honeypot Integration** (In Development)
   - Traps attackers and records their activities
   - Captures exact IP addresses, attack commands, and timestamps
   - Currently integrated only in the manager

### Data Flow

```
Agents → Wazuh Manager → alerts.json → Filebeat → Elasticsearch
   ↓
Suricata → Network Alerts → Wazuh Manager
   ↓
Logstash → HTML Email Alerts + Kibana Dashboards
```

## 🚀 Key Features

- **Real-time Threat Detection**: Immediate detection of security incidents
- **Beautiful HTML Email Alerts**: Professional, formatted notifications for critical events
- **Interactive Kibana Dashboards**: Comprehensive visualization of security data
- **Automated Installation Wizard**: Streamlined setup process with version control
- **Local GUI Management**: Easy-to-use interface for system administration
- **Multi-Agent Support**: Monitor multiple machines simultaneously
- **Network + Host-based Detection**: Comprehensive coverage with Suricata integration

## 🛠️ Installation & Setup

### Prerequisites
- **Hardware**: Raspberry Pi 5 (recommended)
- **OS**: Kali Linux (clean installation)
- **Network**: Access to target machines for agent deployment
- **Permissions**: Administrative privileges for installation

### Automated Installation

Visit our web installer: **[https://abdullah-mehtab.github.io/Cyber-Sentinal/](https://abdullah-mehtab.github.io/Cyber-Sentinal/)**

The installer wizard handles:
- Version-controlled installation of all components
- Automatic configuration file deployment
- Service initialization and management
- Certificate generation and security setup
- Integration testing and validation

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/your-username/CyberSentinel.git

# Run the installer
python3 CyberSenti_Installer.py

# Follow the on-screen instructions
```

## 📁 Configuration Files

This repository contains all necessary configuration files for a complete CyberSentinel deployment:

```
.
├── etc/
│   ├── elasticsearch/    # Elasticsearch configuration
│   │   ├── elasticsearch.yml
│   │   └── certs/
│   ├── logstash/        # Logstash processing and email alerts
│   │   └── conf.d/
│   │       └── wazuh.conf
│   ├── filebeat/        # Log forwarding configuration
│   │   ├── filebeat.yml
│   │   └── wazuh-template.json
│   ├── packetbeat/      # Network monitoring configuration
│   │   └── packetbeat.yml
│   ├── suricata/        # Network attack detection
│   │   ├── suricata.yml
│   │   └── rules/
│   │       └── custom.rules
│   └── postfix/         # Legacy email configuration (deprecated)
└── var/
    └── ossec/           # Wazuh manager core configuration
        ├── etc/
        │   ├── ossec.conf
        │   └── rules/
        │       └── local_rules.xml
```

## 🔧 Usage Guide

### 1. Initial Setup
1. Install the system using the web installer or GUI installer
2. Configure email alert settings through the management interface
3. Add monitoring agents to your network
4. Verify all services are running properly

### 2. Daily Monitoring
- **Email Alerts**: Receive immediate notifications for critical security events
- **Kibana Dashboard**: Access real-time security visualizations
- **Local GUI**: Manage system settings and monitor agent status
- **Log Analysis**: Review detailed logs for incident investigation

### 3. Agent Management
- Add new machines as monitoring agents
- Monitor agent connection status and health
- Configure agent-specific security rules
- Update agent configurations remotely

## 🔍 Detection Capabilities

### What We Detect
- ✅ **OS-level attacks** (Wazuh primary detection)
- ✅ **Network-based attacks** (Suricata integration)
- ✅ **Web application attacks** (with proper logging)
- ✅ **System intrusions** and unauthorized access
- ✅ **Service exploitation attempts**
- ✅ **Reconnaissance activities**

### Limitations & Considerations
- **Legacy Systems**: Older machines (like Metasploitable-3) may have limited detection due to outdated logging
- **Web Attacks**: Some web-based attacks require proper application logging to be detected
- **Agent Requirements**: Suricata needs to be installed on each agent for network-based detection
- **Local Network Focus**: Currently optimized for LAN deployment (WAN deployment would require additional security considerations)

## 🎯 Target Audience

CyberSentinel is designed for:
- **Small Businesses**: Affordable enterprise-grade security monitoring
- **Startups**: Easy-to-deploy security solution for growing companies
- **Educational Institutions**: Comprehensive security for campus networks
- **Home Networks**: Advanced protection for tech-savvy households
- **Security Teams**: Centralized monitoring and alerting system

## 🔮 Future Enhancements

### In Development
- **Honeypot Integration**: Advanced attacker trapping and analysis
- **AI-Powered Detection**: Machine learning for threat pattern recognition
- **Cloud Deployment**: Support for cloud-based monitoring
- **Enhanced Web Attack Detection**: Improved detection for modern web applications

### Planned Features
- **Mobile App**: Remote monitoring and alert management
- **Advanced Analytics**: Predictive threat analysis
- **Integration APIs**: Third-party security tool integration
- **Automated Response**: Automated threat mitigation capabilities

## 🛡️ Security Considerations

- **Local Deployment**: Designed for secure local network environments
- **Access Controls**: Proper authentication and authorization required
- **Sensitive Data**: Configuration files may contain security-sensitive information
- **Network Isolation**: Recommended for isolated network segments
- **Regular Updates**: Keep all components updated for latest security patches

## 📞 Support & Documentation

- **Installation Guide**: Follow the web installer for step-by-step setup
- **Configuration Manual**: Detailed configuration options in the `etc/` directories
- **Troubleshooting**: Check service logs and agent status through the GUI
- **Community**: Submit issues and feature requests through GitHub

## 🤝 Contributing

We welcome contributions! Please feel free to:
- Submit bug reports and feature requests
- Contribute code improvements
- Share configuration optimizations
- Help improve documentation

---

**CyberSentinel** - Making enterprise-grade security monitoring accessible to everyone.

*Built with ❤️ for the cybersecurity community*
