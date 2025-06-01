# CyberSentinel - Network Security Monitoring System

CyberSenti is an advanced security monitoring tool designed for Local Area Networks (LAN). It provides real-time detection and alerting for various network security threats including aggressive scans, DDoS attacks, brute force attempts, and other traditional attack vectors. The system is built using Wazuh and the ELK Stack (Elasticsearch, Logstash, Kibana), providing a comprehensive security monitoring solution for small businesses and startups. This repository contains the configuration files for setting up a Wazuh Manager with Elastic Stack integration. These configurations are essential for deploying a complete security monitoring solution. The installer helps download all the services and load the config files. While the Manager helps... well.. manage :v

## Key Features
- Real-time security threat detection
- Email alerts for critical security events
- Beautiful HTML-formatted email notifications
- Interactive Kibana dashboards for security monitoring
- Easy-to-use GUI for system management
- Automated installation process
- Support for multiple agent connections
- Local network monitoring capabilities

## System Architecture
The system consists of several key components:
1. **Wazuh Manager**: Core security monitoring component that collects and analyzes security events
2. **ELK Stack**:
   - Elasticsearch: Stores and indexes security logs
   - Logstash: Processes and formats logs, manages email alerts
   - Kibana: Provides visualization and dashboard interface
3. **Filebeat**: Forwards logs from Wazuh to Elasticsearch
4. **GUI Interface**: Local management interface for system monitoring

## Prerequisites
- Raspberry Pi 5
- Kali Linux
- Network access to target machines
- Administrative privileges for installation

## Installation
The system comes with an automated GUI installer that handles:
- Version-controlled installation of all components
- Configuration file setup
- Service initialization
- Certificate generation and management

## Directory Structure

```
.
├── etc/
│   ├── elasticsearch/    # Elasticsearch configuration files
│   ├── logstash/        # Logstash configuration files
│   ├── postfix/         # Postfix mail server configuration
│   ├── filebeat/        # Filebeat configuration for log shipping
│   └── packetbeat/      # Packetbeat configuration for network monitoring
└── var/
    └── ossec/           # Wazuh manager configuration files
```

## Config Files

### 1. Wazuh Manager (var/ossec/)
- Contains the core Wazuh manager configuration files
- Includes rules, decoders, and other security monitoring configurations

### 2. Elastic Stack Integration
- **Elasticsearch**: Configuration for the search and analytics engine
- **Logstash**: Configuration for log processing and forwarding
- **Filebeat**: Configuration for shipping logs to Elasticsearch
- **Packetbeat**: Configuration for network monitoring and packet analysis

### 3. Postfix Configuration
- Mail server configuration for alert notifications

To install:
1. Clone this repository
2. Run the CyberSenti_Installer.py script
3. Follow the on-screen instructions

## Usage
1. **Initial Setup**:
   - Install the system using the provided GUI installer
   - Configure email alerts through the management interface
   - Add agents to the monitoring system

2. **Monitoring**:
   - Access the Kibana dashboard for real-time monitoring
   - Receive email alerts for critical security events
   - Use the local GUI for system management

3. **Agent Management**:
   - Add new agents through the management interface
   - Monitor agent status and logs
   - Configure agent-specific settings

## Security Considerations
- The system is designed for local network deployment
- Supports detection of traditional attack vectors
- These configuration files may contain sensitive information
- Ensure proper access controls are in place

## Limitations
- Currently optimized for local network deployment
- Detection capabilities limited to OS-level logs
- Some advanced attacks may require additional logging systems
- Best suited for modern systems with proper logging capabilities

## Future Enhancements
- Integration with honeypot systems
- AI-powered threat detection
- Enhanced web attack detection
- Support for cloud deployment
- Additional attack vector detection

## Contributing

Feel free to submit issues and enhancement requests.
