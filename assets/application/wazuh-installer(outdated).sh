#!/bin/bash
# Wazuh-ELK Automated Installer with Config Deployment (Correct Order)

# Ensure script is run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Configuration variables
REPO_URL="https://github.com/Abdullah-Mehtab/Cyber-Sentinal"
TMP_DIR="/tmp/cyber-sentinal-config"
CONFIG_DIR="$TMP_DIR/etc"

# Step 1: System Preparation
echo "Updating system and installing dependencies..."
apt update && apt upgrade -y
apt install -y curl apt-transport-https wget gnupg git

# Step 2: Install Wazuh Manager
echo "Installing Wazuh Manager..."
curl -O https://packages.wazuh.com/key/GPG-KEY-WAZUH
gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import GPG-KEY-WAZUH
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
apt install -y wazuh-manager

# Step 3: Install Elastic Stack
echo "Installing Elastic Stack..."
apt install -y openjdk-11-jdk
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list

apt update
apt install -y elasticsearch=7.17.13 kibana=7.17.13 logstash=7.17.13 filebeat=7.17.13

# Step 4: Stop services before config deployment
echo "Stopping services for configuration..."
systemctl stop wazuh-manager elasticsearch kibana logstash filebeat

# Step 5: Clone and deploy configurations
echo "Deploying custom configurations..."
rm -rf $TMP_DIR
git clone $REPO_URL $TMP_DIR

echo "Copying configuration files..."
cp -r $TMP_DIR/etc/elasticsearch/* /etc/elasticsearch/
cp -r $TMP_DIR/etc/logstash/* /etc/logstash/
cp -r $TMP_DIR/etc/postfix/* /etc/postfix/
cp -r $TMP_DIR/etc/filebeat/* /etc/filebeat/
cp -r $TMP_DIR/etc/packetbeat/* /etc/packetbeat/
cp -r $TMP_DIR/var/ossec/* /var/ossec/

# Step 6: Set permissions and ownership
echo "Setting proper permissions..."
chown -R elasticsearch:elasticsearch /etc/elasticsearch
chown -R logstash:logstash /etc/logstash
chown -R root:root /etc/postfix /etc/filebeat /etc/packetbeat
chown -R ossec:ossec /var/ossec
find /var/ossec -type d -exec chmod 750 {} \;
find /var/ossec -type f -exec chmod 640 {} \;

# Step 7: Configure Elasticsearch JVM
sed -i 's/-Xms4g/-Xms1g/' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx4g/-Xmx1g/' /etc/elasticsearch/jvm.options

# Step 8: Enable and start services
echo "Starting services with new configurations..."
systemctl daemon-reload
systemctl enable --now wazuh-manager elasticsearch kibana logstash filebeat

# Step 9: Certificate Generation
echo "Generating certificates..."
cd $TMP_DIR
chmod +x wazuh-certs-tool.sh
./wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

# Step 10: Install Kibana plugin
echo "Installing Kibana plugin..."
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.5.4_7.17.13-1.zip

# Step 11: Email Configuration
echo "Configuring email alerts..."
apt install -y postfix mailutils

read -p "Enter your Gmail address: " GMAIL_USER
read -sp "Enter your Gmail app password: " GMAIL_PASS
echo "[smtp.gmail.com]:587 $GMAIL_USER:$GMAIL_PASS" | tee /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db

# Update Wazuh email config
sed -i "s/<email_to>.*<\/email_to>/<email_to>$GMAIL_USER<\/email_to>/" /var/ossec/etc/ossec.conf
sed -i "s/<email_from>.*<\/email_from>/<email_from>$GMAIL_USER<\/email_from>/" /var/ossec/etc/ossec.conf

# Final cleanup
rm -rf $TMP_DIR

echo "Installation complete!"
echo "Access Kibana at: http://$(hostname -I | awk '{print $1}'):5601"
echo "Wazuh dashboard credentials: elastic/elastic (change after first login)"