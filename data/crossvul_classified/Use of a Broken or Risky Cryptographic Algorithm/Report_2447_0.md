# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in shell
**Pair ID:** 2447_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2447_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```bash
Lines 1-22 of the vulnerable file.

#!/bin/bash
ln -s /etc/openitcockpit/nagios.cfg /opt/openitc/nagios/etc/nagios.cfg
sudo -g www-data /usr/share/openitcockpit/app/Console/cake schema update -y --connection default --file schema_itcockpit.php -s 26
#sudo -g www-data /usr/share/openitcockpit/app/Console/cake schema update --plugin NagiosModule --file ndo.php --connection default
oitc AclExtras.AclExtras aco_sync
oitc compress
oitc nagios_export --all

CODENAME=$(lsb_release -sc)
if [ $CODENAME = "jessie" ] || [ $CODENAME = "xenial" ] || [ $CODENAME = "bionic" ] || [ $CODENAME = "stretch" ]; then
    systemctl restart nagios
    systemctl restart sudo_server
fi

if [ $CODENAME = "trusty" ]; then
    service nagios restart
fi

sudo -g www-data /usr/share/openitcockpit/app/Console/cake setup

oitc docu_generator
oitc roles
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,16 @@
 #!/bin/bash
+
+INIFILE=/etc/openitcockpit/mysql.cnf
+
 ln -s /etc/openitcockpit/nagios.cfg /opt/openitc/nagios/etc/nagios.cfg
 sudo -g www-data /usr/share/openitcockpit/app/Console/cake schema update -y --connection default --file schema_itcockpit.php -s 26
 #sudo -g www-data /usr/share/openitcockpit/app/Console/cake schema update --plugin NagiosModule --file ndo.php --connection default
+
+echo "---------------------------------------------------------------"
+echo "Create new WebSocket Key"
+WEBSOCKET_KEY=$(php -r "echo bin2hex(openssl_random_pseudo_bytes(80, \$cstrong));")
+mysql "--defaults-extra-file=${INIFILE}" -e "UPDATE systemsettings SET \`systemsettings\`.\`value\`='${WEBSOCKET_KEY}' WHERE \`key\`='SUDO_SERVER.API_KEY';"
+
 oitc AclExtras.AclExtras aco_sync
 oitc compress
 oitc nagios_export --all
@@ -10,6 +19,7 @@
 if [ $CODENAME = "jessie" ] || [ $CODENAME = "xenial" ] || [ $CODENAME = "bionic" ] || [ $CODENAME = "stretch" ]; then
     systemctl restart nagios
     systemctl restart sudo_server
+    systemctl restart push_notification
 fi
 
 if [ $CODENAME = "trusty" ]; then
```
