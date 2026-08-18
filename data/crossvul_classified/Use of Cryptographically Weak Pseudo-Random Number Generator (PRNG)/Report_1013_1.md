# CrossVul Fix Pair: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in shell
**Pair ID:** 1013_1
**Vulnerability Class:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-338
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1013_1`)

## Vulnerability Information & PoC

## Description
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.

## Vulnerable Code
```bash
Lines 53-93 of the vulnerable file.

genpasswd() 
{
	length=$1
	digits=({1..9})
	lower=({a..z})
	upper=({A..Z})
	CharArray=(${digits[*]} ${lower[*]} ${upper[*]})
	ArrayLength=${#CharArray[*]}
	password=""
	for i in `seq 1 $length`
	do
	        index=$(($RANDOM%$ArrayLength))
	        char=${CharArray[$index]}
	        password=${password}${char}
	done
	echo $password
}

MYSQL_ROOT_PASSWORD=`echo "$(genpasswd 20)" | sed s/./*/5`
ASTPPUSER_MYSQL_PASSWORD=`echo "$(genpasswd 20)" | sed s/./*/5`
#Fetch OS Distribution
get_linux_distribution ()
{ 
        V1=`cat /etc/*release | head -n1 | tail -n1 | cut -c 14- | cut -c1-18`
        V2=`cat /etc/*release | head -n7 | tail -n1 | cut -c 14- | cut -c1-14`
        if [[ $V1 = "Debian GNU/Linux 9" ]]; then
                DIST="DEBIAN"
        else if [[ $V2 = "CentOS Linux 7" ]]; then
                DIST="CENTOS"
        else
                DIST="OTHER"
                echo -e 'Ooops!!! Quick Installation does not support your distribution \nPlease use manual steps or contact ASTPP Sales Team \nat sales@astpp.com.'
                exit 1
        fi
        fi
}

#Install Prerequisties
install_prerequisties ()
{
        if [ $DIST = "CENTOS" ]; then
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,6 +70,8 @@
 
 MYSQL_ROOT_PASSWORD=`echo "$(genpasswd 20)" | sed s/./*/5`
 ASTPPUSER_MYSQL_PASSWORD=`echo "$(genpasswd 20)" | sed s/./*/5`
+PR_KEY=`echo "$(genpasswd 32)"`
+EN_KEY=`echo "$(genpasswd 12)"`
 #Fetch OS Distribution
 get_linux_distribution ()
 { 
@@ -332,6 +334,8 @@
         sed -i "s#DB_PASSWD=\"<PASSSWORD>\"#DB_PASSWD = \"${ASTPPUSER_MYSQL_PASSWORD}\"#g" ${ASTPPDIR}astpp.lua
         sed -i "s#base_url=http://localhost:8089/#base_url=https://${ASTPP_HOST_DOMAIN_NAME}/#g" ${ASTPPDIR}/astpp-config.conf
         sed -i "s#PASSWORD = <PASSWORD>#PASSWORD = ${ASTPPUSER_MYSQL_PASSWORD}#g" /etc/odbc.ini
+        sed -i "s#<PR_KEY>#${PR_KEY}#g" ${ASTPPDIR}astpp-config.conf
+        sed -i "s#<EN_KEY>#${EN_KEY}#g" ${ASTPPDIR}astpp-config.conf
         systemctl restart nginx
 }
 
```
