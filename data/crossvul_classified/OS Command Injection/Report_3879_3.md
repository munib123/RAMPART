# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3879_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3879_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 150-197 of the vulnerable file.

                }

                break;

            case '5238f8e57e72e81d44119a8ffc3f98ea':
                $this->exec(escapeshellcmd('apt-get purge -y openitcockpit-module-' . base64_decode($msg->data->name)) . ';/bin/echo -e "\n\nDone - Please run openitcockpit-update\n"', [
                    'task' => '5238f8e57e72e81d44119a8ffc3f98ea',
                ]);
                break;

            case 'd41d8cd98f00b204e9800998ecf8427e':
                $this->exec(escapeshellcmd('apt-get install -y openitcockpit-module-' . base64_decode($msg->data->name)) . ';/bin/echo -e "\n\nDone - Please check your User Roles for possible new settings.\n"', [
                    'task' => 'd41d8cd98f00b204e9800998ecf8427e',
                ]);
                break;

            case 'keepAlive':
                $this->send('Pong', 'keepAlive', 'keepAlive');
                break;

            case 'apt_get_update':
                //$this->exec('apt-get update');
                break;

            case 'execute_nagios_command':
                $this->execNagiosPlugin($msg->data);
                break;

            case 'rescheduleHost':
                $this->Cake->Externalcommand->rescheduleHost(['uuid' => $msg->data[0], 'type' => $msg->data[1], 'satellite_id' => $msg->data[2]]);
                break;

            case 'rescheduleHostWithQuery':
                $this->Cake->Externalcommand->rescheduleHostWithQuery(['uuid' => $msg->data[0], 'type' => $msg->data[1]]);
                break;

            case 'rescheduleHostgroup':
                $this->Cake->Externalcommand->rescheduleHostgroup(['hostgroupUuid' => $msg->data[0], 'type' => $msg->data[1]]);
                break;

            case 'commitPassiveResult':
                $this->Cake->Externalcommand->passiveTransferHostCheckresult(['uuid' => $msg->data[0], 'comment' => $msg->data[1], 'state' => $msg->data[2], 'forceHardstate' => $msg->data[3], 'repetitions' => $msg->data[4]]);
                break;

            case 'commitPassiveServiceResult':
                $this->Cake->Externalcommand->passiveTransferServiceCheckresult(['hostUuid' => $msg->data[0], 'serviceUuid' => $msg->data[1], 'comment' => $msg->data[2], 'state' => $msg->data[3], 'forceHardstate' => $msg->data[4], 'repetitions' => $msg->data[5]]);
                break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,14 +165,6 @@
 
             case 'keepAlive':
                 $this->send('Pong', 'keepAlive', 'keepAlive');
-                break;
-
-            case 'apt_get_update':
-                //$this->exec('apt-get update');
-                break;
-
-            case 'execute_nagios_command':
-                $this->execNagiosPlugin($msg->data);
                 break;
 
             case 'rescheduleHost':
@@ -306,43 +298,6 @@
 
         $conn->close();
         $this->clients->detach($conn);
-    }
-
-    public function execNagiosPlugin($command) {
-
-        $folder = new Folder(Configure::read('nagios.basepath') . Configure::read('nagios.libexec'));
-        $plugins = $folder->find();
-        $plugins[] = 'ls';
-        $plugins[] = 'ls -la';
-
-        if (strpos($command, ';') || strpos($command, '&&') || strpos($command, '$') || strpos($command, '|') || strpos($command, '`')) {
-            $this->send("\e[0;34mWARNING: This command contain illegal characters, to run this command is only allowed from real CLI!\e[0m\n");
-
-            return false;
-        }
-
-        if (strpos($command, './') === 0) {
-            //Parse ./ away
-            $_command = explode('./', $command);
-            //remove spaces to get raw command name
-            $_command = explode(' ', $_command[1], 2);
-            if (!isset($_command[0]) || !in_array($_command[0], $plugins)) {
-                $this->send("\e[0;31mERROR: Forbidden command!\e[0m\n");
-
-                return false;
-            }
-        } else {
-            $_command = explode(' ', $command, 2);
-            if (!isset($_command[0]) || !in_array($_command[0], $plugins)) {
-                $this->send("\e[0;31mERROR: Forbidden command!\e[0m\n");
-
-                return false;
-            }
-        }
-
-        $this->exec(escapeshellcmd("su " . Configure::read('nagios.user') . " -c '" . $command . "'"), [
-            'cwd' => Configure::read('nagios.basepath') . Configure::read('nagios.libexec'),
-        ]);
     }
 
     public function exec($command, $options = []) {
```
