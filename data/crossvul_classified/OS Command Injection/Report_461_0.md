# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 461_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `461_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 5062-5102 of the vulnerable file.

        return $this->save($event);
    }

    public function upload_stix($user, $filename, $stix_version, $original_file)
    {
        App::uses('Folder', 'Utility');
        App::uses('File', 'Utility');
        if ($stix_version == '2') {
            $scriptFile = APP . 'files/scripts/stix2/stix2misp.py';
            $tempFilePath = APP . 'files/scripts/tmp/' . $filename;
            $shell_command = $this->getPythonVersion() . ' ' . $scriptFile . ' ' . $tempFilePath;
            $output_path = $tempFilePath . '.stix2';
        } elseif ($stix_version == '1' || $stix_version == '1.1' || $stix_version == '1.2') {
            $scriptFile = APP . 'files/scripts/stix2misp.py';
            $tempFilePath = APP . 'files/scripts/tmp/' . $filename;
            $shell_command = $this->getPythonVersion() . ' ' . $scriptFile . ' ' . $filename;
            $output_path = $tempFilePath . '.json';
        } else {
            throw new MethodNotAllowedException('Invalid STIX version');
        }
        $shell_command .=  ' ' . $original_file . ' ' . escapeshellarg(Configure::read('MISP.default_event_distribution')) . ' ' . escapeshellarg(Configure::read('MISP.default_attribute_distribution')) . ' 2>' . APP . 'tmp/logs/exec-errors.log';
        $result = shell_exec($shell_command);
        unlink($tempFilePath);
        if (trim($result) == '1') {
            $data = file_get_contents($output_path);
            $data = json_decode($data, true);
            unlink($output_path);
            $created_id = false;
            $validationIssues = false;
            $result = $this->_add($data, true, $user, '', null, false, null, $created_id, $validationIssues);
            if ($result) {
                return $created_id;
            }
            return $validationIssues;
        } else {
            if (trim($result) == '2') {
                $response = __('Issues while loading the stix file. ');
            } elseif (trim($result) == '3') {
                $response = __('Issues with the maec library. ');
            } else {
                $response = __('Issues executing the ingestion script or invalid input. ');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5079,7 +5079,7 @@
         } else {
             throw new MethodNotAllowedException('Invalid STIX version');
         }
-        $shell_command .=  ' ' . $original_file . ' ' . escapeshellarg(Configure::read('MISP.default_event_distribution')) . ' ' . escapeshellarg(Configure::read('MISP.default_attribute_distribution')) . ' 2>' . APP . 'tmp/logs/exec-errors.log';
+        $shell_command .=  ' ' . escapeshellarg(Configure::read('MISP.default_event_distribution')) . ' ' . escapeshellarg(Configure::read('MISP.default_attribute_distribution')) . ' 2>' . APP . 'tmp/logs/exec-errors.log';
         $result = shell_exec($shell_command);
         unlink($tempFilePath);
         if (trim($result) == '1') {
@@ -5090,6 +5090,7 @@
             $validationIssues = false;
             $result = $this->_add($data, true, $user, '', null, false, null, $created_id, $validationIssues);
             if ($result) {
+                $this->add_original_file($tempFilePath, $original_filename, $created_id, 'STIX 1.1');
                 return $created_id;
             }
             return $validationIssues;
@@ -5643,4 +5644,55 @@
         }
         return $eventIdList;
     }
+
+    public function add_original_file($file_path, $original_filename, $event_id, $format)
+    {
+        if (!Configure::check('MISP.default_attribute_distribution') || Configure::read('MISP.default_attribute_distribution') === 'event') {
+            $distribution = 5;
+        } else {
+            $distribution = Configure::read('MISP.default_attribute_distribution');
+        }
+        $this->MispObject->create();
+        $object = array(
+            'name' => 'original-imported-file',
+            'meta-category' => 'file',
+            'description' => 'Object describing the original file used to import data in MISP.',
+            'template_uuid' => '4cd560e9-2cfe-40a1-9964-7b2e797ecac5',
+            'template_version' => '2',
+            'event_id' => $event_id,
+            'distribution' => $distribution
+        );
+        $this->MispObject->save($object);
+        $object_id = $this->MispObject->id;
+        $file = file_get_contents($file_path);
+        $attributes = array(
+            array(
+                'type' => 'attachment',
+                'category' => 'External analysis',
+                'to_ids' => false,
+                'event_id' => $event_id,
+                'distribution' => $distribution,
+                'object_relation' => 'imported-sample',
+                'value' => $original_filename,
+                'data' => base64_encode($file),
+                'object_id' => $object_id,
+            ),
+            array(
+                'type' => 'text',
+                'category' => 'Other',
+                'to_ids' => false,
+                'uuid' => '5c08f00d-2174-4ab7-ad0d-1b1a011fb688',
+                'event_id' => $event_id,
+                'distribution' => $distribution,
+                'object_id' => $object_id,
+                'object_relation' => 'format',
+                'value' => 'STIX 1.1'
+            )
+        );
+        foreach ($attributes as $attribute) {
+            $this->Attribute->create();
+            $this->Attribute->save($attribute);
+        }
+        return true;
+    }
 }
```
