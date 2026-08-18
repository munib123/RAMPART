# CrossVul Fix Pair: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') in php
**Pair ID:** 4579_0
**Vulnerability Class:** Remote File Inclusion
**CWE:** CWE-98
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4579_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') - In certain versions and configurations of PHP, this can allow an attacker to specify a URL to a remote location from which the product will obtain the code to execute.

## Vulnerable Code
```php
Lines 268-307 of the vulnerable file.

    /**
     * Returns the file name.
     * @return string
     */
    public function getFileName()
    {
        return $this->fileName;
    }

    /**
     * Returns the absolute file path.
     * @param string $fileName Specifies the file name to return the path to.
     * @return string
     */
    public function getFilePath($fileName = null)
    {
        if ($fileName === null) {
            $fileName = $this->fileName;
        }

        return $this->theme->getPath().'/'.$this->dirName.'/'.$fileName;
    }

    /**
     * Returns a list of editable asset extensions.
     * The list can be overridden with the cms.editableAssetTypes configuration option.
     * @return array
     */
    public static function getEditableExtensions()
    {
        $defaultTypes =  ['css', 'js', 'less', 'sass', 'scss'];

        $configTypes = Config::get('cms.editableAssetTypes');
        if (!$configTypes) {
            return $defaultTypes;
        }

        return $configTypes;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -285,7 +285,14 @@
             $fileName = $this->fileName;
         }
 
-        return $this->theme->getPath().'/'.$this->dirName.'/'.$fileName;
+        // Limit paths to those under the assets directory
+        $directory = $this->theme->getPath() . '/' . $this->dirName . '/';
+        $path = realpath($directory . $fileName);
+        if (!starts_with($path, $directory)) {
+            return false;
+        }
+
+        return $path;
     }
 
     /**
```
