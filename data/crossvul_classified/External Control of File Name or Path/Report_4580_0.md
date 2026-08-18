# CrossVul Fix Pair: External Control of File Name or Path in php
**Pair ID:** 4580_0
**Vulnerability Class:** External Control of File Name or Path
**CWE:** CWE-73
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4580_0`)

## Vulnerability Information & PoC

## Description
External Control of File Name or Path - This could allow an attacker to access or modify system files or other files that are critical to the application.

## Vulnerable Code
```php
Lines 316-356 of the vulnerable file.

            throw new ApplicationException(Lang::get('cms::lang.asset.select_destination_dir'));
        }

        $destinationFullPath = $this->getFullPath($destinationDir);
        if (!file_exists($destinationFullPath) || !is_dir($destinationFullPath)) {
            throw new ApplicationException(Lang::get('cms::lang.asset.destination_not_found'));
        }

        $list = @json_decode(@base64_decode($selectedList));
        if ($list === false) {
            throw new ApplicationException(Lang::get('cms::lang.asset.selected_files_not_found'));
        }

        foreach ($list as $path) {
            if (!$this->validatePath($path)) {
                throw new ApplicationException(Lang::get('cms::lang.asset.invalid_path'));
            }

            $basename = basename($path);
            $originalFullPath = $this->getFullPath($path);
            $newFullPath = rtrim($destinationFullPath, '/').'/'.$basename;
            $safeDir = $this->getAssetsPath();

            if ($originalFullPath == $newFullPath) {
                continue;
            }

            if (is_file($originalFullPath)) {
                if (!@File::move($originalFullPath, $newFullPath)) {
                    throw new ApplicationException(Lang::get(
                        'cms::lang.asset.error_moving_file',
                        ['file' => $basename]
                    ));
                }
            }
            elseif (is_dir($originalFullPath)) {
                if (!@File::copyDirectory($originalFullPath, $newFullPath)) {
                    throw new ApplicationException(Lang::get(
                        'cms::lang.asset.error_moving_directory',
                        ['dir' => $basename]
                    ));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -333,11 +333,18 @@
 
             $basename = basename($path);
             $originalFullPath = $this->getFullPath($path);
-            $newFullPath = rtrim($destinationFullPath, '/').'/'.$basename;
+            $newFullPath = realpath(rtrim($destinationFullPath, '/')) . '/' . $basename;
             $safeDir = $this->getAssetsPath();
 
             if ($originalFullPath == $newFullPath) {
                 continue;
+            }
+
+            if (!starts_with($newFullPath, $safeDir)) {
+                throw new ApplicationException(Lang::get(
+                    'cms::lang.asset.error_moving_file',
+                    ['file' => $basename]
+                ));
             }
 
             if (is_file($originalFullPath)) {
```
