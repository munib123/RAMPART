# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 47_3
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `47_3`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1218-1277 of the vulnerable file.

                            "filename" => $direntry,
                            "status" => gT("OK")
                            );
                        }
                    } else {
                        // Extension forbidden
                        $aErrorFilesInfo[] = array(
                        "filename" => $direntry,
                        "status" => gT("Forbidden Extension")
                        );
                    }
                    unlink($extractdir."/".$direntry);
                }
            }
        }

        return array($aImportedFilesInfo, $aErrorFilesInfo);
    }

    /**
     * Creates a temporary directory
     *
     * @access protected
     * @param string $dir
     * @param string $prefix
     * @param int $mode
     * @return string
     */
    protected function _tempdir($dir, $prefix = '', $mode = 0700)
    {
        if (substr($dir, -1) != DIRECTORY_SEPARATOR) {
            $dir .= DIRECTORY_SEPARATOR;
        }

        do {
            $path = $dir.$prefix.mt_rand(0, 9999999);
        } while (!mkdir($path, $mode));

        return $path;
    }

    /**
     * Get extra menus from plugins that are using event beforeAdminMenuRender
     *
     * @param array $aData
     * @return array<ExtraMenu>
     */
    protected function fetchExtraMenus(array $aData)
    {
        $event = new PluginEvent('beforeAdminMenuRender', $this);
        $event->set('data', $aData);
        $result = App()->getPluginManager()->dispatchEvent($event);

        $extraMenus = $result->get('extraMenus');

        if ($extraMenus === null) {
            $extraMenus = array();
        }

        return $extraMenus;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1235,28 +1235,6 @@
     }
 
     /**
-     * Creates a temporary directory
-     *
-     * @access protected
-     * @param string $dir
-     * @param string $prefix
-     * @param int $mode
-     * @return string
-     */
-    protected function _tempdir($dir, $prefix = '', $mode = 0700)
-    {
-        if (substr($dir, -1) != DIRECTORY_SEPARATOR) {
-            $dir .= DIRECTORY_SEPARATOR;
-        }
-
-        do {
-            $path = $dir.$prefix.mt_rand(0, 9999999);
-        } while (!mkdir($path, $mode));
-
-        return $path;
-    }
-
-    /**
      * Get extra menus from plugins that are using event beforeAdminMenuRender
      *
      * @param array $aData
```
