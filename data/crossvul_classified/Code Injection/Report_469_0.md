# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 469_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `469_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 806-847 of the vulnerable file.

                continue;
            }

            $categoryData[] = [
                'id' => $category->getId(),
                'name' => $category->getName(),
                'learnpaths' => $listData,
            ];
        }

        return $categoryData;
    }

    /**
     * @param string $encoded
     *
     * @return array
     */
    public static function decodeParams($encoded)
    {
        $decoded = str_replace(['-', '_', '.'], ['+', '/', '='], $encoded);
        $mod4 = strlen($decoded) % 4;

        if ($mod4) {
            $decoded .= substr('====', $mod4);
        }

        $b64Decoded = base64_decode($decoded);

        return unserialize($b64Decoded);
    }

    /**
     * Start login for a user. Then make a redirect to show the learnpath.
     *
     * @param int $lpId
     */
    public function showLearningPath($lpId)
    {
        $loggedUser['user_id'] = $this->user->getId();
        $loggedUser['status'] = $this->user->getStatus();
        $loggedUser['uidReset'] = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -823,16 +823,9 @@
      */
     public static function decodeParams($encoded)
     {
-        $decoded = str_replace(['-', '_', '.'], ['+', '/', '='], $encoded);
-        $mod4 = strlen($decoded) % 4;
-
-        if ($mod4) {
-            $decoded .= substr('====', $mod4);
-        }
-
-        $b64Decoded = base64_decode($decoded);
-
-        return unserialize($b64Decoded);
+        $decoded = json_decode($encoded);
+
+        return $decoded;
     }
 
     /**
@@ -1319,10 +1312,8 @@
             'api_key' => $this->apiKey,
             'username' => $this->user->getUsername(),
         ]);
-
-        $strParams = serialize($params);
-        $b64Encoded = base64_encode($strParams);
-
-        return str_replace(['+', '/', '='], ['-', '_', '.'], $b64Encoded);
+        $encoded = json_encode($params);
+
+        return $encoded;
     }
 }
```
