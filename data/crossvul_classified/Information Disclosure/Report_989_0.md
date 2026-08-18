# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 989_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `989_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

    private $repository;

    /**
     * Store data associated with current stage.
     *
     * @param array $data
     *
     * @return MessageBag
     */
    public function configureJob(array $data): MessageBag
    {
        $config = [];

        $config['fints_url']       = trim($data['fints_url'] ?? '');
        $config['fints_port']      = (int)($data['fints_port'] ?? '');
        $config['fints_bank_code'] = (string)($data['fints_bank_code'] ?? '');
        $config['fints_username']  = (string)($data['fints_username'] ?? '');
        $config['fints_password']  = (string)(Crypt::encrypt($data['fints_password']) ?? '');
        $config['apply-rules']     = 1 === (int)$data['apply_rules'];

        $this->repository->setConfiguration($this->importJob, $config);


        $incomplete = false;
        foreach ($config as $value) {
            $incomplete = '' === $value or $incomplete;
        }

        if ($incomplete) {
            return new MessageBag([trans('import.incomplete_fints_form')]);
        }
        $finTS = app(FinTS::class, ['config' => $this->importJob->configuration]);
        if (true !== ($checkConnection = $finTS->checkConnection())) {
            return new MessageBag([trans('import.fints_connection_failed', ['originalError' => $checkConnection])]);
        }

        $this->repository->setStage($this->importJob, FinTSConfigurationSteps::CHOOSE_ACCOUNT);

        return new MessageBag();
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,9 @@
         $config['fints_password']  = (string)(Crypt::encrypt($data['fints_password']) ?? '');
         $config['apply-rules']     = 1 === (int)$data['apply_rules'];
 
+        // sanitize FinTS URL.
+        $config['fints_url'] = $this->validURI($config['fints_url']) ? $config['fints_url'] : '';
+
         $this->repository->setConfiguration($this->importJob, $config);
 
 
@@ -108,4 +111,21 @@
         $this->repository->setUser($importJob->user);
     }
 
+    /**
+     * @param string $fints_url
+     *
+     * @return bool
+     */
+    private function validURI(string $fintsUri): bool
+    {
+        $res = filter_var($fintsUri, FILTER_VALIDATE_URL);
+        if (false === $res) {
+            return false;
+        }
+        $scheme = parse_url($fintsUri, PHP_URL_SCHEME);
+
+        return 'https' === $scheme;
+    }
+
+
 }
```
