# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 586_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `586_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 173-207 of the vulnerable file.

    public function setFlushInterval($value)
    {
        $this->getLogger()->flushInterval = $value;
    }

    /**
     * Dispatches the logged messages to [[targets]].
     * @param array $messages the logged messages
     * @param bool $final whether this method is called at the end of the current application
     */
    public function dispatch($messages, $final)
    {
        $targetErrors = [];
        foreach ($this->targets as $target) {
            if ($target->enabled) {
                try {
                    $target->collect($messages, $final);
                } catch (\Exception $e) {
                    $target->enabled = false;
                    $targetErrors[] = [
                        'Unable to send log via ' . get_class($target) . ': ' . ErrorHandler::convertExceptionToString($e),
                        Logger::LEVEL_WARNING,
                        __METHOD__,
                        microtime(true),
                        [],
                    ];
                }
            }
        }

        if (!empty($targetErrors)) {
            $this->dispatch($targetErrors, true);
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -190,7 +190,7 @@
                 } catch (\Exception $e) {
                     $target->enabled = false;
                     $targetErrors[] = [
-                        'Unable to send log via ' . get_class($target) . ': ' . ErrorHandler::convertExceptionToString($e),
+                        'Unable to send log via ' . get_class($target) . ': ' . ErrorHandler::convertExceptionToVerboseString($e),
                         Logger::LEVEL_WARNING,
                         __METHOD__,
                         microtime(true),
```
