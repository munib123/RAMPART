# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2941_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2941_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 166-206 of the vulnerable file.

            // re-use the same DumpOutput instance, so it won't re-render the global styles/scripts on each dump.
            // exclude verbose information (e.g. exception stack traces)
            if (class_exists('Symfony\Component\VarDumper\Caster\Caster')) {
                $cloneVar = $this->getCloner()->cloneVar($value, Caster::EXCLUDE_VERBOSE);
                // Symfony VarDumper 2.6 Caster class dont exist.
            } else {
                $cloneVar = $this->getCloner()->cloneVar($value);
            }

            $dumper->dump(
                $cloneVar,
                $this->htmlDumperOutput
            );

            $output = $this->htmlDumperOutput->getOutput();
            $this->htmlDumperOutput->clear();

            return $output;
        }

        return print_r($value, true);
    }

    /**
     * Format the args of the given Frame as a human readable html string
     *
     * @param  Frame $frame
     * @return string the rendered html
     */
    public function dumpArgs(Frame $frame)
    {
        // we support frame args only when the optional dumper is available
        if (!$this->getDumper()) {
            return '';
        }

        $html = '';
        $numFrames = count($frame->getArgs());

        if ($numFrames > 0) {
            $html = '<ol class="linenums">';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -183,7 +183,7 @@
             return $output;
         }
 
-        return print_r($value, true);
+        return htmlspecialchars(print_r($value, true));
     }
 
     /**
```
