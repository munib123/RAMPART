# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2814_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2814_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 181-221 of the vulnerable file.

     */
    private function _raw($convert = false, $options = array())
    {
        $options = array_merge(
            array('index' => 0, 'preserve_data' => false),
            $options
        );

        if (empty($this->_data) ||
            // If there are no operations, and we already have data, don't
            // bother writing out files, just return the current data.
            (!$convert &&
             !count($this->_operations) &&
             !count($this->_postSrcOperations))) {
            return $this->_data;
        }

        $tmpin = $this->toFile($this->_data);
        $tmpout = Horde_Util::getTempFile('img', false, $this->_tmpdir);
        $command = $this->_convert . ' ' . implode(' ', $this->_operations)
            . ' "' . $tmpin . '"\'[' . $options['index'] . ']\' '
            . implode(' ', $this->_postSrcOperations)
            . ' -strip ' . $this->_type . ':"' . $tmpout . '" 2>&1';
        $this->_logDebug(sprintf("convert command executed by Horde_Image_im::raw(): %s", $command));
        exec($command, $output, $retval);
        if ($retval) {
            $error = sprintf("Error running command: %s", $command . "\n" . implode("\n", $output));
            $this->_logErr($error);
            throw new Horde_Image_Exception($error);
        }

        /* Empty the operations queue */
        $this->_operations = array();
        $this->_postSrcOperations = array();

        /* Load the result */
        $fp = fopen($tmpout, 'r');
        $return = new Horde_Stream_Temp();
        $return->add($fp, true);
        if (empty($options['preserve_data'])) {
            if ($this->_data) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,7 +198,7 @@
         $tmpin = $this->toFile($this->_data);
         $tmpout = Horde_Util::getTempFile('img', false, $this->_tmpdir);
         $command = $this->_convert . ' ' . implode(' ', $this->_operations)
-            . ' "' . $tmpin . '"\'[' . $options['index'] . ']\' '
+            . ' "' . $tmpin . '"\'[' . (integer)$options['index'] . ']\' '
             . implode(' ', $this->_postSrcOperations)
             . ' -strip ' . $this->_type . ':"' . $tmpout . '" 2>&1';
         $this->_logDebug(sprintf("convert command executed by Horde_Image_im::raw(): %s", $command));
```
