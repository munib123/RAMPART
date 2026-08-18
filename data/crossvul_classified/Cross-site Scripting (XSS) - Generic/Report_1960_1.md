# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1960_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1960_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 82-122 of the vulnerable file.

            weekNumbers: false,
            firstDay   : " . ($GLOBALS['pref']['ui_week_start_day'] ? 1 : 0) . ",
            electric   : false
        })
        Calendar.setup({
            inputField : '{$this->_name}_end',
            ifFormat   : '%Y-%m-%d',
            button     : '{$this->_name}_end_button',
            align      : 'Bl',
            weekNumbers: false,
            firstDay   : " . ($GLOBALS['pref']['ui_week_start_day'] ? 1 : 0) . ",
            electric   : false
        })
        // Tabindex handling
        {$this->_name}TabIndex = " . ($this->_tabIndex - 4) . ";
        // Functions
        function {$this->_name}Reset()
        {
            document.getElementById('{$this->_name}_start').value = '$startDateStr';
            document.getElementById('{$this->_name}_start').value = '$endDateStr';
            document.getElementById('{$this->_name}_preset').value = '{$this->_fieldSelectionValue}';
        }
        function {$this->_name}FormSubmit() {
            submitForm();
            return false;
        }
        function {$this->_name}FormChange(bAutoSubmit)
        {
            var o = document.getElementById('{$this->_name}_preset');
            var {$this->_name}SelectName = o.options[o.selectedIndex].value;
            var specific = {$this->_name}SelectName == 'specific';";

        $oTmpDaySpan = new OA_Admin_DaySpan();
        foreach ($this->_fieldSelectionNames as $v => $n) {
            if ($v != 'specific') {
                if ($v != 'all_events') {
                    $oTmpDaySpan->setSpanPresetValue($v);
                    $oTmpStartDate = $oTmpDaySpan->getStartDate();
                    $sTmpStartDate = $oTmpStartDate->format('%Y-%m-%d');
                    $oTmpEndDate   = $oTmpDaySpan->getEndDate();
                    $sTmpEndDate   = $oTmpEndDate->format('%Y-%m-%d');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
         {
             document.getElementById('{$this->_name}_start').value = '$startDateStr';
             document.getElementById('{$this->_name}_start').value = '$endDateStr';
-            document.getElementById('{$this->_name}_preset').value = '{$this->_fieldSelectionValue}';
+            document.getElementById('{$this->_name}_preset').value = \"".addcslashes(stripslashes($this->_fieldSelectionValue), "\0..\37/\"\\")."\";
         }
         function {$this->_name}FormSubmit() {
             submitForm();
```
