# CrossVul Fix Pair: Improper Neutralization of Formula Elements in a CSV File in php
**Pair ID:** 1936_0
**Vulnerability Class:** Improper Neutralization of Formula Elements in a CSV File
**CWE:** CWE-1236
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1936_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Formula Elements in a CSV File - User-provided data is often saved to traditional databases.

## Vulnerable Code
```php
Lines 72-112 of the vulnerable file.

                }
            }
            if (is_callable([$this, 'setDayValues'])) {
                $this->setDayValues($layers);
            }
        } elseif (strtotime($this->_employee->stats_date_to) - strtotime($this->_employee->stats_date_from) <= 2678400) {
            // If the granularity is inferior to 1 month
            // @TODO : change to manage 28 to 31 days

            if ($legend) {
                $days = [];
                if ($from_array['mon'] == $to_array['mon']) {
                    for ($i = $from_array['mday']; $i <= $to_array['mday']; ++$i) {
                        $days[] = $i;
                    }
                } else {
                    $imax = date('t', mktime(0, 0, 0, $from_array['mon'], 1, $from_array['year']));
                    for ($i = $from_array['mday']; $i <= $imax; ++$i) {
                        $days[] = $i;
                    }
                    for ($i = 1; $i <= $to_array['mday']; ++$i) {
                        $days[] = $i;
                    }
                }
                foreach ($days as $i) {
                    if ($layers == 1) {
                        $this->_values[$i] = 0;
                    } else {
                        for ($j = 0; $j < $layers; ++$j) {
                            $this->_values[$j][$i] = 0;
                        }
                    }
                    $this->_legend[$i] = ($i % 2) ? '' : sprintf('%02d', $i);
                }
            }
            if (is_callable([$this, 'setMonthValues'])) {
                $this->setMonthValues($layers);
            }
        } elseif (strtotime('-1 year', strtotime($this->_employee->stats_date_to)) < strtotime($this->_employee->stats_date_from)) {
            // If the granularity is less than 1 year

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,10 +89,12 @@
                     for ($i = $from_array['mday']; $i <= $imax; ++$i) {
                         $days[] = $i;
                     }
+
                     for ($i = 1; $i <= $to_array['mday']; ++$i) {
                         $days[] = $i;
                     }
                 }
+
                 foreach ($days as $i) {
                     if ($layers == 1) {
                         $this->_values[$i] = 0;
@@ -101,9 +103,11 @@
                             $this->_values[$j][$i] = 0;
                         }
                     }
+
                     $this->_legend[$i] = ($i % 2) ? '' : sprintf('%02d', $i);
                 }
             }
+
             if (is_callable([$this, 'setMonthValues'])) {
                 $this->setMonthValues($layers);
             }
@@ -146,6 +150,7 @@
                 for ($i = $from_array['year']; $i <= $to_array['year']; ++$i) {
                     $years[] = $i;
                 }
+
                 foreach ($years as $i) {
                     if ($layers == 1) {
                         $this->_values[$i] = 0;
@@ -157,6 +162,7 @@
                     $this->_legend[$i] = sprintf('%04d', $i);
                 }
             }
+
             if (is_callable([$this, 'setAllTimeValues'])) {
                 $this->setAllTimeValues($layers);
             }
@@ -174,6 +180,7 @@
         if (isset($datas['option'])) {
             $this->setOption($datas['option'], $layers);
         }
+
         $this->getData($layers);
 
         // @todo use native CSV PHP functions ?
@@ -184,15 +191,17 @@
                     $this->_csv .= ';';
                 }
                 if (isset($this->_titles['main'][$i])) {
-                    $this->_csv .= $this->_titles['main'][$i];
+                    $this->_csv .= $this->escapeCell($this->_titles['main'][$i]);
                 }
             }
         } else { // If there is only one column title, there is in fast two column (the first without title)
-            $this->_csv .= ';' . $this->_titles['main'];
-        }
+            $this->_csv .= ';' . $this->escapeCell($this->_titles['main']);
+        }
+
         $this->_csv .= "\n";
         if (count($this->_legend)) {
             $total = 0;
+
             if ($datas['type'] == 'pie') {
                 foreach ($this->_legend as $key => $legend) {
                     for ($i = 0, $total_main = (is_array($this->_titles['main']) ? count($this->_values) : 1); $i < $total_main; ++$i) {
@@ -200,8 +209,9 @@
                     }
                 }
             }
+
             foreach ($this->_legend as $key => $legend) {
-                $this->_csv .= $legend . ';';
+                $this->_csv .= $this->escapeCell($legend) . ';';
                 for ($i = 0, $total_main = (is_array($this->_titles['main']) ? count($this->_values) : 1); $i < $total_main; ++$i) {
                     if (!isset($this->_values[$i]) || !is_array($this->_values[$i])) {
                         if (isset($this->_values[$key])) {
@@ -209,7 +219,7 @@
                             if (is_numeric($this->_values[$key])) {
                                 $this->_csv .= $this->_values[$key] / (($datas['type'] == 'pie') ? $total : 1);
                             } else {
-                                $this->_csv .= $this->_values[$key];
+                                $this->_csv .= $this->escapeCell($this->_values[$key]);
                             }
                         } else {
                             $this->_csv .= '0';
@@ -219,7 +229,7 @@
                         if (is_numeric($this->_values[$i][$key])) {
                             $this->_csv .= $this->_values[$i][$key] / (($datas['type'] == 'pie') ? $total : 1);
                         } else {
-                            $this->_csv .= $this->_values[$i][$key];
+                            $this->_csv .= $this->escapeCell($this->_values[$i][$key]);
                         }
                     }
                     $this->_csv .= ';';
@@ -227,6 +237,7 @@
                 $this->_csv .= "\n";
             }
         }
+
         $this->_displayCsv();
     }
 
@@ -342,12 +353,12 @@
 
     public function getDate()
     {
-        return ModuleGraph::getDateBetween($this->_employee);
+        return static::getDateBetween($this->_employee);
     }
 
     public static function getDateBetween($employee = null)
     {
-        if ($employee = ModuleGraph::getEmployee($employee)) {
+        if ($employee = static::getEmployee($employee)) {
             return ' \'' . pSQL($employee->stats_date_from) . ' 00:00:00\' AND \'' . pSQL($employee->stats_date_to) . ' 23:59:59\' ';
         }
 
@@ -358,4 +369,27 @@
     {
         return $this->_id_lang;
     }
+
+    /**
+     * Escape cell content.
+     * If the content begins with =+-@ a quote is added at the beginning of
+     * the string.
+     * In all situation, add double quote to encapsulate the content.
+     *
+     * @param string $content
+     *
+     * @return string
+     */
+    public function escapeCell(string $content): string
+    {
+        $escaped = '"';
+        if (preg_match('~^[=+\-@]~', $content)) {
+            $content = '\'' . $content;
+        }
+
+        $escaped .= str_replace('"', '""', $content);
+        $escaped .= '"';
+
+        return $escaped;
+    }
 }
```
