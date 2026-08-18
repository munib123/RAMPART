# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1483-1523 of the vulnerable file.


    /**
     * This converts the sql statement into a nice CSV.
     * We grab the items array which is stored funkily in the DB in an associative array when we pull it.
     * So basically our aray looks like this:
     *
     * ITEMS
     * {[id]=>myID, [Name]=>name, [Address]=>myaddr}
     * {[id]=>myID1, [Name]=>name1, [Address]=>myaddr1}
     * {[id]=>myID2, [Name]=>name2, [Address]=>myaddr2}
     * {[id]=>myID3, [Name]=>name3, [Address]=>myaddr3}
     * {[id]=>myID4, [Name]=>name4, [Address]=>myaddr4}
     * {[id]=>myID5, [Name]=>name5, [Address]=>myaddr5}
     *
     * So by nature of the array, the keys are repetated in each line (id, name, etc)
     * So if we want to make a header row, we just run through once at the beginning and
     * use the array_keys function to strip out a functional header
     *
     * @param      $items
     *
     * @param null $rptcols
     *
     * @return string
     */
    public static function sql2csv($items, $rptcols = null) {
        $str = "";
        foreach ($rptcols as $individual_Header) {
            if (!is_array($rptcols) || in_array($individual_Header, $rptcols)) $str .= $individual_Header . ",";  //FIXME $individual_Header is ALWAYS in $rptcols?
        }
        $str .= "\r\n";
        foreach ($items as $item) {
            foreach ($rptcols as $key => $rowitem) {
                if (!is_array($rptcols) || property_exists($item, $key)) {
                    $rowitem = str_replace(",", " ", $item->$key);
                    $str .= $rowitem . ",";
                }
            } //foreach rowitem
            $str = substr($str, 0, strlen($str) - 1);
            $str .= "\r\n";
        } //end of foreach loop
        return $str;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1500,7 +1500,7 @@
      *
      * @param      $items
      *
-     * @param null $rptcols
+     * @param array|null $rptcols
      *
      * @return string
      */
```
