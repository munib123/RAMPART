# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1653_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1653_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1699-1739 of the vulnerable file.

                    if (isset($_POST['closerecord']) && isset($_POST['token']) && $_POST['token'] != '') // submittoken
                    {
                        // get submit date
                        if (isset($_POST['closedate']))
                        { $submitdate = $_POST['closedate']; }
                        else
                        { $submitdate = dateShift(date("Y-m-d H:i:s"), "Y-m-d", $timeadjust); }

                        // check how many uses the token has left
                        $usesquery = "SELECT usesleft FROM {{tokens_}}$surveyid WHERE token=".App()->db->quoteValue($_POST['token']);
                        $usesresult = dbExecuteAssoc($usesquery);
                        $usesrow = $usesresult->readAll(); //$usesresult->row_array()
                        if (isset($usesrow)) { $usesleft = $usesrow[0]['usesleft']; }

                        // query for updating tokens
                        $utquery = "UPDATE {{tokens_$surveyid}}\n";
                        if (isTokenCompletedDatestamped($thissurvey))
                        {
                            if (isset($usesleft) && $usesleft<=1)
                            {
                                $utquery .= "SET usesleft=usesleft-1, completed='$submitdate'\n";
                            }
                            else
                            {
                                $utquery .= "SET usesleft=usesleft-1\n";
                            }
                        }
                        else
                        {
                            if (isset($usesleft) && $usesleft<=1)
                            {
                                $utquery .= "SET usesleft=usesleft-1, completed='Y'\n";
                            }
                            else
                            {
                                $utquery .= "SET usesleft=usesleft-1\n";
                            }
                        }
                        $utquery .= "WHERE token=".App()->db->quoteValue($_POST['token']);
                        $utresult = dbExecuteAssoc($utquery); //Yii::app()->db->Execute($utquery) or safeDie ("Couldn't update tokens table!<br />\n$utquery<br />\n".Yii::app()->db->ErrorMsg());

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1716,7 +1716,7 @@
                         {
                             if (isset($usesleft) && $usesleft<=1)
                             {
-                                $utquery .= "SET usesleft=usesleft-1, completed='$submitdate'\n";
+                                $utquery .= "SET usesleft=usesleft-1, completed=".dbQuoteAll($submitdate);
                             }
                             else
                             {
```
