# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in xml
**Pair ID:** 5179_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5179_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```xml
Lines 1308-1348 of the vulnerable file.

            To test this package please follow the examples described in the Usage section, all the
            tests cases should return the expected results defined at the beginning of each example.
        </para>
    </section>
    <section>
        <title>Unit Tests</title>
        <para>
            To ensure the quality of the module, several so-called unit tests were created, to test
            the functionalities of this module. These unit tests can be run via command line.
        </para>
        <para>
            ATTENTION: Please never run unit tests on a productive system, since the added test data
            to the system will no longer be removed. Always use a test system.
        </para>
        <para>Run the package specific unit tests</para>
        <para>
            To run only the unit test which will be delivered with this package, use the following
            command on the command line:
        </para>
        <screen>
shell> perl bin/otrs.UnitTest.pl -n FAQ:FAQSearch:GenericInterface/FAQConnector
        </screen>
        <para>Run all available unit tests</para>
        <para>
            To run all available unit tests, use the following command on the command line:
        </para>
        <screen>shell> perl bin/otrs.UnitTest.pl</screen>
    </section>
</chapter>

<!-- ************* -->
<!-- 10. Changelog -->
<!-- ************* -->
<chapter>
    <title>ChangeLog</title>
    <para>$ChangeLog</para>
</chapter>

<!-- ************** -->
<!-- 11. Appendixes -->
<!-- ************** -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1325,7 +1325,7 @@
             command on the command line:
         </para>
         <screen>
-shell> perl bin/otrs.UnitTest.pl -n FAQ:FAQSearch:GenericInterface/FAQConnector
+shell> perl bin/otrs.UnitTest.pl -n FAQ:FAQSearch:FAQSearch/InConditionGet:GenericInterface/FAQConnector
         </screen>
         <para>Run all available unit tests</para>
         <para>
```
