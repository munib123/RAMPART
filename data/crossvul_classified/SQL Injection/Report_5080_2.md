# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5080_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5080_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 20-47 of the vulnerable file.


import org.junit.Before;

public class SQLTestSuite extends SQLDataSetTestBase {

    protected <T extends SQLDataSetTestBase> T setUp(T test) throws Exception {
        test.testSettings = testSettings;
        test.conn = conn;
        return test;
    }

    protected List<SQLDataSetTestBase> sqlTestList = new ArrayList<SQLDataSetTestBase>();

    @Before
    public void setUp() throws Exception {
        super.setUp();
        sqlTestList.add(setUp(new SQLDataSetDefTest()));
        sqlTestList.add(setUp(new SQLDataSetTrimTest()));
        sqlTestList.add(setUp(new SQLTableDataSetLookupTest()));
        sqlTestList.add(setUp(new SQLQueryDataSetLookupTest()));
    }

    public void testAll() throws Exception {
        for (SQLDataSetTestBase testBase : sqlTestList) {
            testBase.testAll();
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,7 @@
         sqlTestList.add(setUp(new SQLDataSetTrimTest()));
         sqlTestList.add(setUp(new SQLTableDataSetLookupTest()));
         sqlTestList.add(setUp(new SQLQueryDataSetLookupTest()));
+        sqlTestList.add(setUp(new SQLInjectionAttacksTest()));
     }
 
     public void testAll() throws Exception {
```
