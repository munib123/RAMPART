# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in java
**Pair ID:** 5080_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5080_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```java
Lines 528-568 of the vulnerable file.

        }
        return getStringParameterSQL(param.toString());
    }


    @Override
    public String getNumberParameterSQL(Number param) {
        return param.toString();
    }

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S");

    @Override
    public String getDateParameterSQL(Date param) {
        // timestamp '2015-08-24 13:14:36.615'
        return "TIMESTAMP '" + dateFormat.format(param) + "'";
    }

    @Override
    public String getStringParameterSQL(String param) {
        return "'" + param + "'";
    }

    @Override
    public String getLogicalConditionSQL(LogicalCondition condition) {
        LogicalExprType type = condition.getType();
        Condition[] conditions = condition.getConditions();
        if (LogicalExprType.NOT.equals(type)) {
            return getNotExprConditionSQL(conditions[0]);
        }
        if (LogicalExprType.AND.equals(type)) {
            return getAndExprConditionSQL(conditions);
        }
        if (LogicalExprType.OR.equals(type)) {
            return getOrExprConditionSQL(conditions);
        }
        throw new IllegalArgumentException("Logical condition type not supported: " + type);
    }

    @Override
    public String getNotExprConditionSQL(Condition condition) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -545,7 +545,9 @@
 
     @Override
     public String getStringParameterSQL(String param) {
-        return "'" + param + "'";
+        // DASHBUILDE-113: SQL Injection on data set lookup filters
+        String escapedParam = param.replaceAll("'", "''");
+        return "'" + escapedParam + "'";
     }
 
     @Override
```
