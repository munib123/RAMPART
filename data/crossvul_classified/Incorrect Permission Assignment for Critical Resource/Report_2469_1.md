# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 2469_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2469_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 1568-1588 of the vulnerable file.

		int amount = Integer.valueOf(countString);

		TemporalUnit field;
		String dmyString = matcher.group(2);
		switch (dmyString) {
			case "d":
				field = ChronoUnit.DAYS;
				break;
			case "m":
				field = ChronoUnit.MONTHS;
				break;
			case "y":
				field = ChronoUnit.YEARS;
				break;
			default:
				throw new InternalErrorException("Wrong format of gracePeriod.");
		}

		return new Pair<>(amount, field);
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1585,4 +1585,16 @@
 
 		return new Pair<>(amount, field);
 	}
+
+	/**
+	 * We need to escape some special characters for LDAP filtering.
+	 * We need to escape these characters: '\\', '*', '(', ')', '\000'
+	 *
+	 * @param searchString search string which need to be escaped properly
+	 * @return properly escaped search string
+	 */
+	public static String escapeStringForLDAP(String searchString) {
+		if(searchString == null) return "";
+		return searchString.replace("\\", "\\5C").replace("*", "\\2A").replace("(", "\\28").replace(")", "\\29").replace("\000", "\\00");
+	}
 }
```
