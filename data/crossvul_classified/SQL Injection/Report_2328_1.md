# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2328_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2328_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 194-234 of the vulnerable file.

	sess := x.Limit(20, (page-1)*20)

	if rid > 0 {
		sess.Where("repo_id=?", rid).And("is_closed=?", isClosed)
	} else {
		sess.Where("is_closed=?", isClosed)
	}

	if uid > 0 {
		sess.And("assignee_id=?", uid)
	} else if pid > 0 {
		sess.And("poster_id=?", pid)
	}

	if mid > 0 {
		sess.And("milestone_id=?", mid)
	}

	if len(labelIds) > 0 {
		for _, label := range strings.Split(labelIds, ",") {
			sess.And("label_ids like '%$" + label + "|%'")
		}
	}

	switch sortType {
	case "oldest":
		sess.Asc("created")
	case "recentupdate":
		sess.Desc("updated")
	case "leastupdate":
		sess.Asc("updated")
	case "mostcomment":
		sess.Desc("num_comments")
	case "leastcomment":
		sess.Asc("num_comments")
	case "priority":
		sess.Desc("priority")
	default:
		sess.Desc("created")
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,7 +211,10 @@
 
 	if len(labelIds) > 0 {
 		for _, label := range strings.Split(labelIds, ",") {
-			sess.And("label_ids like '%$" + label + "|%'")
+			// Prevent SQL inject.
+			if com.StrTo(label).MustInt() > 0 {
+				sess.And("label_ids like '%$" + label + "|%'")
+			}
 		}
 	}
 
```
