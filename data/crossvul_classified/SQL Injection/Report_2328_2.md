# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2328_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2328_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 1114-1154 of the vulnerable file.

func GetCollaborators(repoName string) (us []*User, err error) {
	accesses := make([]*Access, 0, 10)
	if err = x.Find(&accesses, &Access{RepoName: strings.ToLower(repoName)}); err != nil {
		return nil, err
	}

	us = make([]*User, len(accesses))
	for i := range accesses {
		us[i], err = GetUserByName(accesses[i].UserName)
		if err != nil {
			return nil, err
		}
	}
	return us, nil
}

type SearchOption struct {
	Keyword string
	Uid     int64
	Limit   int
}

// SearchRepositoryByName returns given number of repositories whose name contains keyword.
func SearchRepositoryByName(opt SearchOption) (repos []*Repository, err error) {
	// Prevent SQL inject.
	opt.Keyword = strings.TrimSpace(opt.Keyword)
	if len(opt.Keyword) == 0 {
		return repos, nil
	}

	opt.Keyword = strings.Split(opt.Keyword, " ")[0]
	if len(opt.Keyword) == 0 {
		return repos, nil
	}
	opt.Keyword = strings.ToLower(opt.Keyword)

	repos = make([]*Repository, 0, opt.Limit)

	// Append conditions.
	sess := x.Limit(opt.Limit)
	if opt.Uid > 0 {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1131,17 +1131,21 @@
 	Keyword string
 	Uid     int64
 	Limit   int
+	Private bool
+}
+
+// FilterSQLInject tries to prevent SQL injection.
+func FilterSQLInject(key string) string {
+	key = strings.TrimSpace(key)
+	key = strings.Split(key, " ")[0]
+	key = strings.Replace(key, ",", "", -1)
+	return key
 }
 
 // SearchRepositoryByName returns given number of repositories whose name contains keyword.
 func SearchRepositoryByName(opt SearchOption) (repos []*Repository, err error) {
 	// Prevent SQL inject.
-	opt.Keyword = strings.TrimSpace(opt.Keyword)
-	if len(opt.Keyword) == 0 {
-		return repos, nil
-	}
-
-	opt.Keyword = strings.Split(opt.Keyword, " ")[0]
+	opt.Keyword = FilterSQLInject(opt.Keyword)
 	if len(opt.Keyword) == 0 {
 		return repos, nil
 	}
@@ -1153,6 +1157,9 @@
 	sess := x.Limit(opt.Limit)
 	if opt.Uid > 0 {
 		sess.Where("owner_id=?", opt.Uid)
+	}
+	if !opt.Private {
+		sess.And("is_private=false")
 	}
 	sess.And("lower_name like '%" + opt.Keyword + "%'").Find(&repos)
 	return repos, err
```
