# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2329_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2329_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 1144-1184 of the vulnerable file.


// SearchRepositoryByName returns given number of repositories whose name contains keyword.
func SearchRepositoryByName(opt SearchOption) (repos []*Repository, err error) {
	// Prevent SQL inject.
	opt.Keyword = FilterSQLInject(opt.Keyword)
	if len(opt.Keyword) == 0 {
		return repos, nil
	}
	opt.Keyword = strings.ToLower(opt.Keyword)

	repos = make([]*Repository, 0, opt.Limit)

	// Append conditions.
	sess := x.Limit(opt.Limit)
	if opt.Uid > 0 {
		sess.Where("owner_id=?", opt.Uid)
	}
	if !opt.Private {
		sess.And("is_private=false")
	}
	sess.And("lower_name like '%" + opt.Keyword + "%'").Find(&repos)
	return repos, err
}

//  __      __         __         .__
// /  \    /  \_____ _/  |_  ____ |  |__
// \   \/\/   /\__  \\   __\/ ___\|  |  \
//  \        /  / __ \|  | \  \___|   Y  \
//   \__/\  /  (____  /__|  \___  >___|  /
//        \/        \/          \/     \/

// Watch is connection request for receiving repository notifycation.
type Watch struct {
	Id     int64
	UserId int64 `xorm:"UNIQUE(watch)"`
	RepoId int64 `xorm:"UNIQUE(watch)"`
}

// IsWatching checks if user has watched given repository.
func IsWatching(uid, repoId int64) bool {
	has, _ := x.Get(&Watch{0, uid, repoId})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1161,7 +1161,7 @@
 	if !opt.Private {
 		sess.And("is_private=false")
 	}
-	sess.And("lower_name like '%" + opt.Keyword + "%'").Find(&repos)
+	sess.And("lower_name like ?", "%"+opt.Keyword+"%").Find(&repos)
 	return repos, err
 }
 
```
