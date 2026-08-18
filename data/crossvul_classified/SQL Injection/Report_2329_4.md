# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2329_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2329_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 564-604 of the vulnerable file.

	}
	user := &User{Email: strings.ToLower(email)}
	has, err := x.Get(user)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrUserNotExist
	}
	return user, nil
}

// SearchUserByName returns given number of users whose name contains keyword.
func SearchUserByName(opt SearchOption) (us []*User, err error) {
	opt.Keyword = FilterSQLInject(opt.Keyword)
	if len(opt.Keyword) == 0 {
		return us, nil
	}
	opt.Keyword = strings.ToLower(opt.Keyword)

	us = make([]*User, 0, opt.Limit)
	err = x.Limit(opt.Limit).Where("type=0").And("lower_name like '%" + opt.Keyword + "%'").Find(&us)
	return us, err
}

// Follow is connection request for receiving user notifycation.
type Follow struct {
	Id       int64
	UserId   int64 `xorm:"unique(follow)"`
	FollowId int64 `xorm:"unique(follow)"`
}

// FollowUser marks someone be another's follower.
func FollowUser(userId int64, followId int64) (err error) {
	sess := x.NewSession()
	defer sess.Close()
	sess.Begin()

	if _, err = sess.Insert(&Follow{UserId: userId, FollowId: followId}); err != nil {
		sess.Rollback()
		return err
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -581,7 +581,7 @@
 	opt.Keyword = strings.ToLower(opt.Keyword)
 
 	us = make([]*User, 0, opt.Limit)
-	err = x.Limit(opt.Limit).Where("type=0").And("lower_name like '%" + opt.Keyword + "%'").Find(&us)
+	err = x.Limit(opt.Limit).Where("type=0").And("lower_name like ?", "%"+opt.Keyword+"%").Find(&us)
 	return us, err
 }
 
```
