# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2328_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2328_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 12-52 of the vulnerable file.

	"github.com/Unknwon/com"

	"github.com/gogits/gogs/models"
	"github.com/gogits/gogs/modules/auth"
	"github.com/gogits/gogs/modules/log"
	"github.com/gogits/gogs/modules/middleware"
)

type repo struct {
	RepoLink string `json:"repolink"`
}

func SearchRepos(ctx *middleware.Context) {
	opt := models.SearchOption{
		Keyword: path.Base(ctx.Query("q")),
		Uid:     com.StrTo(ctx.Query("uid")).MustInt64(),
		Limit:   com.StrTo(ctx.Query("limit")).MustInt(),
	}
	if opt.Limit == 0 {
		opt.Limit = 10
	}

	repos, err := models.SearchRepositoryByName(opt)
	if err != nil {
		ctx.JSON(500, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	results := make([]*repo, len(repos))
	for i := range repos {
		if err = repos[i].GetOwner(); err != nil {
			ctx.JSON(500, map[string]interface{}{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}
		results[i] = &repo{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,26 @@
 	}
 	if opt.Limit == 0 {
 		opt.Limit = 10
+	}
+
+	// Check visibility.
+	if ctx.IsSigned && opt.Uid > 0 {
+		if ctx.User.Id == opt.Uid {
+			opt.Private = true
+		} else {
+			u, err := models.GetUserById(opt.Uid)
+			if err != nil {
+				ctx.JSON(500, map[string]interface{}{
+					"ok":    false,
+					"error": err.Error(),
+				})
+				return
+			}
+			if u.IsOrganization() && u.IsOrgOwner(ctx.User.Id) {
+				opt.Private = true
+			}
+			// FIXME: how about collaborators?
+		}
 	}
 
 	repos, err := models.SearchRepositoryByName(opt)
```
