# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2329_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2329_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 377-419 of the vulnerable file.

		CacheConn = strings.Trim(Cfg.MustValue("cache", "HOST"), "\" ")
	default:
		log.Fatal(4, "Unknown cache adapter: %s", CacheAdapter)
	}

	log.Info("Cache Service Enabled")
}

func newSessionService() {
	SessionProvider = Cfg.MustValueRange("session", "PROVIDER", "memory",
		[]string{"memory", "file", "redis", "mysql"})

	SessionConfig = new(session.Config)
	SessionConfig.ProviderConfig = strings.Trim(Cfg.MustValue("session", "PROVIDER_CONFIG"), "\" ")
	SessionConfig.CookieName = Cfg.MustValue("session", "COOKIE_NAME", "i_like_gogits")
	SessionConfig.CookiePath = AppSubUrl
	SessionConfig.Secure = Cfg.MustBool("session", "COOKIE_SECURE")
	SessionConfig.EnableSetCookie = Cfg.MustBool("session", "ENABLE_SET_COOKIE", true)
	SessionConfig.Gclifetime = Cfg.MustInt64("session", "GC_INTERVAL_TIME", 86400)
	SessionConfig.Maxlifetime = Cfg.MustInt64("session", "SESSION_LIFE_TIME", 86400)
	SessionConfig.SessionIDHashFunc = Cfg.MustValueRange("session", "SESSION_ID_HASHFUNC",
		"sha1", []string{"sha1", "sha256", "md5"})
	SessionConfig.SessionIDHashKey = Cfg.MustValue("session", "SESSION_ID_HASHKEY", string(com.RandomCreateBytes(16)))

	if SessionProvider == "file" {
		os.MkdirAll(path.Dir(SessionConfig.ProviderConfig), os.ModePerm)
	}

	log.Info("Session Service Enabled")
}

// Mailer represents mail service.
type Mailer struct {
	Name         string
	Host         string
	From         string
	User, Passwd string
}

type OauthInfo struct {
	ClientId, ClientSecret string
	Scopes                 string
	AuthUrl, TokenUrl      string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -394,9 +394,6 @@
 	SessionConfig.EnableSetCookie = Cfg.MustBool("session", "ENABLE_SET_COOKIE", true)
 	SessionConfig.Gclifetime = Cfg.MustInt64("session", "GC_INTERVAL_TIME", 86400)
 	SessionConfig.Maxlifetime = Cfg.MustInt64("session", "SESSION_LIFE_TIME", 86400)
-	SessionConfig.SessionIDHashFunc = Cfg.MustValueRange("session", "SESSION_ID_HASHFUNC",
-		"sha1", []string{"sha1", "sha256", "md5"})
-	SessionConfig.SessionIDHashKey = Cfg.MustValue("session", "SESSION_ID_HASHKEY", string(com.RandomCreateBytes(16)))
 
 	if SessionProvider == "file" {
 		os.MkdirAll(path.Dir(SessionConfig.ProviderConfig), os.ModePerm)
```
