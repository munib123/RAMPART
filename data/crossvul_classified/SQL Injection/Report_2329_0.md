# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in go
**Pair ID:** 2329_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2329_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```go
Lines 55-95 of the vulnerable file.

func checkVersion() {
	// Templates.
	data, err := ioutil.ReadFile(path.Join(setting.StaticRootPath, "templates/.VERSION"))
	if err != nil {
		log.Fatal(4, "Fail to read 'templates/.VERSION': %v", err)
	}
	if string(data) != setting.AppVer {
		log.Fatal(4, "Binary and template file version does not match, did you forget to recompile?")
	}

	// Check dependency version.
	macaronVer := git.MustParseVersion(strings.Join(strings.Split(macaron.Version(), ".")[:3], "."))
	if macaronVer.LessThan(git.MustParseVersion("0.2.3")) {
		log.Fatal(4, "Package macaron version is too old, did you forget to update?(github.com/Unknwon/macaron)")
	}
	i18nVer := git.MustParseVersion(i18n.Version())
	if i18nVer.LessThan(git.MustParseVersion("0.0.2")) {
		log.Fatal(4, "Package i18n version is too old, did you forget to update?(github.com/macaron-contrib/i18n)")
	}
	sessionVer := git.MustParseVersion(session.Version())
	if sessionVer.LessThan(git.MustParseVersion("0.0.3")) {
		log.Fatal(4, "Package session version is too old, did you forget to update?(github.com/macaron-contrib/session)")
	}
}

// newMacaron initializes Macaron instance.
func newMacaron() *macaron.Macaron {
	m := macaron.New()
	m.Use(macaron.Logger())
	m.Use(macaron.Recovery())
	if setting.EnableGzip {
		m.Use(macaron.Gziper())
	}
	m.Use(macaron.Static(
		path.Join(setting.StaticRootPath, "public"),
		macaron.StaticOptions{
			SkipLogging: !setting.DisableRouterLog,
		},
	))
	m.Use(macaron.Renderer(macaron.RenderOptions{
		Directory:  path.Join(setting.StaticRootPath, "templates"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 		log.Fatal(4, "Package i18n version is too old, did you forget to update?(github.com/macaron-contrib/i18n)")
 	}
 	sessionVer := git.MustParseVersion(session.Version())
-	if sessionVer.LessThan(git.MustParseVersion("0.0.3")) {
+	if sessionVer.LessThan(git.MustParseVersion("0.0.5")) {
 		log.Fatal(4, "Package session version is too old, did you forget to update?(github.com/macaron-contrib/session)")
 	}
 }
```
