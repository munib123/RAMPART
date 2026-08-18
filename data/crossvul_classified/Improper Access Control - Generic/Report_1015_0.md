# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in go
**Pair ID:** 1015_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1015_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```go
Lines 16-56 of the vulnerable file.

	if common.FileExists(path) {
		log.Fatalf("the path %s has exist, does not support install", path)
	}
	MkidrDirAll(path, "conf", "web/static", "web/views")
	//复制文件到对应目录
	if err := CopyDir(filepath.Join(common.GetAppPath(), "web", "views"), filepath.Join(path, "web", "views")); err != nil {
		log.Fatalln(err)
	}
	if err := CopyDir(filepath.Join(common.GetAppPath(), "web", "static"), filepath.Join(path, "web", "static")); err != nil {
		log.Fatalln(err)
	}
	if err := CopyDir(filepath.Join(common.GetAppPath(), "conf"), filepath.Join(path, "conf")); err != nil {
		log.Fatalln(err)
	}

	if !common.IsWindows() {
		if _, err := copyFile(filepath.Join(common.GetAppPath(), "nps"), "/usr/bin/nps"); err != nil {
			if _, err := copyFile(filepath.Join(common.GetAppPath(), "nps"), "/usr/local/bin/nps"); err != nil {
				log.Fatalln(err)
			} else {
				os.Chmod("/usr/local/bin/nps", 0777)
				log.Println("Executable files have been copied to", "/usr/local/bin/nps")
			}
		} else {
			os.Chmod("/usr/bin/nps", 0777)
			log.Println("Executable files have been copied to", "/usr/bin/nps")
		}

	}
	log.Println("install ok!")
	log.Println("Static files and configuration files in the current directory will be useless")
	log.Println("The new configuration file is located in", path, "you can edit them")
	if !common.IsWindows() {
		log.Println("You can start with nps test|start|stop|restart|status anywhere")
	} else {
		log.Println("You can copy executable files to any directory and start working with nps.exe test|start|stop|restart|status")
	}
}
func MkidrDirAll(path string, v ...string) {
	for _, item := range v {
		if err := os.MkdirAll(filepath.Join(path, item), 0755); err != nil {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,11 +33,11 @@
 			if _, err := copyFile(filepath.Join(common.GetAppPath(), "nps"), "/usr/local/bin/nps"); err != nil {
 				log.Fatalln(err)
 			} else {
-				os.Chmod("/usr/local/bin/nps", 0777)
+				os.Chmod("/usr/local/bin/nps", 0755)
 				log.Println("Executable files have been copied to", "/usr/local/bin/nps")
 			}
 		} else {
-			os.Chmod("/usr/bin/nps", 0777)
+			os.Chmod("/usr/bin/nps", 0755)
 			log.Println("Executable files have been copied to", "/usr/bin/nps")
 		}
 
```
