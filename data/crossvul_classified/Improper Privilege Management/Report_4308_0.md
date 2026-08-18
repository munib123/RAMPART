# CrossVul Fix Pair: Improper Privilege Management in go
**Pair ID:** 4308_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4308_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```go
Lines 197-237 of the vulnerable file.

	MacAddr            string             `json:"mac_addr"`
	MacAddrs           []string           `json:"mac_addrs"`
	SystemProfile      *sprofile.Sprofile `json:"-"`
}

type AuthData struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

func (p *Profile) write() (pth string, err error) {
	rootDir, err := utils.GetTempDir()
	if err != nil {
		return
	}

	pth = filepath.Join(rootDir, p.Id)

	err = ioutil.WriteFile(pth, []byte(p.Data), os.FileMode(0600))
	if err != nil {
		err = &WriteError{
			errors.Wrap(err, "profile: Failed to write profile"),
		}
		return
	}

	return
}

func (p *Profile) writeUp() (pth string, err error) {
	rootDir, err := utils.GetTempDir()
	if err != nil {
		return
	}

	pth = filepath.Join(rootDir, p.Id+"-up.sh")

	script := ""
	switch runtime.GOOS {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,6 +214,7 @@
 
 	pth = filepath.Join(rootDir, p.Id)
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(pth, []byte(p.Data), os.FileMode(0600))
 	if err != nil {
 		err = &WriteError{
@@ -261,6 +262,7 @@
 		panic("profile: Not implemented")
 	}
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(pth, []byte(script), os.FileMode(0755))
 	if err != nil {
 		err = &WriteError{
@@ -308,6 +310,7 @@
 		panic("profile: Not implemented")
 	}
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(pth, []byte(script), os.FileMode(0755))
 	if err != nil {
 		err = &WriteError{
@@ -327,6 +330,7 @@
 
 	pth = filepath.Join(rootDir, p.Id+"-block.sh")
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(pth, []byte(blockScript), os.FileMode(0755))
 	if err != nil {
 		err = &WriteError{
@@ -468,6 +472,7 @@
 
 	pth = filepath.Join(rootDir, p.Id+".auth")
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(pth, []byte(username+"\n"+password+"\n"),
 		os.FileMode(0600))
 	if err != nil {
@@ -511,6 +516,7 @@
 
 	pth = filepath.Join(rootDir, p.Id+".key")
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(
 		pth,
 		[]byte(p.PrivateKeyWg+"\n"),
@@ -599,7 +605,7 @@
 
 	pth = filepath.Join(rootDir, p.Iface+".conf")
 
-	os.Remove(pth)
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(
 		pth,
 		[]byte(output.String()),
```
