# CrossVul Fix Pair: Improper Privilege Management in go
**Pair ID:** 4308_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4308_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```go
Lines 897-937 of the vulnerable file.


	pth := GetPidPath()
	pid := 0

	data, err := ioutil.ReadFile(pth)
	if err != nil {
		if !os.IsNotExist(err) {
			err = errortypes.ReadError{
				errors.Wrapf(err, "utils: Failed to read %s", pth),
			}
			return
		}
		err = nil
	} else {
		pidStr := strings.TrimSpace(string(data))
		if pidStr != "" {
			pid, _ = strconv.Atoi(pidStr)
		}
	}

	err = ioutil.WriteFile(
		pth,
		[]byte(strconv.Itoa(os.Getpid())),
		0644,
	)
	if err != nil {
		err = errortypes.WriteError{
			errors.Wrapf(err, "utils: Failed to write pid"),
		}
		return
	}

	if pid != 0 {
		proc, e := os.FindProcess(pid)
		if e == nil {
			proc.Signal(os.Interrupt)

			done := false

			go func() {
				defer func() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -914,6 +914,7 @@
 		}
 	}
 
+	_ = os.Remove(pth)
 	err = ioutil.WriteFile(
 		pth,
 		[]byte(strconv.Itoa(os.Getpid())),
```
