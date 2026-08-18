# CrossVul Fix Pair: Use After Free in go
**Pair ID:** 446_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `446_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```go
Lines 127-156 of the vulnerable file.

	segment, err := findSegment(t, id)
	if err != nil {
		return 0, nil, syserror.EINVAL
	}

	switch cmd {
	case linux.IPC_SET:
		var ds linux.ShmidDS
		_, err = t.CopyIn(buf, &ds)
		if err != nil {
			return 0, nil, err
		}
		err = segment.Set(t, &ds)
		return 0, nil, err

	case linux.IPC_RMID:
		segment.MarkDestroyed()
		return 0, nil, nil

	case linux.SHM_LOCK, linux.SHM_UNLOCK:
		// We currently do not support memmory locking anywhere.
		// mlock(2)/munlock(2) are currently stubbed out as no-ops so do the
		// same here.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, nil

	default:
		return 0, nil, syserror.EINVAL
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
 		return 0, nil, nil
 
 	case linux.SHM_LOCK, linux.SHM_UNLOCK:
-		// We currently do not support memmory locking anywhere.
+		// We currently do not support memory locking anywhere.
 		// mlock(2)/munlock(2) are currently stubbed out as no-ops so do the
 		// same here.
 		t.Kernel().EmitUnimplementedEvent(t)
```
