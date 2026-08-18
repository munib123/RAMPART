# CrossVul Fix Pair: Use After Free in go
**Pair ID:** 446_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `446_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```go
Lines 558-598 of the vulnerable file.

	mode := linux.FileMode(ds.ShmPerm.Mode & 0x1ff)
	s.perms = fs.FilePermsFromMode(mode)

	s.owner.UID = uid
	s.owner.GID = gid

	s.changeTime = ktime.NowFromContext(ctx)
	return nil
}

func (s *Shm) destroy() {
	s.registry.remove(s)
	s.p.Memory().DecRef(s.fr)
}

// MarkDestroyed marks a shm for destruction. The shm is actually destroyed once
// it has no references. See shmctl(IPC_RMID).
func (s *Shm) MarkDestroyed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prevent the segment from being found in the registry.
	s.key = linux.IPC_PRIVATE
	s.pendingDestruction = true
	s.DecRef()
}

// checkOwnership verifies whether a segment may be accessed by ctx as an
// owner. See ipc/util.c:ipcctl_pre_down_nolock() in Linux.
//
// Precondition: Caller must hold s.mu.
func (s *Shm) checkOwnership(ctx context.Context) bool {
	creds := auth.CredentialsFromContext(ctx)
	if s.owner.UID == creds.EffectiveKUID || s.creator.UID == creds.EffectiveKUID {
		return true
	}

	// Tasks with CAP_SYS_ADMIN may bypass ownership checks. Strangely, Linux
	// doesn't use CAP_IPC_OWNER for this despite CAP_IPC_OWNER being documented
	// for use to "override IPC ownership checks".
	return creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, s.registry.userNS)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -575,10 +575,19 @@
 func (s *Shm) MarkDestroyed() {
 	s.mu.Lock()
 	defer s.mu.Unlock()
+
 	// Prevent the segment from being found in the registry.
 	s.key = linux.IPC_PRIVATE
-	s.pendingDestruction = true
-	s.DecRef()
+
+	// Only drop the segment's self-reference once, when destruction is
+	// requested. Otherwise, repeated calls shmctl(IPC_RMID) would force a
+	// segment to be destroyed prematurely, potentially with active maps to the
+	// segment's address range. Remaining references are dropped when the
+	// segment is detached or unmaped.
+	if !s.pendingDestruction {
+		s.pendingDestruction = true
+		s.DecRef()
+	}
 }
 
 // checkOwnership verifies whether a segment may be accessed by ctx as an
```
