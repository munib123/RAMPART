# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 965_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `965_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 33-73 of the vulnerable file.

	var rawHdr rawV2
	err = binary.Read(bytes.NewReader(buf), binary.BigEndian, &rawHdr)
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: err}
	}
	if !bytes.Equal(rawHdr.Sig[:], sigV2) {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid signature")}
	}
	// highest 4 indicate version
	if (rawHdr.VerCmd >> 4) != 2 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 version value")}
	}
	var h HeaderV2
	// lowest 4 = command (0xf == 0b00001111)
	h.Command = Cmd(rawHdr.VerCmd & 0xf)
	if h.Command > CmdProxy {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 command")}
	}

	// highest 4 indicate address family
	if (rawHdr.FamProto >> 4) > 3 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 address family")}
	}

	// lowest 4 = transport protocol (0xf == 0b00001111)
	if (rawHdr.FamProto & 0xf) > 2 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 transport protocol")}
	}

	if 16+int(rawHdr.Len) > len(buf) {
		newBuf := make([]byte, 16+int(rawHdr.Len))
		copy(newBuf, buf[:16])
		buf = newBuf
	} else {
		buf = buf[:16+int(rawHdr.Len)]
	}

	n, err = io.ReadFull(r, buf[16:])
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16+n], error: err}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,24 @@
 	}
 
 	// highest 4 indicate address family
-	if (rawHdr.FamProto >> 4) > 3 {
+	switch rawHdr.FamProto >> 4 {
+	case 0: // local
+		if rawHdr.Len != 0 {
+			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
+		}
+	case 1: // ipv4
+		if rawHdr.Len != 12 {
+			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
+		}
+	case 2: // ipv6
+		if rawHdr.Len != 36 {
+			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
+		}
+	case 3: // unix
+		if rawHdr.Len != 216 {
+			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
+		}
+	default:
 		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 address family")}
 	}
 
@@ -59,13 +76,7 @@
 		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 transport protocol")}
 	}
 
-	if 16+int(rawHdr.Len) > len(buf) {
-		newBuf := make([]byte, 16+int(rawHdr.Len))
-		copy(newBuf, buf[:16])
-		buf = newBuf
-	} else {
-		buf = buf[:16+int(rawHdr.Len)]
-	}
+	buf = buf[:16+int(rawHdr.Len)]
 
 	n, err = io.ReadFull(r, buf[16:])
 	if err != nil {
```
