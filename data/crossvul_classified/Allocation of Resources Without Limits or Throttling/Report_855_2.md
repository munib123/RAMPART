# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in go
**Pair ID:** 855_2
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `855_2`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```go
Lines 395-435 of the vulnerable file.

// Doesn't actually consume any wire data, just removes the last field for
// this struct from the field stack.
func (p *CompactProtocol) ReadStructEnd() error {
	// consume the last field we read off the wire.
	p.lastFieldIDRead = p.lastFieldRead[len(p.lastFieldRead)-1]
	p.lastFieldRead = p.lastFieldRead[:len(p.lastFieldRead)-1]
	return nil
}

// Read a field header off the wire.
func (p *CompactProtocol) ReadFieldBegin() (name string, typeId Type, id int16, err error) {
	t, err := p.readByteDirect()
	if err != nil {
		return
	}

	// if it's a stop, then we can return immediately, as the struct is over.
	if (t & 0x0f) == STOP {
		return "", STOP, 0, nil
	}

	// mask off the 4 MSB of the type header. it could contain a field id delta.
	modifier := int16((t & 0xf0) >> 4)
	if modifier == 0 {
		// not a delta. look ahead for the zigzag varint field id.
		id, err = p.ReadI16()
		if err != nil {
			return
		}
	} else {
		// has a delta. add the delta to the last read field id.
		id = int16(p.lastFieldIDRead) + modifier
	}
	typeId, e := p.getType(compactType(t & 0x0f))
	if e != nil {
		err = NewProtocolException(e)
		return
	}

	// if this happens to be a boolean field, the value is encoded in the type
	if p.isBoolType(t) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -412,7 +412,6 @@
 	if (t & 0x0f) == STOP {
 		return "", STOP, 0, nil
 	}
-
 	// mask off the 4 MSB of the type header. it could contain a field id delta.
 	modifier := int16((t & 0xf0) >> 4)
 	if modifier == 0 {
@@ -458,6 +457,10 @@
 		err = invalidDataLength
 		return
 	}
+	if uint64(size32*2) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
+		err = invalidDataLength
+		return
+	}
 	size = int(size32)
 
 	keyAndValueType := byte(STOP)
@@ -496,6 +499,11 @@
 		}
 		size = int(size2)
 	}
+	if uint64(size) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
+		err = invalidDataLength
+		return
+	}
+
 	elemType, e := p.getType(compactType(size_and_type))
 	if e != nil {
 		err = NewProtocolException(e)
@@ -596,7 +604,7 @@
 	if length < 0 {
 		return "", invalidDataLength
 	}
-	if uint64(length) > p.trans.RemainingBytes() {
+	if uint64(length) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
 		return "", invalidDataLength
 	}
 
@@ -625,7 +633,7 @@
 	if length < 0 {
 		return nil, invalidDataLength
 	}
-	if uint64(length) > p.trans.RemainingBytes() {
+	if uint64(length) > p.trans.RemainingBytes() || p.trans.RemainingBytes() == UnknownRemaining {
 		return nil, invalidDataLength
 	}
 
```
