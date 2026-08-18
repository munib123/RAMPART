# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5419_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5419_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.


	int *Data() { return (int *)(this+1); }
	int Type() { return m_TypeAndID>>16; }
	int ID() { return m_TypeAndID&0xffff; }
	int Key() { return m_TypeAndID; }
};


class CSnapshot
{
	friend class CSnapshotBuilder;
	int m_DataSize;
	int m_NumItems;

	int *Offsets() const { return (int *)(this+1); }
	char *DataStart() const { return (char*)(Offsets()+m_NumItems); }

public:
	enum
	{
		MAX_SIZE=64*1024
	};

	void Clear() { m_DataSize = 0; m_NumItems = 0; }
	int NumItems() const { return m_NumItems; }
	CSnapshotItem *GetItem(int Index);
	int GetItemSize(int Index);
	int GetItemIndex(int Key);

	int Crc();
	void DebugDump();
};


// CSnapshotDelta

class CSnapshotDelta
{
public:
	class CData
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,8 @@
 public:
 	enum
 	{
-		MAX_SIZE=64*1024
+		MAX_PARTS	= 64,
+		MAX_SIZE	= MAX_PARTS*1024
 	};
 
 	void Clear() { m_DataSize = 0; m_NumItems = 0; }
```
