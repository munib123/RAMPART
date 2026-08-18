# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 676_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `676_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 243-283 of the vulnerable file.

	sftag = get_from(msg)->tag_value;
	trim(&sftag);

	chid = get_hash1_raw(msg->callid->body.s, msg->callid->body.len);
	slotid = chid & (_tmx_ptran_size-1);

	if(unlikely(_tmx_proc_ptran == NULL)) {
		_tmx_proc_ptran = (pretran_t*)shm_malloc(sizeof(pretran_t));
		if(_tmx_proc_ptran == NULL) {
			LM_ERR("not enough memory for pretran structure\n");
			return -1;
		}
		memset(_tmx_proc_ptran, 0, sizeof(pretran_t));
		_tmx_proc_ptran->pid = my_pid();
	}
	dsize = scallid.len + scseqnum.len + scseqmet.len
		+ sftag.len + 4;
	if(likely(vbr!=NULL)) {
		svbranch = vbr->value;
		trim(&svbranch);
		dsize += svbranch.len;
	}
	if(dsize<256) dsize = 256;

	tmx_pretran_unlink();

	if(dsize > _tmx_proc_ptran->dbuf.len) {
		if(_tmx_proc_ptran->dbuf.s) shm_free(_tmx_proc_ptran->dbuf.s);
		_tmx_proc_ptran->dbuf.s = (char*)shm_malloc(dsize);
		if(_tmx_proc_ptran->dbuf.s==NULL) {
			LM_ERR("not enough memory for pretran data\n");
			return -1;
		}
		_tmx_proc_ptran->dbuf.len = dsize;
	}
	_tmx_proc_ptran->hid = chid;
	_tmx_proc_ptran->cseqmetid = (get_cseq(msg))->method_id;

	_tmx_proc_ptran->callid.s = _tmx_proc_ptran->dbuf.s;
	memcpy(_tmx_proc_ptran->callid.s, scallid.s, scallid.len);
	_tmx_proc_ptran->callid.len = scallid.len;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,7 +260,7 @@
 	if(likely(vbr!=NULL)) {
 		svbranch = vbr->value;
 		trim(&svbranch);
-		dsize += svbranch.len;
+		dsize += svbranch.len + 1;
 	}
 	if(dsize<256) dsize = 256;
 
```
