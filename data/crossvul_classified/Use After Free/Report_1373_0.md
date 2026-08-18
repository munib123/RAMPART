# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1373_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1373_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1650-1690 of the vulnerable file.


	if (!(status&GF_M2TS_TABLE_UPDATE) && gf_list_count(ts->programs)) {
		if (ts->pat->demux_restarted) {
			ts->pat->demux_restarted = 0;
		} else {
			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Multiple different PAT on single TS found, ignoring new PAT declaration (table id %d - extended table id %d)\n", table_id, ex_table_id));
		}
		return;
	}
	nb_progs = data_size / 4;

	for (i=0; i<nb_progs; i++) {
		u16 number, pid;
		number = (data[0]<<8) | data[1];
		pid = (data[2]&0x1f)<<8 | data[3];
		data += 4;
		if (number==0) {
			if (!ts->nit) {
				ts->nit = gf_m2ts_section_filter_new(gf_m2ts_process_nit, 0);
			}
		} else {
			GF_SAFEALLOC(prog, GF_M2TS_Program);
			if (!prog) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Fail to allocate program for pid %d\n", pid));
				return;
			}
			prog->streams = gf_list_new();
			prog->pmt_pid = pid;
			prog->number = number;
			prog->ts = ts;
			gf_list_add(ts->programs, prog);
			GF_SAFEALLOC(pmt, GF_M2TS_SECTION_ES);
			if (!pmt) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Fail to allocate pmt filter for pid %d\n", pid));
				return;
			}
			pmt->flags = GF_M2TS_ES_IS_SECTION;
			gf_list_add(prog->streams, pmt);
			pmt->pid = prog->pmt_pid;
			pmt->program = prog;
			ts->ess[pmt->pid] = (GF_M2TS_ES *)pmt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1667,7 +1667,9 @@
 			if (!ts->nit) {
 				ts->nit = gf_m2ts_section_filter_new(gf_m2ts_process_nit, 0);
 			}
-		} else {
+		} else if (!pid) {
+			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Broken PAT found reserved PID 0, ignoring\n", pid));
+		} else if (! ts->ess[pid]) {
 			GF_SAFEALLOC(prog, GF_M2TS_Program);
 			if (!prog) {
 				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Fail to allocate program for pid %d\n", pid));
```
