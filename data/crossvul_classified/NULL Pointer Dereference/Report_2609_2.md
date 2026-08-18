# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 2609_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2609_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 537-577 of the vulnerable file.

            cursors[index].m_Locator.m_TrakIndex   = index;
            cursors[index].m_Locator.m_SampleTable = new AP4_AtomSampleTable(stbl, *trak_data_stream);
            cursors[index].m_Locator.m_SampleIndex = 0;
            cursors[index].m_Locator.m_ChunkIndex  = 0;
            if (cursors[index].m_Locator.m_SampleTable->GetSampleCount()) {
                cursors[index].m_Locator.m_SampleTable->GetSample(0, cursors[index].m_Locator.m_Sample);
            } else {
                cursors[index].m_EndReached = true;
            }

            index++;            
        }

        // figure out the layout of the chunks
        for (;;) {
            // see which is the next sample to write
            AP4_UI64 min_offset = (AP4_UI64)(-1);
            int cursor = -1;
            for (unsigned int i=0; i<track_count; i++) {
                if (!cursors[i].m_EndReached &&
                    cursors[i].m_Locator.m_Sample.GetOffset() <= min_offset) {
                    min_offset = cursors[i].m_Locator.m_Sample.GetOffset();
                    cursor = i;
                }
            }

            // stop if all cursors are exhausted
            if (cursor == -1) break;

            // append this locator to the layout list
            AP4_SampleLocator& locator = cursors[cursor].m_Locator;
            locators.Append(locator);

            // move the cursor to the next sample
            locator.m_SampleIndex++;
            if (locator.m_SampleIndex == locator.m_SampleTable->GetSampleCount()) {
                // mark this track as completed
                cursors[cursor].m_EndReached = true;
            } else {
                // get the next sample info
                locator.m_SampleTable->GetSample(locator.m_SampleIndex, locator.m_Sample);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -554,6 +554,7 @@
             int cursor = -1;
             for (unsigned int i=0; i<track_count; i++) {
                 if (!cursors[i].m_EndReached &&
+                    cursors[i].m_Locator.m_SampleTable &&
                     cursors[i].m_Locator.m_Sample.GetOffset() <= min_offset) {
                     min_offset = cursors[i].m_Locator.m_Sample.GetOffset();
                     cursor = i;
```
