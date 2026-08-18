# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3348_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3348_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 299-339 of the vulnerable file.


    yr_free(page->address);
    yr_free(page);

    page = next_page;
  }

  yr_free(arena);
}


//
// yr_arena_base_address
//
// Returns the base address for the arena.
//
// Args:
//    YR_ARENA* arena  - Pointer to the arena.
//
// Returns:
//    A pointer to the arena's data. NULL if the no data has been written to
//    the arena yet.
//

void* yr_arena_base_address(
  YR_ARENA* arena)
{
  if (arena->page_list_head->used == 0)
    return NULL;

  return arena->page_list_head->address;
}


//
// yr_arena_next_address
//
// Given an address and an offset, returns the address where
// address + offset resides. The arena is a collection of non-contiguous
// regions of memory (pages), if address is pointing at the end of a page,
// address + offset could cross the page boundary and point at somewhere
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -316,7 +316,7 @@
 //    YR_ARENA* arena  - Pointer to the arena.
 //
 // Returns:
-//    A pointer to the arena's data. NULL if the no data has been written to
+//    A pointer to the arena's data. NULL if no data has been written to
 //    the arena yet.
 //
 
```
