# CrossVul Fix Pair: Improper Privilege Management in cpp
**Pair ID:** 1350_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1350_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```cpp
Lines 575-616 of the vulnerable file.

    auto old_physical_address = pte.physical_page_base();
#endif
    pte.set_physical_page_base(0);
    pte.set_present(false);
    pte.set_writable(false);
    flush_tlb(page_vaddr);
#ifdef MM_DEBUG
    dbg() << "MM: >> unquickmap_page " << page_vaddr << " =/> " << old_physical_address;
#endif
    m_quickmap_in_use = false;
}

bool MemoryManager::validate_user_stack(const Process& process, VirtualAddress vaddr) const
{
    auto* region = region_from_vaddr(process, vaddr);
    return region && region->is_stack();
}

bool MemoryManager::validate_user_read(const Process& process, VirtualAddress vaddr) const
{
    auto* region = region_from_vaddr(process, vaddr);
    return region && region->is_readable();
}

bool MemoryManager::validate_user_write(const Process& process, VirtualAddress vaddr) const
{
    auto* region = region_from_vaddr(process, vaddr);
    return region && region->is_writable();
}

void MemoryManager::register_vmobject(VMObject& vmobject)
{
    InterruptDisabler disabler;
    m_vmobjects.append(&vmobject);
}

void MemoryManager::unregister_vmobject(VMObject& vmobject)
{
    InterruptDisabler disabler;
    m_vmobjects.remove(&vmobject);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -592,14 +592,14 @@
 
 bool MemoryManager::validate_user_read(const Process& process, VirtualAddress vaddr) const
 {
-    auto* region = region_from_vaddr(process, vaddr);
-    return region && region->is_readable();
+    auto* region = user_region_from_vaddr(const_cast<Process&>(process), vaddr);
+    return region && region->is_user_accessible() && region->is_readable();
 }
 
 bool MemoryManager::validate_user_write(const Process& process, VirtualAddress vaddr) const
 {
-    auto* region = region_from_vaddr(process, vaddr);
-    return region && region->is_writable();
+    auto* region = user_region_from_vaddr(const_cast<Process&>(process), vaddr);
+    return region && region->is_user_accessible() && region->is_writable();
 }
 
 void MemoryManager::register_vmobject(VMObject& vmobject)
```
