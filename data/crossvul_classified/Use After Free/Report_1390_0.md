# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1390_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1390_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 160-200 of the vulnerable file.

            comps_hslist_destroy(&rtdata->data);
            rtdata->subnodes = ((COMPS_MRTreeData*)it->data)->subnodes;
            rtdata->data = new_data_list;
            comps_hslist_append(new_subnodes, rtdata, 0);

            comps_hslist_append(to_clone, rtdata, 0);
        }
        ((COMPS_MRTreeData*)it2->data)->subnodes = new_subnodes;
        free(it2);
    }
    comps_hslist_destroy(&to_clone);
    return ret;
}

void comps_mrtree_unite(COMPS_MRTree *rt1, COMPS_MRTree *rt2) {
    COMPS_HSList *tmplist, *tmp_subnodes;
    COMPS_HSListItem *it, *it2;
    struct Pair {
        COMPS_HSList * subnodes;
        char * key;
        char added;
    } *pair, *parent_pair;

    pair = malloc(sizeof(struct Pair));
    pair->subnodes = rt2->subnodes;
    pair->key = NULL;

    tmplist = comps_hslist_create();
    comps_hslist_init(tmplist, NULL, NULL, &free);
    comps_hslist_append(tmplist, pair, 0);

    while (tmplist->first != NULL) {
        it = tmplist->first;
        comps_hslist_remove(tmplist, tmplist->first);
        tmp_subnodes = ((struct Pair*)it->data)->subnodes;
        parent_pair = (struct Pair*) it->data;
        free(it);

        pair->added = 0;
        for (it = tmp_subnodes->first; it != NULL; it=it->next) {
            pair = malloc(sizeof(struct Pair));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,6 @@
     struct Pair {
         COMPS_HSList * subnodes;
         char * key;
-        char added;
     } *pair, *parent_pair;
 
     pair = malloc(sizeof(struct Pair));
@@ -195,7 +194,6 @@
         parent_pair = (struct Pair*) it->data;
         free(it);
 
-        pair->added = 0;
         for (it = tmp_subnodes->first; it != NULL; it=it->next) {
             pair = malloc(sizeof(struct Pair));
             pair->subnodes = ((COMPS_MRTreeData*)it->data)->subnodes;
```
