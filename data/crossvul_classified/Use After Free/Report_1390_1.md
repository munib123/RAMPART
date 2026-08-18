# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1390_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1390_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 268-308 of the vulnerable file.

            rtdata->data = new_data_list;
            comps_hslist_append(new_subnodes, rtdata, 0);

            comps_hslist_append(to_clone, rtdata, 0);
        }
        ((COMPS_ObjMRTreeData*)it2->data)->subnodes = new_subnodes;
        free(it2);
    }
    ret->len = rt->len;
    comps_hslist_destroy(&to_clone);
    return ret;
}

void comps_objmrtree_unite(COMPS_ObjMRTree *rt1, COMPS_ObjMRTree *rt2) {
    COMPS_HSList *tmplist, *tmp_subnodes;
    COMPS_HSListItem *it;
    COMPS_ObjListIt *it2;
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
@@ -285,7 +285,6 @@
     struct Pair {
         COMPS_HSList * subnodes;
         char * key;
-        char added;
     } *pair, *parent_pair;
 
     pair = malloc(sizeof(struct Pair));
@@ -303,7 +302,6 @@
         parent_pair = (struct Pair*) it->data;
         free(it);
 
-        pair->added = 0;
         for (it = tmp_subnodes->first; it != NULL; it=it->next) {
             pair = malloc(sizeof(struct Pair));
             pair->subnodes = ((COMPS_ObjMRTreeData*)it->data)->subnodes;
```
