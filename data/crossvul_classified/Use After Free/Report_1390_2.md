# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1390_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1390_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 680-720 of the vulnerable file.

                                       ((COMPS_ObjRTreeData*)hsit->data)->key);
            pair->data = ((COMPS_ObjRTreeData*)hsit->data)->data;
            pair->subnodes = ((COMPS_ObjRTreeData*)hsit->data)->subnodes;
            comps_hslist_insert_at(to_process, x, pair, 0);
        }
        free(current_pair->key);
        free(current_pair);
        free(oldit);
    }

    comps_hslist_destroy(&to_process);
    return ret;
}

void comps_objrtree_unite(COMPS_ObjRTree *rt1, COMPS_ObjRTree *rt2) {
    COMPS_HSList *tmplist, *tmp_subnodes;
    COMPS_HSListItem *it;
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
        //printf("key-part:%s\n", parent_pair->key);
        free(it);

        //pair->added = 0;
        for (it = tmp_subnodes->first; it != NULL; it=it->next) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -697,7 +697,6 @@
     struct Pair {
         COMPS_HSList * subnodes;
         char * key;
-        char added;
     } *pair, *parent_pair;
 
     pair = malloc(sizeof(struct Pair));
@@ -716,7 +715,6 @@
         //printf("key-part:%s\n", parent_pair->key);
         free(it);
 
-        //pair->added = 0;
         for (it = tmp_subnodes->first; it != NULL; it=it->next) {
             pair = malloc(sizeof(struct Pair));
             pair->subnodes = ((COMPS_ObjRTreeData*)it->data)->subnodes;
```
