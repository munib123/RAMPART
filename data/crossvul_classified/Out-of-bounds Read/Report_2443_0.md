# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2443_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2443_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 112-152 of the vulnerable file.

    uint32_t size = 0;
    int read_size = 0;
    char *plist_entire = NULL;
    struct stat filestats;
    options_t *options = parse_arguments(argc, argv);

    if (!options)
    {
        print_usage(argc, argv);
        return 0;
    }

    // read input file
    iplist = fopen(options->in_file, "rb");
    if (!iplist) {
        free(options);
        return 1;
    }

    stat(options->in_file, &filestats);
    plist_entire = (char *) malloc(sizeof(char) * (filestats.st_size + 1));
    read_size = fread(plist_entire, sizeof(char), filestats.st_size, iplist);
    fclose(iplist);

    // convert from binary to xml or vice-versa
    if (memcmp(plist_entire, "bplist00", 8) == 0)
    {
        plist_from_bin(plist_entire, read_size, &root_node);
        plist_to_xml(root_node, &plist_out, &size);
    }
    else
    {
        plist_from_xml(plist_entire, read_size, &root_node);
        plist_to_bin(root_node, &plist_out, &size);
    }
    plist_free(root_node);
    free(plist_entire);

    if (plist_out)
    {
        if (options->out_file != NULL)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,6 +129,12 @@
     }
 
     stat(options->in_file, &filestats);
+
+    if (filestats.st_size < 8) {
+        printf("ERROR: Input file is too small to contain valid plist data.\n");
+        return -1;
+    }
+
     plist_entire = (char *) malloc(sizeof(char) * (filestats.st_size + 1));
     read_size = fread(plist_entire, sizeof(char), filestats.st_size, iplist);
     fclose(iplist);
```
