# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4074_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4074_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 169-209 of the vulnerable file.

    if (getstr(ubridge_config, bridge_name, "pcap_filter", &pcap_filter)) {
        printf("Applying PCAP filter '%s'\n", pcap_filter);
        if (bridge->source_nio->type == NIO_TYPE_ETHERNET) {
            if (set_pcap_filter(bridge->source_nio->dptr, pcap_filter) < 0)
               fprintf(stderr, "unable to apply filter to source NIO\n");
        }
        else if (bridge->destination_nio->type == NIO_TYPE_ETHERNET) {
            if (set_pcap_filter(bridge->destination_nio->dptr, pcap_filter) < 0)
               fprintf(stderr, "unable to apply filter to destination NIO\n");
        }
    }
}

int parse_config(char *filename, bridge_t **bridges)
{
    dictionary *ubridge_config = NULL;
    const char *value;
    const char *bridge_name;
    int i, nsec;

    if ((ubridge_config = iniparser_load(filename)) == NULL) {
       return FALSE;
    }

    nsec = iniparser_getnsec(ubridge_config);
    for (i = 0; i < nsec; i++) {
        bridge_t *bridge;
        nio_t *source_nio = NULL;
        nio_t *destination_nio = NULL;

        bridge_name = iniparser_getsecname(ubridge_config, i);
        printf("Parsing %s\n", bridge_name);
        if (getstr(ubridge_config, bridge_name, "source_udp", &value))
           source_nio = create_udp_tunnel(value);
        else if (getstr(ubridge_config, bridge_name, "source_unix", &value))
           source_nio = create_unix_socket(value);
        else if (getstr(ubridge_config, bridge_name, "source_ethernet", &value))
           source_nio = open_ethernet_device(value);
        else if (getstr(ubridge_config, bridge_name, "source_tap", &value))
           source_nio = open_tap_device(value);
#ifdef LINUX_RAW
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,7 +186,7 @@
     const char *bridge_name;
     int i, nsec;
 
-    if ((ubridge_config = iniparser_load(filename)) == NULL) {
+    if ((ubridge_config = iniparser_load(filename, HIDE_ERRORED_LINE_CONTENT)) == NULL) {
        return FALSE;
     }
 
```
