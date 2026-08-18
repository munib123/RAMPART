# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 438_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `438_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 196-229 of the vulnerable file.

	unsigned			vrrp_netlink_cmd_rcv_bufs;
	bool				vrrp_netlink_cmd_rcv_bufs_force;
	unsigned			vrrp_netlink_monitor_rcv_bufs;
	bool				vrrp_netlink_monitor_rcv_bufs_force;
#endif
#ifdef _WITH_LVS_
	unsigned			lvs_netlink_cmd_rcv_bufs;
	bool				lvs_netlink_cmd_rcv_bufs_force;
	unsigned			lvs_netlink_monitor_rcv_bufs;
	bool				lvs_netlink_monitor_rcv_bufs_force;
#endif
#ifdef _WITH_LVS_
	bool				rs_init_notifies;
	bool				no_checker_emails;
#endif
#ifdef _WITH_VRRP_
	int				vrrp_rx_bufs_policy;
	size_t				vrrp_rx_bufs_size;
	int				vrrp_rx_bufs_multiples;
#endif
} data_t;

/* Global vars exported */
extern data_t *global_data;	/* Global configuration data */
extern data_t *old_global_data;	/* Old global configuration data - used during reload */

/* Prototypes */
extern void alloc_email(char *);
extern data_t *alloc_global_data(void);
extern void init_global_data(data_t *, data_t *);
extern void free_global_data(data_t *);
extern void dump_global_data(FILE *, data_t *);

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,6 +213,7 @@
 	size_t				vrrp_rx_bufs_size;
 	int				vrrp_rx_bufs_multiples;
 #endif
+	mode_t				umask;			/* mask for file creation */
 } data_t;
 
 /* Global vars exported */
```
