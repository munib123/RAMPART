# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_9
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_9`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 126-166 of the vulnerable file.


enum rpcrdma_errcode {
	ERR_VERS = 1,
	ERR_CHUNK = 2
};

enum rpcrdma_proc {
	RDMA_MSG = 0,		/* An RPC call or reply msg */
	RDMA_NOMSG = 1,		/* An RPC call or reply msg - separate body */
	RDMA_MSGP = 2,		/* An RPC call or reply msg with padding */
	RDMA_DONE = 3,		/* Client signals reply completion */
	RDMA_ERROR = 4		/* An RPC RDMA encoding error */
};

#define rdma_msg	cpu_to_be32(RDMA_MSG)
#define rdma_nomsg	cpu_to_be32(RDMA_NOMSG)
#define rdma_msgp	cpu_to_be32(RDMA_MSGP)
#define rdma_done	cpu_to_be32(RDMA_DONE)
#define rdma_error	cpu_to_be32(RDMA_ERROR)

/*
 * Private extension to RPC-over-RDMA Version One.
 * Message passed during RDMA-CM connection set-up.
 *
 * Add new fields at the end, and don't permute existing
 * fields.
 */
struct rpcrdma_connect_private {
	__be32			cp_magic;
	u8			cp_version;
	u8			cp_flags;
	u8			cp_send_size;
	u8			cp_recv_size;
} __packed;

#define rpcrdma_cmp_magic	__cpu_to_be32(0xf6ab0e18)

enum {
	RPCRDMA_CMP_VERSION		= 1,
	RPCRDMA_CMP_F_SND_W_INV_OK	= BIT(0),
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,6 +143,9 @@
 #define rdma_done	cpu_to_be32(RDMA_DONE)
 #define rdma_error	cpu_to_be32(RDMA_ERROR)
 
+#define err_vers	cpu_to_be32(ERR_VERS)
+#define err_chunk	cpu_to_be32(ERR_CHUNK)
+
 /*
  * Private extension to RPC-over-RDMA Version One.
  * Message passed during RDMA-CM connection set-up.
```
