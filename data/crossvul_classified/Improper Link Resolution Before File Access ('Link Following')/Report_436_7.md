# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_7
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_7`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 1117-1157 of the vulnerable file.

}

#ifdef _WITH_DUMP_THREADS_
void
dump_threads(void)
{
	FILE *fp;
	char time_buf[26];
	element e;
	vrrp_t *vrrp;
	char *file_name;

	file_name = make_file_name("/tmp/thread_dump.dat",
					"vrrp",
#if HAVE_DECL_CLONE_NEWNET
					global_data->network_namespace,
#else
					NULL,
#endif
					global_data->instance_name);
	fp = fopen(file_name, "a");
	FREE(file_name);

	set_time_now();
	ctime_r(&time_now.tv_sec, time_buf);

	fprintf(fp, "\n%.19s.%6.6ld: Thread dump\n", time_buf, time_now.tv_usec);

	dump_thread_data(master, fp);

	fprintf(fp, "alloc = %lu\n", master->alloc);

	fprintf(fp, "\n");
	LIST_FOREACH(vrrp_data->vrrp, vrrp, e) {
		ctime_r(&vrrp->sands.tv_sec, time_buf);
		fprintf(fp, "VRRP instance %s, sands %.19s.%6.6lu, status %s\n", vrrp->iname, time_buf, vrrp->sands.tv_usec,
				vrrp->state == VRRP_STATE_INIT ? "INIT" :
				vrrp->state == VRRP_STATE_BACK ? "BACKUP" :
				vrrp->state == VRRP_STATE_MAST ? "MASTER" :
				vrrp->state == VRRP_STATE_FAULT ? "FAULT" :
				vrrp->state == VRRP_STATE_STOP ? "STOP" :
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1134,7 +1134,7 @@
 					NULL,
 #endif
 					global_data->instance_name);
-	fp = fopen(file_name, "a");
+	fp = fopen_safe(file_name, "a");
 	FREE(file_name);
 
 	set_time_now();
```
