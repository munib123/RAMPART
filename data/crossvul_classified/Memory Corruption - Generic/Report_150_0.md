# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 150_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `150_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 171-211 of the vulnerable file.

	cgc.cmd[7] = ti->cdti_trk1;
	cgc.cmd[8] = ti->cdti_ind1;
	cgc.data_direction = DMA_NONE;

	result = sr_do_ioctl(cd, &cgc);
	if (result == -EDRIVE_CANT_DO_THIS)
		result = sr_fake_playtrkind(cdi, ti);

	return result;
}

/* We do our own retries because we want to know what the specific
   error code is.  Normally the UNIT_ATTENTION code will automatically
   clear after one error */

int sr_do_ioctl(Scsi_CD *cd, struct packet_command *cgc)
{
	struct scsi_device *SDev;
	struct scsi_sense_hdr sshdr;
	int result, err = 0, retries = 0;

	SDev = cd->device;

      retry:
	if (!scsi_block_when_processing_errors(SDev)) {
		err = -ENODEV;
		goto out;
	}

	result = scsi_execute(SDev, cgc->cmd, cgc->data_direction,
			      cgc->buffer, cgc->buflen,
			      (unsigned char *)cgc->sense, &sshdr,
			      cgc->timeout, IOCTL_RETRIES, 0, 0, NULL);

	/* Minimal error checking.  Ignore cases we know about, and report the rest. */
	if (driver_byte(result) != 0) {
		switch (sshdr.sense_key) {
		case UNIT_ATTENTION:
			SDev->changed = 1;
			if (!cgc->quiet)
				sr_printk(KERN_INFO, cd,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,8 +188,12 @@
 	struct scsi_device *SDev;
 	struct scsi_sense_hdr sshdr;
 	int result, err = 0, retries = 0;
+	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE], *senseptr = NULL;
 
 	SDev = cd->device;
+
+	if (cgc->sense)
+		senseptr = sense_buffer;
 
       retry:
 	if (!scsi_block_when_processing_errors(SDev)) {
@@ -198,9 +202,11 @@
 	}
 
 	result = scsi_execute(SDev, cgc->cmd, cgc->data_direction,
-			      cgc->buffer, cgc->buflen,
-			      (unsigned char *)cgc->sense, &sshdr,
+			      cgc->buffer, cgc->buflen, senseptr, &sshdr,
 			      cgc->timeout, IOCTL_RETRIES, 0, 0, NULL);
+
+	if (cgc->sense)
+		memcpy(cgc->sense, sense_buffer, sizeof(*cgc->sense));
 
 	/* Minimal error checking.  Ignore cases we know about, and report the rest. */
 	if (driver_byte(result) != 0) {
```
