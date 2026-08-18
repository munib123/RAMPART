# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3339_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3339_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 372-412 of the vulnerable file.

	/* Calculate the new read position */
	new_grp = curr_grp + bytes_to_read;
	if (new_grp > bus->m_dwSizeGetRing) {

		/* Ring wraps */
		new_grp -= bus->m_dwSizeGetRing;
		space_rem = bus->m_dwSizeGetRing - curr_grp;

		memcpy_fromio(&msg_tmp, bus->m_pdwGetRing + curr_grp, space_rem);
		memcpy_fromio((u8 *)&msg_tmp + space_rem, bus->m_pdwGetRing,
			bytes_to_read - space_rem);

	} else {
		/* No wrapping */
		memcpy_fromio(&msg_tmp, bus->m_pdwGetRing + curr_grp, bytes_to_read);
	}
	/* Convert from little endian to CPU */
	msg_tmp.size = le16_to_cpu((__force __le16)msg_tmp.size);
	msg_tmp.command = le32_to_cpu((__force __le32)msg_tmp.command);
	msg_tmp.controlselector = le16_to_cpu((__force __le16)msg_tmp.controlselector);

	/* No need to update the read positions, because this was a peek */
	/* If the caller specifically want to peek, return */
	if (peekonly) {
		memcpy(msg, &msg_tmp, sizeof(*msg));
		goto peekout;
	}

	/* Check if the command/response matches what is expected */
	if ((msg_tmp.id != msg->id) || (msg_tmp.command != msg->command) ||
		(msg_tmp.controlselector != msg->controlselector) ||
		(msg_tmp.seqno != msg->seqno) || (msg_tmp.size != msg->size)) {

		printk(KERN_ERR "%s() Unexpected msg miss-match\n", __func__);
		saa7164_bus_dumpmsg(dev, msg, buf);
		saa7164_bus_dumpmsg(dev, &msg_tmp, NULL);
		ret = SAA_ERR_INVALID_COMMAND;
		goto out;
	}

	/* Get the actual command and response from the bus */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,11 +389,11 @@
 	msg_tmp.size = le16_to_cpu((__force __le16)msg_tmp.size);
 	msg_tmp.command = le32_to_cpu((__force __le32)msg_tmp.command);
 	msg_tmp.controlselector = le16_to_cpu((__force __le16)msg_tmp.controlselector);
+	memcpy(msg, &msg_tmp, sizeof(*msg));
 
 	/* No need to update the read positions, because this was a peek */
 	/* If the caller specifically want to peek, return */
 	if (peekonly) {
-		memcpy(msg, &msg_tmp, sizeof(*msg));
 		goto peekout;
 	}
 
@@ -438,21 +438,15 @@
 		space_rem = bus->m_dwSizeGetRing - curr_grp;
 
 		if (space_rem < sizeof(*msg)) {
-			/* msg wraps around the ring */
-			memcpy_fromio(msg, bus->m_pdwGetRing + curr_grp, space_rem);
-			memcpy_fromio((u8 *)msg + space_rem, bus->m_pdwGetRing,
-				sizeof(*msg) - space_rem);
 			if (buf)
 				memcpy_fromio(buf, bus->m_pdwGetRing + sizeof(*msg) -
 					space_rem, buf_size);
 
 		} else if (space_rem == sizeof(*msg)) {
-			memcpy_fromio(msg, bus->m_pdwGetRing + curr_grp, sizeof(*msg));
 			if (buf)
 				memcpy_fromio(buf, bus->m_pdwGetRing, buf_size);
 		} else {
 			/* Additional data wraps around the ring */
-			memcpy_fromio(msg, bus->m_pdwGetRing + curr_grp, sizeof(*msg));
 			if (buf) {
 				memcpy_fromio(buf, bus->m_pdwGetRing + curr_grp +
 					sizeof(*msg), space_rem - sizeof(*msg));
@@ -465,15 +459,10 @@
 
 	} else {
 		/* No wrapping */
-		memcpy_fromio(msg, bus->m_pdwGetRing + curr_grp, sizeof(*msg));
 		if (buf)
 			memcpy_fromio(buf, bus->m_pdwGetRing + curr_grp + sizeof(*msg),
 				buf_size);
 	}
-	/* Convert from little endian to CPU */
-	msg->size = le16_to_cpu((__force __le16)msg->size);
-	msg->command = le32_to_cpu((__force __le32)msg->command);
-	msg->controlselector = le16_to_cpu((__force __le16)msg->controlselector);
 
 	/* Update the read positions, adjusting the ring */
 	saa7164_writel(bus->m_dwGetReadPos, new_grp);
```
