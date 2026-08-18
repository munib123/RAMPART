# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 3345_0
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3345_0`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 1744-1784 of the vulnerable file.

	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dev_dbg(&urb->dev->dev, "%s - urb shutting down with status: %d\n", __func__, status);
		return;
	default:
		dev_err(&urb->dev->dev, "%s - nonzero read bulk status received: %d\n", __func__, status);
	}

	if (status == -EPIPE)
		goto exit;

	if (status) {
		dev_err(&urb->dev->dev, "%s - stopping read!\n", __func__);
		return;
	}

	port_number = edge_port->port->port_number;

	if (edge_port->lsr_event) {
		edge_port->lsr_event = 0;
		dev_dbg(dev, "%s ===== Port %u LSR Status = %02x, Data = %02x ======\n",
			__func__, port_number, edge_port->lsr_mask, *data);
		handle_new_lsr(edge_port, 1, edge_port->lsr_mask, *data);
		/* Adjust buffer length/pointer */
		--urb->actual_length;
		++data;
	}

	if (urb->actual_length) {
		usb_serial_debug_data(dev, __func__, urb->actual_length, data);
		if (edge_port->close_pending)
			dev_dbg(dev, "%s - close pending, dropping data on the floor\n",
								__func__);
		else
			edge_tty_recv(edge_port->port, data,
					urb->actual_length);
		edge_port->port->icount.rx += urb->actual_length;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1761,7 +1761,7 @@
 
 	port_number = edge_port->port->port_number;
 
-	if (edge_port->lsr_event) {
+	if (urb->actual_length > 0 && edge_port->lsr_event) {
 		edge_port->lsr_event = 0;
 		dev_dbg(dev, "%s ===== Port %u LSR Status = %02x, Data = %02x ======\n",
 			__func__, port_number, edge_port->lsr_mask, *data);
```
