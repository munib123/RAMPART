# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5591_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5591_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 512-552 of the vulnerable file.

	if ((*lsr & UMP_UART_LSR_TX_MASK) == 0)
		bytes_left += 1;

	/* We return Not Active if we get any kind of error */
exit_is_tx_active:
	dev_dbg(&port->port->dev, "%s - return %d\n", __func__, bytes_left);

	kfree(lsr);
	kfree(oedb);
	return bytes_left;
}

static void chase_port(struct edgeport_port *port, unsigned long timeout,
								int flush)
{
	int baud_rate;
	struct tty_struct *tty = tty_port_tty_get(&port->port->port);
	struct usb_serial *serial = port->port->serial;
	wait_queue_t wait;
	unsigned long flags;

	if (!timeout)
		timeout = (HZ * EDGE_CLOSING_WAIT)/100;

	/* wait for data to drain from the buffer */
	spin_lock_irqsave(&port->ep_lock, flags);
	init_waitqueue_entry(&wait, current);
	add_wait_queue(&tty->write_wait, &wait);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kfifo_len(&port->write_fifo) == 0
		|| timeout == 0 || signal_pending(current)
		|| serial->disconnected)
			/* disconnect */
			break;
		spin_unlock_irqrestore(&port->ep_lock, flags);
		timeout = schedule_timeout(timeout);
		spin_lock_irqsave(&port->ep_lock, flags);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&tty->write_wait, &wait);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -530,6 +530,9 @@
 	wait_queue_t wait;
 	unsigned long flags;
 
+	if (!tty)
+		return;
+
 	if (!timeout)
 		timeout = (HZ * EDGE_CLOSING_WAIT)/100;
 
```
