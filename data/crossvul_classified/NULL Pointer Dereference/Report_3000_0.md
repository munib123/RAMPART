# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3000_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3000_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 419-459 of the vulnerable file.

	i8042_ctr |= irq_bit;
	if (i8042_command(&i8042_ctr, I8042_CMD_CTL_WCTR))
		pr_err("Can't reactivate %s port\n", port_name);

	/*
	 * See if there is any data appeared while we were messing with
	 * port state.
	 */
	i8042_interrupt(0, NULL);
}

/*
 * i8042_start() is called by serio core when port is about to finish
 * registering. It will mark port as existing so i8042_interrupt can
 * start sending data through it.
 */
static int i8042_start(struct serio *serio)
{
	struct i8042_port *port = serio->port_data;

	port->exists = true;
	mb();
	return 0;
}

/*
 * i8042_stop() marks serio port as non-existing so i8042_interrupt
 * will not try to send data to the port that is about to go away.
 * The function is called by serio core as part of unregister procedure.
 */
static void i8042_stop(struct serio *serio)
{
	struct i8042_port *port = serio->port_data;

	port->exists = false;

	/*
	 * We synchronize with both AUX and KBD IRQs because there is
	 * a (very unlikely) chance that AUX IRQ is raised for KBD port
	 * and vice versa.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -436,8 +436,10 @@
 {
 	struct i8042_port *port = serio->port_data;
 
+	spin_lock_irq(&i8042_lock);
 	port->exists = true;
-	mb();
+	spin_unlock_irq(&i8042_lock);
+
 	return 0;
 }
 
@@ -450,16 +452,20 @@
 {
 	struct i8042_port *port = serio->port_data;
 
+	spin_lock_irq(&i8042_lock);
 	port->exists = false;
+	port->serio = NULL;
+	spin_unlock_irq(&i8042_lock);
 
 	/*
+	 * We need to make sure that interrupt handler finishes using
+	 * our serio port before we return from this function.
 	 * We synchronize with both AUX and KBD IRQs because there is
 	 * a (very unlikely) chance that AUX IRQ is raised for KBD port
 	 * and vice versa.
 	 */
 	synchronize_irq(I8042_AUX_IRQ);
 	synchronize_irq(I8042_KBD_IRQ);
-	port->serio = NULL;
 }
 
 /*
@@ -576,7 +582,7 @@
 
 	spin_unlock_irqrestore(&i8042_lock, flags);
 
-	if (likely(port->exists && !filtered))
+	if (likely(serio && !filtered))
 		serio_interrupt(serio, data, dfl);
 
  out:
```
