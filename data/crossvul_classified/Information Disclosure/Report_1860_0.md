# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1860_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1860_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 400-440 of the vulnerable file.


void tty_ldisc_flush(struct tty_struct *tty)
{
	struct tty_ldisc *ld = tty_ldisc_ref(tty);

	tty_buffer_flush(tty, ld);
	if (ld)
		tty_ldisc_deref(ld);
}
EXPORT_SYMBOL_GPL(tty_ldisc_flush);

/**
 *	tty_set_termios_ldisc		-	set ldisc field
 *	@tty: tty structure
 *	@num: line discipline number
 *
 *	This is probably overkill for real world processors but
 *	they are not on hot paths so a little discipline won't do
 *	any harm.
 *
 *	Locking: takes termios_rwsem
 */

static void tty_set_termios_ldisc(struct tty_struct *tty, int num)
{
	down_write(&tty->termios_rwsem);
	tty->termios.c_line = num;
	up_write(&tty->termios_rwsem);
}

/**
 *	tty_ldisc_open		-	open a line discipline
 *	@tty: tty we are opening the ldisc on
 *	@ld: discipline to open
 *
 *	A helper opening method. Also a convenient debugging and check
 *	point.
 *
 *	Locking: always called with BTM already held.
 */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -417,6 +417,10 @@
  *	they are not on hot paths so a little discipline won't do
  *	any harm.
  *
+ *	The line discipline-related tty_struct fields are reset to
+ *	prevent the ldisc driver from re-using stale information for
+ *	the new ldisc instance.
+ *
  *	Locking: takes termios_rwsem
  */
 
@@ -425,6 +429,9 @@
 	down_write(&tty->termios_rwsem);
 	tty->termios.c_line = num;
 	up_write(&tty->termios_rwsem);
+
+	tty->disc_data = NULL;
+	tty->receive_room = 0;
 }
 
 /**
```
