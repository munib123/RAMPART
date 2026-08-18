# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 3035_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3035_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 2319-2359 of the vulnerable file.

		dev_dbg(dev, "%s - INBOUND XON/XOFF is enabled, XON = %2x, XOFF = %2x\n",
			__func__, config->cXon, config->cXoff);
	} else
		dev_dbg(dev, "%s - INBOUND XON/XOFF is disabled\n", __func__);

	/* if we are implementing OUTBOUND XON/XOFF */
	if (I_IXON(tty)) {
		config->wFlags |= UMP_MASK_UART_FLAGS_OUT_X;
		dev_dbg(dev, "%s - OUTBOUND XON/XOFF is enabled, XON = %2x, XOFF = %2x\n",
			__func__, config->cXon, config->cXoff);
	} else
		dev_dbg(dev, "%s - OUTBOUND XON/XOFF is disabled\n", __func__);

	tty->termios.c_cflag &= ~CMSPAR;

	/* Round the baud rate */
	baud = tty_get_baud_rate(tty);
	if (!baud) {
		/* pick a default, any default... */
		baud = 9600;
	} else
		tty_encode_baud_rate(tty, baud, baud);

	edge_port->baud_rate = baud;
	config->wBaudRate = (__u16)((461550L + baud/2) / baud);

	/* FIXME: Recompute actual baud from divisor here */

	dev_dbg(dev, "%s - baud rate = %d, wBaudRate = %d\n", __func__, baud, config->wBaudRate);

	dev_dbg(dev, "wBaudRate:   %d\n", (int)(461550L / config->wBaudRate));
	dev_dbg(dev, "wFlags:    0x%x\n", config->wFlags);
	dev_dbg(dev, "bDataBits:   %d\n", config->bDataBits);
	dev_dbg(dev, "bParity:     %d\n", config->bParity);
	dev_dbg(dev, "bStopBits:   %d\n", config->bStopBits);
	dev_dbg(dev, "cXon:        %d\n", config->cXon);
	dev_dbg(dev, "cXoff:       %d\n", config->cXoff);
	dev_dbg(dev, "bUartMode:   %d\n", config->bUartMode);

	/* move the word values into big endian mode */
	cpu_to_be16s(&config->wFlags);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2336,8 +2336,11 @@
 	if (!baud) {
 		/* pick a default, any default... */
 		baud = 9600;
-	} else
+	} else {
+		/* Avoid a zero divisor. */
+		baud = min(baud, 461550);
 		tty_encode_baud_rate(tty, baud, baud);
+	}
 
 	edge_port->baud_rate = baud;
 	config->wBaudRate = (__u16)((461550L + baud/2) / baud);
```
