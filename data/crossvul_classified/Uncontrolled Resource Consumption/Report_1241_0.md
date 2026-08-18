# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1241_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1241_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 110-150 of the vulnerable file.

	}
	result = i2400m_msg_check_status(wimax_msg_data(ack_skb),
					 strerr, sizeof(strerr));
	if (result < 0) {
		dev_err(dev, "'RF Control' (0x%04x) command failed: %d - %s\n",
			I2400M_MT_CMD_RF_CONTROL, result, strerr);
		goto error_cmd;
	}

	/* Now we wait for the state to change to RADIO_OFF or RADIO_ON */
	result = wait_event_timeout(
		i2400m->state_wq, i2400m_radio_is(i2400m, state),
		5 * HZ);
	if (result == 0)
		result = -ETIMEDOUT;
	if (result < 0)
		dev_err(dev, "Error waiting for device to toggle RF state: "
			"%d\n", result);
	result = 0;
error_cmd:
	kfree(cmd);
	kfree_skb(ack_skb);
error_msg_to_dev:
error_alloc:
	d_fnend(4, dev, "(wimax_dev %p state %d) = %d\n",
		wimax_dev, state, result);
	return result;
}


/*
 * Inform the WiMAX stack of changes in the RF Kill switches reported
 * by the device
 *
 * @i2400m: device descriptor
 * @rfss: TLV for RF Switches status; already validated
 *
 * NOTE: the reports on RF switch status cannot be trusted
 *       or used until the device is in a state of RADIO_OFF
 *       or greater.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,12 +127,12 @@
 			"%d\n", result);
 	result = 0;
 error_cmd:
-	kfree(cmd);
 	kfree_skb(ack_skb);
 error_msg_to_dev:
 error_alloc:
 	d_fnend(4, dev, "(wimax_dev %p state %d) = %d\n",
 		wimax_dev, state, result);
+	kfree(cmd);
 	return result;
 }
 
```
