# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1268_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1268_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 418-458 of the vulnerable file.

		}

		usb_fill_bulk_urb(urb,
				  ar_usb->udev,
				  pipe->usb_pipe_handle,
				  skb->data,
				  skb->len,
				  ath10k_usb_transmit_complete, urb_context);

		if (!(skb->len % pipe->max_packet_size)) {
			/* hit a max packet boundary on this pipe */
			urb->transfer_flags |= URB_ZERO_PACKET;
		}

		usb_anchor_urb(urb, &pipe->urb_submitted);
		ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret) {
			ath10k_dbg(ar, ATH10K_DBG_USB_BULK,
				   "usb bulk transmit failed: %d\n", ret);
			usb_unanchor_urb(urb);
			ret = -EINVAL;
			goto err_free_urb_to_pipe;
		}

		usb_free_urb(urb);
	}

	return 0;

err_free_urb_to_pipe:
	ath10k_usb_free_urb_to_pipe(urb_context->pipe, urb_context);
err:
	return ret;
}

static void ath10k_usb_hif_stop(struct ath10k *ar)
{
	ath10k_usb_flush_all(ar);
}

static u16 ath10k_usb_hif_get_free_queue_number(struct ath10k *ar, u8 pipe_id)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -435,6 +435,7 @@
 			ath10k_dbg(ar, ATH10K_DBG_USB_BULK,
 				   "usb bulk transmit failed: %d\n", ret);
 			usb_unanchor_urb(urb);
+			usb_free_urb(urb);
 			ret = -EINVAL;
 			goto err_free_urb_to_pipe;
 		}
```
