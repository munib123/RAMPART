# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5759_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5759_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1943-1983 of the vulnerable file.

		if (IoBuffer.InputLength != sizeof(unsigned long)) {
			Status = -EINVAL;
			break;
		}

		Status = copy_from_user(&RxCntrlMsgBitMask, IoBuffer.InputBuffer, IoBuffer.InputLength);
		if (Status) {
			BCM_DEBUG_PRINT(Adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "copy of control bit mask failed from user space");
			return -EFAULT;
		}
		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "\n Got user defined cntrl msg bit mask :%lx", RxCntrlMsgBitMask);
		pTarang->RxCntrlMsgBitMask = RxCntrlMsgBitMask;
	}
	break;

	case IOCTL_BCM_GET_DEVICE_DRIVER_INFO: {
		struct bcm_driver_info DevInfo;

		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "Called IOCTL_BCM_GET_DEVICE_DRIVER_INFO\n");

		DevInfo.MaxRDMBufferSize = BUFFER_4K;
		DevInfo.u32DSDStartOffset = EEPROM_CALPARAM_START;
		DevInfo.u32RxAlignmentCorrection = 0;
		DevInfo.u32NVMType = Adapter->eNVMType;
		DevInfo.u32InterfaceType = BCM_USB;

		if (copy_from_user(&IoBuffer, argp, sizeof(struct bcm_ioctl_buffer)))
			return -EFAULT;

		if (IoBuffer.OutputLength < sizeof(DevInfo))
			return -EINVAL;

		if (copy_to_user(IoBuffer.OutputBuffer, &DevInfo, sizeof(DevInfo)))
			return -EFAULT;
	}
	break;

	case IOCTL_BCM_TIME_SINCE_NET_ENTRY: {
		struct bcm_time_elapsed stTimeElapsedSinceNetEntry = {0};

		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "IOCTL_BCM_TIME_SINCE_NET_ENTRY called");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1960,6 +1960,7 @@
 
 		BCM_DEBUG_PRINT(Adapter, DBG_TYPE_OTHERS, OSAL_DBG, DBG_LVL_ALL, "Called IOCTL_BCM_GET_DEVICE_DRIVER_INFO\n");
 
+		memset(&DevInfo, 0, sizeof(DevInfo));
 		DevInfo.MaxRDMBufferSize = BUFFER_4K;
 		DevInfo.u32DSDStartOffset = EEPROM_CALPARAM_START;
 		DevInfo.u32RxAlignmentCorrection = 0;
```
