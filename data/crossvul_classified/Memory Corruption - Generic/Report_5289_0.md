# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5289_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5289_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2371-2411 of the vulnerable file.

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			struct QBUFFER __iomem *prbuffer;
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			prbuffer = arcmsr_get_iop_rqbuffer(acb);
			if (arcmsr_Read_iop_rqbuffer_data(acb, prbuffer) == 0)
				acb->acb_flags |= ACB_F_IOPDATA_OVERFLOW;
		}
		spin_unlock_irqrestore(&acb->rqbuffer_lock, flags);
		kfree(ver_addr);
		pcmdmessagefld->cmdmessage.Length = allxfer_len;
		if (acb->fw_flag == FW_DEADLOCK)
			pcmdmessagefld->cmdmessage.ReturnCode =
				ARCMSR_MESSAGE_RETURNCODE_BUS_HANG_ON;
		else
			pcmdmessagefld->cmdmessage.ReturnCode =
				ARCMSR_MESSAGE_RETURNCODE_OK;
		break;
	}
	case ARCMSR_MESSAGE_WRITE_WQBUFFER: {
		unsigned char *ver_addr;
		int32_t user_len, cnt2end;
		uint8_t *pQbuffer, *ptmpuserbuffer;
		ver_addr = kmalloc(ARCMSR_API_DATA_BUFLEN, GFP_ATOMIC);
		if (!ver_addr) {
			retvalue = ARCMSR_MESSAGE_FAIL;
			goto message_out;
		}
		ptmpuserbuffer = ver_addr;
		user_len = pcmdmessagefld->cmdmessage.Length;
		memcpy(ptmpuserbuffer,
			pcmdmessagefld->messagedatabuffer, user_len);
		spin_lock_irqsave(&acb->wqbuffer_lock, flags);
		if (acb->wqbuf_putIndex != acb->wqbuf_getIndex) {
			struct SENSE_DATA *sensebuffer =
				(struct SENSE_DATA *)cmd->sense_buffer;
			arcmsr_write_ioctldata2iop(acb);
			/* has error report sensedata */
			sensebuffer->ErrorCode = SCSI_SENSE_CURRENT_ERRORS;
			sensebuffer->SenseKey = ILLEGAL_REQUEST;
			sensebuffer->AdditionalSenseLength = 0x0A;
			sensebuffer->AdditionalSenseCode = 0x20;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2388,7 +2388,8 @@
 	}
 	case ARCMSR_MESSAGE_WRITE_WQBUFFER: {
 		unsigned char *ver_addr;
-		int32_t user_len, cnt2end;
+		uint32_t user_len;
+		int32_t cnt2end;
 		uint8_t *pQbuffer, *ptmpuserbuffer;
 		ver_addr = kmalloc(ARCMSR_API_DATA_BUFLEN, GFP_ATOMIC);
 		if (!ver_addr) {
@@ -2397,6 +2398,11 @@
 		}
 		ptmpuserbuffer = ver_addr;
 		user_len = pcmdmessagefld->cmdmessage.Length;
+		if (user_len > ARCMSR_API_DATA_BUFLEN) {
+			retvalue = ARCMSR_MESSAGE_FAIL;
+			kfree(ver_addr);
+			goto message_out;
+		}
 		memcpy(ptmpuserbuffer,
 			pcmdmessagefld->messagedatabuffer, user_len);
 		spin_lock_irqsave(&acb->wqbuffer_lock, flags);
```
