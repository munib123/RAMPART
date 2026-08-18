# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3412_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3412_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 153-193 of the vulnerable file.

			break;
		}
		break;

	case HIMT_MIDI_IN_UCHAR:
		if (chip->msndmidi_mpu)
			snd_msndmidi_input_read(chip->msndmidi_mpu);
		break;

	default:
		snd_printd(KERN_WARNING LOGNAME ": HIMT message %d 0x%02x\n",
			   HIBYTE(wMessage), HIBYTE(wMessage));
		break;
	}
}

static irqreturn_t snd_msnd_interrupt(int irq, void *dev_id)
{
	struct snd_msnd *chip = dev_id;
	void *pwDSPQData = chip->mappedbase + DSPQ_DATA_BUFF;

	/* Send ack to DSP */
	/* inb(chip->io + HP_RXL); */

	/* Evaluate queued DSP messages */
	while (readw(chip->DSPQ + JQS_wTail) != readw(chip->DSPQ + JQS_wHead)) {
		u16 wTmp;

		snd_msnd_eval_dsp_msg(chip,
			readw(pwDSPQData + 2 * readw(chip->DSPQ + JQS_wHead)));

		wTmp = readw(chip->DSPQ + JQS_wHead) + 1;
		if (wTmp > readw(chip->DSPQ + JQS_wSize))
			writew(0, chip->DSPQ + JQS_wHead);
		else
			writew(wTmp, chip->DSPQ + JQS_wHead);
	}
	/* Send ack to DSP */
	inb(chip->io + HP_RXL);
	return IRQ_HANDLED;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,23 +170,24 @@
 {
 	struct snd_msnd *chip = dev_id;
 	void *pwDSPQData = chip->mappedbase + DSPQ_DATA_BUFF;
+	u16 head, tail, size;
 
 	/* Send ack to DSP */
 	/* inb(chip->io + HP_RXL); */
 
 	/* Evaluate queued DSP messages */
-	while (readw(chip->DSPQ + JQS_wTail) != readw(chip->DSPQ + JQS_wHead)) {
-		u16 wTmp;
-
-		snd_msnd_eval_dsp_msg(chip,
-			readw(pwDSPQData + 2 * readw(chip->DSPQ + JQS_wHead)));
-
-		wTmp = readw(chip->DSPQ + JQS_wHead) + 1;
-		if (wTmp > readw(chip->DSPQ + JQS_wSize))
-			writew(0, chip->DSPQ + JQS_wHead);
-		else
-			writew(wTmp, chip->DSPQ + JQS_wHead);
-	}
+	head = readw(chip->DSPQ + JQS_wHead);
+	tail = readw(chip->DSPQ + JQS_wTail);
+	size = readw(chip->DSPQ + JQS_wSize);
+	if (head > size || tail > size)
+		goto out;
+	while (head != tail) {
+		snd_msnd_eval_dsp_msg(chip, readw(pwDSPQData + 2 * head));
+		if (++head > size)
+			head = 0;
+		writew(head, chip->DSPQ + JQS_wHead);
+	}
+ out:
 	/* Send ack to DSP */
 	inb(chip->io + HP_RXL);
 	return IRQ_HANDLED;
```
