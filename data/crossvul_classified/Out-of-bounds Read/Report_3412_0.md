# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3412_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3412_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.


	mpu = substream->rmidi->private_data;
	spin_lock_irqsave(&mpu->input_lock, flags);
	if (up) {
		if (!test_and_set_bit(MSNDMIDI_MODE_BIT_INPUT_TRIGGER,
				      &mpu->mode))
			snd_msndmidi_input_drop(mpu);
	} else {
		clear_bit(MSNDMIDI_MODE_BIT_INPUT_TRIGGER, &mpu->mode);
	}
	spin_unlock_irqrestore(&mpu->input_lock, flags);
	if (up)
		snd_msndmidi_input_read(mpu);
}

void snd_msndmidi_input_read(void *mpuv)
{
	unsigned long flags;
	struct snd_msndmidi *mpu = mpuv;
	void *pwMIDQData = mpu->dev->mappedbase + MIDQ_DATA_BUFF;

	spin_lock_irqsave(&mpu->input_lock, flags);
	while (readw(mpu->dev->MIDQ + JQS_wTail) !=
	       readw(mpu->dev->MIDQ + JQS_wHead)) {
		u16 wTmp, val;
		val = readw(pwMIDQData + 2 * readw(mpu->dev->MIDQ + JQS_wHead));

			if (test_bit(MSNDMIDI_MODE_BIT_INPUT_TRIGGER,
				     &mpu->mode))
				snd_rawmidi_receive(mpu->substream_input,
						    (unsigned char *)&val, 1);

		wTmp = readw(mpu->dev->MIDQ + JQS_wHead) + 1;
		if (wTmp > readw(mpu->dev->MIDQ + JQS_wSize))
			writew(0,  mpu->dev->MIDQ + JQS_wHead);
		else
			writew(wTmp,  mpu->dev->MIDQ + JQS_wHead);
	}
	spin_unlock_irqrestore(&mpu->input_lock, flags);
}
EXPORT_SYMBOL(snd_msndmidi_input_read);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,24 +120,24 @@
 	unsigned long flags;
 	struct snd_msndmidi *mpu = mpuv;
 	void *pwMIDQData = mpu->dev->mappedbase + MIDQ_DATA_BUFF;
+	u16 head, tail, size;
 
 	spin_lock_irqsave(&mpu->input_lock, flags);
-	while (readw(mpu->dev->MIDQ + JQS_wTail) !=
-	       readw(mpu->dev->MIDQ + JQS_wHead)) {
-		u16 wTmp, val;
-		val = readw(pwMIDQData + 2 * readw(mpu->dev->MIDQ + JQS_wHead));
+	head = readw(mpu->dev->MIDQ + JQS_wHead);
+	tail = readw(mpu->dev->MIDQ + JQS_wTail);
+	size = readw(mpu->dev->MIDQ + JQS_wSize);
+	if (head > size || tail > size)
+		goto out;
+	while (head != tail) {
+		unsigned char val = readw(pwMIDQData + 2 * head);
 
-			if (test_bit(MSNDMIDI_MODE_BIT_INPUT_TRIGGER,
-				     &mpu->mode))
-				snd_rawmidi_receive(mpu->substream_input,
-						    (unsigned char *)&val, 1);
-
-		wTmp = readw(mpu->dev->MIDQ + JQS_wHead) + 1;
-		if (wTmp > readw(mpu->dev->MIDQ + JQS_wSize))
-			writew(0,  mpu->dev->MIDQ + JQS_wHead);
-		else
-			writew(wTmp,  mpu->dev->MIDQ + JQS_wHead);
+		if (test_bit(MSNDMIDI_MODE_BIT_INPUT_TRIGGER, &mpu->mode))
+			snd_rawmidi_receive(mpu->substream_input, &val, 1);
+		if (++head > size)
+			head = 0;
+		writew(head, mpu->dev->MIDQ + JQS_wHead);
 	}
+ out:
 	spin_unlock_irqrestore(&mpu->input_lock, flags);
 }
 EXPORT_SYMBOL(snd_msndmidi_input_read);
```
