# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 394_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `394_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 337-377 of the vulnerable file.

			else if (posMapping[k] >= input->length)
				typebuf_temp[k] = typebuf[input->length - 1];  // append to previous
			else
				typebuf_temp[k] = typebuf[posMapping[k]];
		memcpy(typebuf, typebuf_temp, output->length * sizeof(formtype));
		free(typebuf_temp);
	}

failure:
	*realInlen = pos;
	if (input->bufferIndex != origInput->bufferIndex)
		releaseStringBuffer(input->bufferIndex);
	return 1;
}

static int
matchCurrentInput(
		const InString *input, int pos, const widechar *passInstructions, int passIC) {
	int k;
	int kk = pos;
	for (k = passIC + 2; k < passIC + 2 + passInstructions[passIC + 1]; k++)
		if (input->chars[kk] == ENDSEGMENT || passInstructions[k] != input->chars[kk++])
			return 0;
	return 1;
}

static int
swapTest(int swapIC, int *pos, const TranslationTableHeader *table, const InString *input,
		const widechar *passInstructions) {
	int p = *pos;
	TranslationTableOffset swapRuleOffset;
	TranslationTableRule *swapRule;
	swapRuleOffset = (passInstructions[swapIC + 1] << 16) | passInstructions[swapIC + 2];
	swapRule = (TranslationTableRule *)&table->ruleArea[swapRuleOffset];
	while (p - *pos < passInstructions[swapIC + 3]) {
		int test;
		if (swapRule->opcode == CTO_SwapDd) {
			for (test = 1; test < swapRule->charslen; test += 2) {
				if (input->chars[p] == swapRule->charsdots[test]) break;
			}
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -354,7 +354,9 @@
 		const InString *input, int pos, const widechar *passInstructions, int passIC) {
 	int k;
 	int kk = pos;
-	for (k = passIC + 2; k < passIC + 2 + passInstructions[passIC + 1]; k++)
+	for (k = passIC + 2;
+			((k < passIC + 2 + passInstructions[passIC + 1]) && (kk < input->length));
+			k++)
 		if (input->chars[kk] == ENDSEGMENT || passInstructions[k] != input->chars[kk++])
 			return 0;
 	return 1;
```
