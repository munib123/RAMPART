# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 899_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `899_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 96-136 of the vulnerable file.

			input->bufbits = 8-number;
			ret += input->buffer >> (8-number);
			input->buffer &= (1<<input->bufbits)-1;
		}

		return ret;
	}

	ret = input->buffer >> (input->bufbits-number);
	input->bufbits -= number;
	input->buffer &= (1<<input->bufbits)-1;
//	printf("done: readBits(%i) numer < bufbits %i\n", number, ret);
	return ret;
}

int 
SWFInput_readSBits(SWFInput input, int number)
{
	int num = SWFInput_readBits(input, number);

	if ( num & (1<<(number-1)) )
		return num - (1<<number);
	else
		return num;
}

int
SWFInput_getChar(SWFInput input)
{
	return input->getChar(input);
}


int
SWFInput_getUInt16(SWFInput input)
{
	int num = SWFInput_getChar(input);
	num += SWFInput_getChar(input) << 8;
	return num;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,7 +113,7 @@
 {
 	int num = SWFInput_readBits(input, number);
 
-	if ( num & (1<<(number-1)) )
+	if(number && num & (1<<(number-1)))
 		return num - (1<<number);
 	else
 		return num;
```
