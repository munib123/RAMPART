# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 3390_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3390_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 606-646 of the vulnerable file.

		{
			// Miscellaneous for code coverage
			(void)prng.AlgorithmName();  // "unknown"
			word32 result = prng.GenerateWord32();
			result = prng.GenerateWord32((result & 0xff), 0xffffffff - (result & 0xff));
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 4);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 3);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 2);
			prng.GenerateBlock(reinterpret_cast<byte*>(&result), 1);
		}
		catch (const Exception&)
		{
			fail = true;
		}

		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
		std::cout << "  GenerateWord32 and Crop\n";	
	}

#if !defined(NO_OS_DEPENDENCE)
	std::cout << "\nTesting AutoSeeded RandomPool generator...\n\n";
	{
		AutoSeededRandomPool prng;
		static const unsigned int ENTROPY_SIZE = 32;

		MeterFilter meter(new Redirector(TheBitBucket()));
		RandomNumberSource test(prng, 100000, true, new Deflator(new Redirector(meter)));

		fail = false;
		if (meter.GetTotalBytes() < 100000)
			fail = true;

		pass &= !fail;
		if (fail)
			std::cout << "FAILED:";
		else
			std::cout << "passed:";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -623,7 +623,7 @@
 			std::cout << "FAILED:";
 		else
 			std::cout << "passed:";
-		std::cout << "  GenerateWord32 and Crop\n";	
+		std::cout << "  GenerateWord32 and Crop\n";
 	}
 
 #if !defined(NO_OS_DEPENDENCE)
@@ -711,7 +711,7 @@
 			std::cout << "FAILED:";
 		else
 			std::cout << "passed:";
-		std::cout << "  GenerateWord32 and Crop\n";	
+		std::cout << "  GenerateWord32 and Crop\n";
 	}
 #endif
 
@@ -808,7 +808,7 @@
 		std::cout << "FAILED:";
 	else
 		std::cout << "passed:";
-	std::cout << "  GenerateWord32 and Crop\n";	
+	std::cout << "  GenerateWord32 and Crop\n";
 
 	std::cout.flush();
 	return pass;
```
