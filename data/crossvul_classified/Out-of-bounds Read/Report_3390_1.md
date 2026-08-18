# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 3390_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3390_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 535-575 of the vulnerable file.

					if (m_literal > 285)
						throw BadBlockErr();
					unsigned int bits;
		case LENGTH_BITS:
					bits = lengthExtraBits[m_literal-257];
					if (!m_reader.FillBuffer(bits))
					{
						m_nextDecode = LENGTH_BITS;
						break;
					}
					m_literal = m_reader.GetBits(bits) + lengthStarts[m_literal-257];
		case DISTANCE:
					if (!distanceDecoder.Decode(m_reader, m_distance))
					{
						m_nextDecode = DISTANCE;
						break;
					}
		case DISTANCE_BITS:
					// TODO: this surfaced during fuzzing. What do we do???
					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceExtraBits));
					bits = (m_distance >= COUNTOF(distanceExtraBits)) ? distanceExtraBits[29] : distanceExtraBits[m_distance];
					if (!m_reader.FillBuffer(bits))
					{
						m_nextDecode = DISTANCE_BITS;
						break;
					}
					m_distance = m_reader.GetBits(bits) + distanceStarts[m_distance];
					OutputPast(m_literal, m_distance);
				}
			}
			break;
		default:
			CRYPTOPP_ASSERT(0);
		}
	}
	if (blockEnd)
	{
		if (m_eof)
		{
			FlushOutput();
			m_reader.SkipBits(m_reader.BitsBuffered()%8);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -552,12 +552,18 @@
 		case DISTANCE_BITS:
 					// TODO: this surfaced during fuzzing. What do we do???
 					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceExtraBits));
-					bits = (m_distance >= COUNTOF(distanceExtraBits)) ? distanceExtraBits[29] : distanceExtraBits[m_distance];
+					if (m_distance >= COUNTOF(distanceExtraBits))
+						throw BadDistanceErr();
+					bits = distanceExtraBits[m_distance];
 					if (!m_reader.FillBuffer(bits))
 					{
 						m_nextDecode = DISTANCE_BITS;
 						break;
 					}
+					// TODO: this surfaced during fuzzing. What do we do???
+					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceStarts));
+					if (m_distance >= COUNTOF(distanceStarts))
+						throw BadDistanceErr();
 					m_distance = m_reader.GetBits(bits) + distanceStarts[m_distance];
 					OutputPast(m_literal, m_distance);
 				}
```
