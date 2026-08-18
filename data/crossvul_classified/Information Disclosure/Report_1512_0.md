# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1512_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1512_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 109-149 of the vulnerable file.

	m_q.BERDecode(seq);
	m_u.BERDecode(seq);
	seq.MessageEnd();
}

void InvertibleRWFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_n.DEREncode(seq);
	m_p.DEREncode(seq);
	m_q.DEREncode(seq);
	m_u.DEREncode(seq);
	seq.MessageEnd();
}

Integer InvertibleRWFunction::CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const
{
	DoQuickSanityCheck();
	ModularArithmetic modn(m_n);
	Integer r, rInv;
	do {	// do this in a loop for people using small numbers for testing
		r.Randomize(rng, Integer::One(), m_n - Integer::One());
		rInv = modn.MultiplicativeInverse(r);
	} while (rInv.IsZero());
	Integer re = modn.Square(r);
	re = modn.Multiply(re, x);			// blind

	Integer cp=re%m_p, cq=re%m_q;
	if (Jacobi(cp, m_p) * Jacobi(cq, m_q) != 1)
	{
		cp = cp.IsOdd() ? (cp+m_p) >> 1 : cp >> 1;
		cq = cq.IsOdd() ? (cq+m_q) >> 1 : cq >> 1;
	}

	#pragma omp parallel
		#pragma omp sections
		{
			#pragma omp section
				cp = ModularSquareRoot(cp, m_p);
			#pragma omp section
				cq = ModularSquareRoot(cq, m_q);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -126,10 +126,16 @@
 	DoQuickSanityCheck();
 	ModularArithmetic modn(m_n);
 	Integer r, rInv;
-	do {	// do this in a loop for people using small numbers for testing
+
+	// do this in a loop for people using small numbers for testing
+	do {
 		r.Randomize(rng, Integer::One(), m_n - Integer::One());
+		// Fix for CVE-2015-2141. Thanks to Evgeny Sidorov for reporting.
+		// Squaring to satisfy Jacobi requirements suggested by JPM.
+		r = modn.Square(r);
 		rInv = modn.MultiplicativeInverse(r);
 	} while (rInv.IsZero());
+
 	Integer re = modn.Square(r);
 	re = modn.Multiply(re, x);			// blind
 
```
