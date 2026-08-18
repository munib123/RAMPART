# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3390_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3390_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 81-121 of the vulnerable file.

	static code_t NormalizeCode(code_t code, unsigned int codeBits);
	void FillCacheEntry(LookupEntry &entry, code_t normalizedCode) const;

	unsigned int m_maxCodeBits, m_cacheBits, m_cacheMask, m_normalizedCacheMask;
	std::vector<CodeInfo, AllocatorWithCleanup<CodeInfo> > m_codeToValue;
	mutable std::vector<LookupEntry, AllocatorWithCleanup<LookupEntry> > m_cache;
};

//! \class Inflator
//! \brief DEFLATE decompressor (RFC 1951)
//! \since Crypto++ 1.0
class Inflator : public AutoSignaling<Filter>
{
public:
	class Err : public Exception
	{
	public:
		Err(ErrorType e, const std::string &s)
			: Exception(e, s) {}
	};
	class UnexpectedEndErr : public Err {public: UnexpectedEndErr() : Err(INVALID_DATA_FORMAT, "Inflator: unexpected end of compressed block") {}};
	class BadBlockErr : public Err {public: BadBlockErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in compressed block") {}};

	//! \brief RFC 1951 Decompressor
	//! \param attachment the filter's attached transformation
	//! \param repeat decompress multiple compressed streams in series
	//! \param autoSignalPropagation 0 to turn off MessageEnd signal
	Inflator(BufferedTransformation *attachment = NULLPTR, bool repeat = false, int autoSignalPropagation = -1);

	void IsolatedInitialize(const NameValuePairs &parameters);
	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking);
	bool IsolatedFlush(bool hardFlush, bool blocking);

	virtual unsigned int GetLog2WindowSize() const {return 15;}

protected:
	ByteQueue m_inQueue;

private:
	virtual unsigned int MaxPrestreamHeaderSize() const {return 0;}
	virtual void ProcessPrestreamHeader() {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,8 +98,12 @@
 		Err(ErrorType e, const std::string &s)
 			: Exception(e, s) {}
 	};
+	//! \brief Exception thrown when a truncated stream is encountered
 	class UnexpectedEndErr : public Err {public: UnexpectedEndErr() : Err(INVALID_DATA_FORMAT, "Inflator: unexpected end of compressed block") {}};
+	//! \brief Exception thrown when a bad block is encountered
 	class BadBlockErr : public Err {public: BadBlockErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in compressed block") {}};
+	//! \brief Exception thrown when an invalid distance is encountered
+	class BadDistanceErr : public Err {public: BadDistanceErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in bit distance") {}};
 
 	//! \brief RFC 1951 Decompressor
 	//! \param attachment the filter's attached transformation
```
