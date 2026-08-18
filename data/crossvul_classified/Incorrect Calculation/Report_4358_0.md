# CrossVul Fix Pair: Incorrect Calculation in go
**Pair ID:** 4358_0
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4358_0`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```go
Lines 287-328 of the vulnerable file.

	header.Len *= 4
	header.Cap *= 4
	dataset := *(*[]byte)(unsafe.Pointer(&header))

	// Generate the dataset on many goroutines since it takes a while
	threads := runtime.NumCPU()
	size := uint64(len(dataset))

	var pend sync.WaitGroup
	pend.Add(threads)

	var progress uint64
	for i := 0; i < threads; i++ {
		go func(id int) {
			defer pend.Done()

			// Create a hasher to reuse between invocations
			keccak512 := makeHasher(sha3.NewLegacyKeccak512())

			// Calculate the data segment this thread should generate
			batch := uint32((size + hashBytes*uint64(threads) - 1) / (hashBytes * uint64(threads)))
			first := uint32(id) * batch
			limit := first + batch
			if limit > uint32(size/hashBytes) {
				limit = uint32(size / hashBytes)
			}
			// Calculate the dataset segment
			percent := size / hashBytes / 100
			for index := first; index < limit; index++ {
				item := generateDatasetItem(cache, index, keccak512)
				if swapped {
					swap(item)
				}
				copy(dataset[index*hashBytes:], item)

				if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
					logger.Info("Generating DAG in progress", "percentage", (status*100)/(size/hashBytes), "elapsed", common.PrettyDuration(time.Since(start)))
				}
			}
		}(i)
	}
	// Wait for all the generators to finish and return
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,16 +304,16 @@
 			keccak512 := makeHasher(sha3.NewLegacyKeccak512())
 
 			// Calculate the data segment this thread should generate
-			batch := uint32((size + hashBytes*uint64(threads) - 1) / (hashBytes * uint64(threads)))
-			first := uint32(id) * batch
+			batch := (size + hashBytes*uint64(threads) - 1) / (hashBytes * uint64(threads))
+			first := uint64(id) * batch
 			limit := first + batch
-			if limit > uint32(size/hashBytes) {
-				limit = uint32(size / hashBytes)
+			if limit > size/hashBytes {
+				limit = size / hashBytes
 			}
 			// Calculate the dataset segment
 			percent := size / hashBytes / 100
 			for index := first; index < limit; index++ {
-				item := generateDatasetItem(cache, index, keccak512)
+				item := generateDatasetItem(cache, uint32(index), keccak512)
 				if swapped {
 					swap(item)
 				}
```
