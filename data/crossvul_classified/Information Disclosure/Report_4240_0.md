# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4240_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4240_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1260-1300 of the vulnerable file.

	unsigned long		now = jiffies;
	cycles_t		cycles = random_get_entropy();
	__u32			c_high, j_high;
	__u64			ip;
	unsigned long		seed;
	int			credit = 0;

	if (cycles == 0)
		cycles = get_reg(fast_pool, regs);
	c_high = (sizeof(cycles) > 4) ? cycles >> 32 : 0;
	j_high = (sizeof(now) > 4) ? now >> 32 : 0;
	fast_pool->pool[0] ^= cycles ^ j_high ^ irq;
	fast_pool->pool[1] ^= now ^ c_high;
	ip = regs ? instruction_pointer(regs) : _RET_IP_;
	fast_pool->pool[2] ^= ip;
	fast_pool->pool[3] ^= (sizeof(ip) > 4) ? ip >> 32 :
		get_reg(fast_pool, regs);

	fast_mix(fast_pool);
	add_interrupt_bench(cycles);

	if (unlikely(crng_init == 0)) {
		if ((fast_pool->count >= 64) &&
		    crng_fast_load((char *) fast_pool->pool,
				   sizeof(fast_pool->pool))) {
			fast_pool->count = 0;
			fast_pool->last = now;
		}
		return;
	}

	if ((fast_pool->count < 64) &&
	    !time_after(now, fast_pool->last + HZ))
		return;

	r = &input_pool;
	if (!spin_trylock(&r->lock))
		return;

	fast_pool->last = now;
	__mix_pool_bytes(r, &fast_pool->pool, sizeof(fast_pool->pool));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1277,6 +1277,7 @@
 
 	fast_mix(fast_pool);
 	add_interrupt_bench(cycles);
+	this_cpu_add(net_rand_state.s1, fast_pool->pool[cycles & 3]);
 
 	if (unlikely(crng_init == 0)) {
 		if ((fast_pool->count >= 64) &&
```
