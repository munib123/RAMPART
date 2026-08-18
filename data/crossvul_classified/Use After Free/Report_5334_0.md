# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5334_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5334_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

free_uid:
			if (who)
				free_uid(user);
			break;
		default:
			ret = -EINVAL;
	}

	rcu_read_unlock();
	return ret;
}

static int get_task_ioprio(struct task_struct *p)
{
	int ret;

	ret = security_task_getioprio(p);
	if (ret)
		goto out;
	ret = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, IOPRIO_NORM);
	if (p->io_context)
		ret = p->io_context->ioprio;
out:
	return ret;
}

int ioprio_best(unsigned short aprio, unsigned short bprio)
{
	unsigned short aclass;
	unsigned short bclass;

	if (!ioprio_valid(aprio))
		aprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
	if (!ioprio_valid(bprio))
		bprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);

	aclass = IOPRIO_PRIO_CLASS(aprio);
	bclass = IOPRIO_PRIO_CLASS(bprio);
	if (aclass == bclass)
		return min(aprio, bprio);
	if (aclass > bclass)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,8 +150,10 @@
 	if (ret)
 		goto out;
 	ret = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, IOPRIO_NORM);
+	task_lock(p);
 	if (p->io_context)
 		ret = p->io_context->ioprio;
+	task_unlock(p);
 out:
 	return ret;
 }
```
