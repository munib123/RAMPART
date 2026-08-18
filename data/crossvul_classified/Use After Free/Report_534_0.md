# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 534_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `534_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 31-71 of the vulnerable file.

#include <scsi/sas_ata.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_transport_sas.h>
#include "../scsi_sas_internal.h"

static int sas_discover_expander(struct domain_device *dev);
static int sas_configure_routing(struct domain_device *dev, u8 *sas_addr);
static int sas_configure_phy(struct domain_device *dev, int phy_id,
			     u8 *sas_addr, int include);
static int sas_disable_routing(struct domain_device *dev,  u8 *sas_addr);

/* ---------- SMP task management ---------- */

static void smp_task_timedout(struct timer_list *t)
{
	struct sas_task_slow *slow = from_timer(slow, t, timer);
	struct sas_task *task = slow->task;
	unsigned long flags;

	spin_lock_irqsave(&task->task_state_lock, flags);
	if (!(task->task_state_flags & SAS_TASK_STATE_DONE))
		task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	spin_unlock_irqrestore(&task->task_state_lock, flags);

	complete(&task->slow_task->completion);
}

static void smp_task_done(struct sas_task *task)
{
	if (!del_timer(&task->slow_task->timer))
		return;
	complete(&task->slow_task->completion);
}

/* Give it some long enough timeout. In seconds. */
#define SMP_TIMEOUT 10

static int smp_execute_task_sg(struct domain_device *dev,
		struct scatterlist *req, struct scatterlist *resp)
{
	int res, retry;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,17 +48,16 @@
 	unsigned long flags;
 
 	spin_lock_irqsave(&task->task_state_lock, flags);
-	if (!(task->task_state_flags & SAS_TASK_STATE_DONE))
+	if (!(task->task_state_flags & SAS_TASK_STATE_DONE)) {
 		task->task_state_flags |= SAS_TASK_STATE_ABORTED;
+		complete(&task->slow_task->completion);
+	}
 	spin_unlock_irqrestore(&task->task_state_lock, flags);
-
-	complete(&task->slow_task->completion);
 }
 
 static void smp_task_done(struct sas_task *task)
 {
-	if (!del_timer(&task->slow_task->timer))
-		return;
+	del_timer(&task->slow_task->timer);
 	complete(&task->slow_task->completion);
 }
 
```
