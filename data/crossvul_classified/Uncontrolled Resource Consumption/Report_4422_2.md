# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4422_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4422_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 * 2. VIRQs, typically used for timers.  These are per-cpu events.
 * 3. IPIs.
 * 4. PIRQs - Hardware interrupts.
 *
 * Jeremy Fitzhardinge <jeremy@xensource.com>, XenSource Inc, 2007
 */

#define pr_fmt(fmt) "xen:" KBUILD_MODNAME ": " fmt

#include <linux/linkage.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/irqnr.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/cpuhotplug.h>

#ifdef CONFIG_X86
#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/idtentry.h>
#include <asm/irq.h>
#include <asm/io_apic.h>
#include <asm/i8259.h>
#include <asm/xen/pci.h>
#endif
#include <asm/sync_bitops.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>
#include <xen/page.h>

#include <xen/xen.h>
#include <xen/hvm.h>
#include <xen/xen-ops.h>
#include <xen/events.h>
#include <xen/interface/xen.h>
#include <xen/interface/event_channel.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,8 @@
 #include <linux/pci.h>
 #include <linux/spinlock.h>
 #include <linux/cpuhotplug.h>
+#include <linux/atomic.h>
+#include <linux/ktime.h>
 
 #ifdef CONFIG_X86
 #include <asm/desc.h>
@@ -65,6 +67,15 @@
 
 #include "events_internal.h"
 
+#undef MODULE_PARAM_PREFIX
+#define MODULE_PARAM_PREFIX "xen."
+
+static uint __read_mostly event_loop_timeout = 2;
+module_param(event_loop_timeout, uint, 0644);
+
+static uint __read_mostly event_eoi_delay = 10;
+module_param(event_eoi_delay, uint, 0644);
+
 const struct evtchn_ops *evtchn_ops;
 
 /*
@@ -88,6 +99,7 @@
  * irq_mapping_update_lock
  *   evtchn_rwlock
  *     IRQ-desc lock
+ *       percpu eoi_list_lock
  */
 
 static LIST_HEAD(xen_irq_list_head);
@@ -119,6 +131,8 @@
 static struct irq_chip xen_pirq_chip;
 static void enable_dynirq(struct irq_data *data);
 static void disable_dynirq(struct irq_data *data);
+
+static DEFINE_PER_CPU(unsigned int, irq_epoch);
 
 static void clear_evtchn_to_irq_row(unsigned row)
 {
@@ -399,15 +413,118 @@
 }
 EXPORT_SYMBOL_GPL(notify_remote_via_irq);
 
+struct lateeoi_work {
+	struct delayed_work delayed;
+	spinlock_t eoi_list_lock;
+	struct list_head eoi_list;
+};
+
+static DEFINE_PER_CPU(struct lateeoi_work, lateeoi);
+
+static void lateeoi_list_del(struct irq_info *info)
+{
+	struct lateeoi_work *eoi = &per_cpu(lateeoi, info->eoi_cpu);
+	unsigned long flags;
+
+	spin_lock_irqsave(&eoi->eoi_list_lock, flags);
+	list_del_init(&info->eoi_list);
+	spin_unlock_irqrestore(&eoi->eoi_list_lock, flags);
+}
+
+static void lateeoi_list_add(struct irq_info *info)
+{
+	struct lateeoi_work *eoi = &per_cpu(lateeoi, info->eoi_cpu);
+	struct irq_info *elem;
+	u64 now = get_jiffies_64();
+	unsigned long delay;
+	unsigned long flags;
+
+	if (now < info->eoi_time)
+		delay = info->eoi_time - now;
+	else
+		delay = 1;
+
+	spin_lock_irqsave(&eoi->eoi_list_lock, flags);
+
+	if (list_empty(&eoi->eoi_list)) {
+		list_add(&info->eoi_list, &eoi->eoi_list);
+		mod_delayed_work_on(info->eoi_cpu, system_wq,
+				    &eoi->delayed, delay);
+	} else {
+		list_for_each_entry_reverse(elem, &eoi->eoi_list, eoi_list) {
+			if (elem->eoi_time <= info->eoi_time)
+				break;
+		}
+		list_add(&info->eoi_list, &elem->eoi_list);
+	}
+
+	spin_unlock_irqrestore(&eoi->eoi_list_lock, flags);
+}
+
 static void xen_irq_lateeoi_locked(struct irq_info *info)
 {
 	evtchn_port_t evtchn;
+	unsigned int cpu;
 
 	evtchn = info->evtchn;
-	if (!VALID_EVTCHN(evtchn))
+	if (!VALID_EVTCHN(evtchn) || !list_empty(&info->eoi_list))
 		return;
 
+	cpu = info->eoi_cpu;
+	if (info->eoi_time && info->irq_epoch == per_cpu(irq_epoch, cpu)) {
+		lateeoi_list_add(info);
+		return;
+	}
+
+	info->eoi_time = 0;
 	unmask_evtchn(evtchn);
+}
+
+static void xen_irq_lateeoi_worker(struct work_struct *work)
+{
+	struct lateeoi_work *eoi;
+	struct irq_info *info;
+	u64 now = get_jiffies_64();
+	unsigned long flags;
+
+	eoi = container_of(to_delayed_work(work), struct lateeoi_work, delayed);
+
+	read_lock_irqsave(&evtchn_rwlock, flags);
+
+	while (true) {
+		spin_lock(&eoi->eoi_list_lock);
+
+		info = list_first_entry_or_null(&eoi->eoi_list, struct irq_info,
+						eoi_list);
+
+		if (info == NULL || now < info->eoi_time) {
+			spin_unlock(&eoi->eoi_list_lock);
+			break;
+		}
+
+		list_del_init(&info->eoi_list);
+
+		spin_unlock(&eoi->eoi_list_lock);
+
+		info->eoi_time = 0;
+
+		xen_irq_lateeoi_locked(info);
+	}
+
+	if (info)
+		mod_delayed_work_on(info->eoi_cpu, system_wq,
+				    &eoi->delayed, info->eoi_time - now);
+
+	read_unlock_irqrestore(&evtchn_rwlock, flags);
+}
+
+static void xen_cpu_init_eoi(unsigned int cpu)
+{
+	struct lateeoi_work *eoi = &per_cpu(lateeoi, cpu);
+
+	INIT_DELAYED_WORK(&eoi->delayed, xen_irq_lateeoi_worker);
+	spin_lock_init(&eoi->eoi_list_lock);
+	INIT_LIST_HEAD(&eoi->eoi_list);
 }
 
 void xen_irq_lateeoi(unsigned int irq, unsigned int eoi_flags)
@@ -429,6 +546,7 @@
 static void xen_irq_init(unsigned irq)
 {
 	struct irq_info *info;
+
 #ifdef CONFIG_SMP
 	/* By default all event channels notify CPU#0. */
 	cpumask_copy(irq_get_affinity_mask(irq), cpumask_of(0));
@@ -443,6 +561,7 @@
 
 	set_info_for_irq(irq, info);
 
+	INIT_LIST_HEAD(&info->eoi_list);
 	list_add_tail(&info->list, &xen_irq_list_head);
 }
 
@@ -497,6 +616,9 @@
 		return;
 
 	write_lock_irqsave(&evtchn_rwlock, flags);
+
+	if (!list_empty(&info->eoi_list))
+		lateeoi_list_del(info);
 
 	list_del(&info->list);
 
@@ -1358,17 +1480,66 @@
 	notify_remote_via_irq(irq);
 }
 
+struct evtchn_loop_ctrl {
+	ktime_t timeout;
+	unsigned count;
+	bool defer_eoi;
+};
+
+void handle_irq_for_port(evtchn_port_t port, struct evtchn_loop_ctrl *ctrl)
+{
+	int irq;
+	struct irq_info *info;
+
+	irq = get_evtchn_to_irq(port);
+	if (irq == -1)
+		return;
+
+	/*
+	 * Check for timeout every 256 events.
+	 * We are setting the timeout value only after the first 256
+	 * events in order to not hurt the common case of few loop
+	 * iterations. The 256 is basically an arbitrary value.
+	 *
+	 * In case we are hitting the timeout we need to defer all further
+	 * EOIs in order to ensure to leave the event handling loop rather
+	 * sooner than later.
+	 */
+	if (!ctrl->defer_eoi && !(++ctrl->count & 0xff)) {
+		ktime_t kt = ktime_get();
+
+		if (!ctrl->timeout) {
+			kt = ktime_add_ms(kt,
+					  jiffies_to_msecs(event_loop_timeout));
+			ctrl->timeout = kt;
+		} else if (kt > ctrl->timeout) {
+			ctrl->defer_eoi = true;
+		}
+	}
+
+	info = info_for_irq(irq);
+
+	if (ctrl->defer_eoi) {
+		info->eoi_cpu = smp_processor_id();
+		info->irq_epoch = __this_cpu_read(irq_epoch);
+		info->eoi_time = get_jiffies_64() + event_eoi_delay;
+	}
+
+	generic_handle_irq(irq);
+}
+
 static void __xen_evtchn_do_upcall(void)
 {
 	struct vcpu_info *vcpu_info = __this_cpu_read(xen_vcpu);
 	int cpu = smp_processor_id();
+	struct evtchn_loop_ctrl ctrl = { 0 };
 
 	read_lock(&evtchn_rwlock);
 
 	do {
 		vcpu_info->evtchn_upcall_pending = 0;
 
-		xen_evtchn_handle_events(cpu);
+		xen_evtchn_handle_events(cpu, &ctrl);
 
 		BUG_ON(!irqs_disabled());
 
@@ -1377,6 +1548,13 @@
 	} while (vcpu_info->evtchn_upcall_pending);
 
 	read_unlock(&evtchn_rwlock);
+
+	/*
+	 * Increment irq_epoch only now to defer EOIs only for
+	 * xen_irq_lateeoi() invocations occurring from inside the loop
+	 * above.
+	 */
+	__this_cpu_inc(irq_epoch);
 }
 
 void xen_evtchn_do_upcall(struct pt_regs *regs)
@@ -1825,15 +2003,14 @@
 static inline void xen_alloc_callback_vector(void) {}
 #endif
 
-#undef MODULE_PARAM_PREFIX
-#define MODULE_PARAM_PREFIX "xen."
-
 static bool fifo_events = true;
 module_param(fifo_events, bool, 0);
 
 static int xen_evtchn_cpu_prepare(unsigned int cpu)
 {
 	int ret = 0;
+
+	xen_cpu_init_eoi(cpu);
 
 	if (evtchn_ops->percpu_init)
 		ret = evtchn_ops->percpu_init(cpu);
@@ -1860,6 +2037,8 @@
 		ret = xen_evtchn_fifo_init();
 	if (ret < 0)
 		xen_evtchn_2l_init();
+
+	xen_cpu_init_eoi(smp_processor_id());
 
 	cpuhp_setup_state_nocalls(CPUHP_XEN_EVTCHN_PREPARE,
 				  "xen/evtchn:prepare",
```
