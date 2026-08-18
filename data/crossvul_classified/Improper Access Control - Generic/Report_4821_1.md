# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4821_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4821_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 502-542 of the vulnerable file.

}

static void timer_enter_running(Timer *t) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(t);

        /* Don't start job if we are supposed to go down */
        if (unit_stop_pending(UNIT(t)))
                return;

        r = manager_add_job(UNIT(t)->manager, JOB_START, UNIT_TRIGGER(UNIT(t)),
                            JOB_REPLACE, true, &error, NULL);
        if (r < 0)
                goto fail;

        dual_timestamp_get(&t->last_trigger);

        if (t->stamp_path)
                touch_file(t->stamp_path, true, t->last_trigger.realtime, UID_INVALID, GID_INVALID, 0);

        timer_set_state(t, TIMER_RUNNING);
        return;

fail:
        log_unit_warning(UNIT(t), "Failed to queue unit startup job: %s", bus_error_message(&error, r));
        timer_enter_dead(t, TIMER_FAILURE_RESOURCES);
}

static int timer_start(Unit *u) {
        Timer *t = TIMER(u);
        TimerValue *v;

        assert(t);
        assert(t->state == TIMER_DEAD || t->state == TIMER_FAILED);

        if (UNIT_TRIGGER(u)->load_state != UNIT_LOADED)
                return -ENOENT;

        t->last_trigger = DUAL_TIMESTAMP_NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -519,7 +519,7 @@
         dual_timestamp_get(&t->last_trigger);
 
         if (t->stamp_path)
-                touch_file(t->stamp_path, true, t->last_trigger.realtime, UID_INVALID, GID_INVALID, 0);
+                touch_file(t->stamp_path, true, t->last_trigger.realtime, UID_INVALID, GID_INVALID, MODE_INVALID);
 
         timer_set_state(t, TIMER_RUNNING);
         return;
@@ -555,7 +555,7 @@
                         /* The timer has never run before,
                          * make sure a stamp file exists.
                          */
-                        touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
+                        touch_file(t->stamp_path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
         }
 
         t->result = TIMER_SUCCESS;
```
