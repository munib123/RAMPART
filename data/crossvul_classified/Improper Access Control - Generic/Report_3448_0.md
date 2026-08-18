# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3448_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3448_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 828-868 of the vulnerable file.

	{
		printk(KERN_WARNING "FM Error: Patch record too short\n");
		return -EINVAL;
	}

	if (copy_from_user(&ins, addr, sizeof(ins)))
		return -EFAULT;

	if (ins.channel < 0 || ins.channel >= SBFM_MAXINSTR)
	{
		printk(KERN_WARNING "FM Error: Invalid instrument number %d\n", ins.channel);
		return -EINVAL;
	}
	ins.key = format;

	return store_instr(ins.channel, &ins);
}

static void opl3_panning(int dev, int voice, int value)
{
	devc->voc[voice].panning = value;
}

static void opl3_volume_method(int dev, int mode)
{
}

#define SET_VIBRATO(cell) { \
	tmp = instr->operators[(cell-1)+(((cell-1)/2)*OFFS_4OP)]; \
	if (pressure > 110) \
		tmp |= 0x40;		/* Vibrato on */ \
	opl3_command (map->ioaddr, AM_VIB + map->op[cell-1], tmp);}

static void opl3_aftertouch(int dev, int voice, int pressure)
{
	int tmp;
	struct sbi_instrument *instr;
	struct physical_voice_info *map;

	if (voice < 0 || voice >= devc->nr_voice)
		return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -845,6 +845,10 @@
 
 static void opl3_panning(int dev, int voice, int value)
 {
+
+	if (voice < 0 || voice >= devc->nr_voice)
+		return;
+
 	devc->voc[voice].panning = value;
 }
 
@@ -1062,8 +1066,15 @@
 
 static void opl3_setup_voice(int dev, int voice, int chn)
 {
-	struct channel_info *info =
-	&synth_devs[dev]->chn_info[chn];
+	struct channel_info *info;
+
+	if (voice < 0 || voice >= devc->nr_voice)
+		return;
+
+	if (chn < 0 || chn > 15)
+		return;
+
+	info = &synth_devs[dev]->chn_info[chn];
 
 	opl3_set_instr(dev, voice, info->pgm_num);
 
```
