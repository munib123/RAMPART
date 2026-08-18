# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3447_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3447_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 254-294 of the vulnerable file.

};

struct synth_operations 
{
	struct module *owner;
	char *id;	/* Unique identifier (ASCII) max 29 char */
	struct synth_info *info;
	int midi_dev;
	int synth_type;
	int synth_subtype;

	int (*open) (int dev, int mode);
	void (*close) (int dev);
	int (*ioctl) (int dev, unsigned int cmd, void __user * arg);
	int (*kill_note) (int dev, int voice, int note, int velocity);
	int (*start_note) (int dev, int voice, int note, int velocity);
	int (*set_instr) (int dev, int voice, int instr);
	void (*reset) (int dev);
	void (*hw_control) (int dev, unsigned char *event);
	int (*load_patch) (int dev, int format, const char __user *addr,
	     int offs, int count, int pmgr_flag);
	void (*aftertouch) (int dev, int voice, int pressure);
	void (*controller) (int dev, int voice, int ctrl_num, int value);
	void (*panning) (int dev, int voice, int value);
	void (*volume_method) (int dev, int mode);
	void (*bender) (int dev, int chn, int value);
	int (*alloc_voice) (int dev, int chn, int note, struct voice_alloc_info *alloc);
	void (*setup_voice) (int dev, int voice, int chn);
	int (*send_sysex)(int dev, unsigned char *bytes, int len);

 	struct voice_alloc_info alloc;
 	struct channel_info chn_info[16];
	int emulation;
#define	EMU_GM			1	/* General MIDI */
#define	EMU_XG			2	/* Yamaha XG */
#define MAX_SYSEX_BUF	64
	unsigned char sysex_buf[MAX_SYSEX_BUF];
	int sysex_ptr;
};

struct midi_input_info 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -271,7 +271,7 @@
 	void (*reset) (int dev);
 	void (*hw_control) (int dev, unsigned char *event);
 	int (*load_patch) (int dev, int format, const char __user *addr,
-	     int offs, int count, int pmgr_flag);
+	     int count, int pmgr_flag);
 	void (*aftertouch) (int dev, int voice, int pressure);
 	void (*controller) (int dev, int voice, int ctrl_num, int value);
 	void (*panning) (int dev, int voice, int value);
```
