# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_8
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_8`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 147-187 of the vulnerable file.

/* rdp5.c */
void process_ts_fp_updates(STREAM s);
/* rdp.c */
void rdp_in_unistr(STREAM s, int in_len, char **string, uint32 * str_size);
void rdp_send_input(uint32 time, uint16 message_type, uint16 device_flags, uint16 param1,
		    uint16 param2);
void rdp_send_suppress_output_pdu(enum RDP_SUPPRESS_STATUS allowupdates);
void process_colour_pointer_pdu(STREAM s);
void process_new_pointer_pdu(STREAM s);
void process_cached_pointer_pdu(STREAM s);
void process_system_pointer_pdu(STREAM s);
void set_system_pointer(uint32 ptr);
void process_bitmap_updates(STREAM s);
void process_palette(STREAM s);
void rdp_main_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
RD_BOOL rdp_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
RD_BOOL rdp_connect(char *server, uint32 flags, char *domain, char *password, char *command,
		    char *directory, RD_BOOL reconnect);
void rdp_reset_state(void);
void rdp_disconnect(void);
/* rdpdr.c */
int get_device_index(RD_NTHANDLE handle);
void convert_to_unix_filename(char *filename);
void rdpdr_send_completion(uint32 device, uint32 id, uint32 status, uint32 result, uint8 * buffer,
			   uint32 length);
RD_BOOL rdpdr_init();
void rdpdr_add_fds(int *n, fd_set * rfds, fd_set * wfds, struct timeval *tv, RD_BOOL * timeout);
struct async_iorequest *rdpdr_remove_iorequest(struct async_iorequest *prev,
					       struct async_iorequest *iorq);
void rdpdr_check_fds(fd_set * rfds, fd_set * wfds, RD_BOOL timed_out);
RD_BOOL rdpdr_abort_io(uint32 fd, uint32 major, RD_NTSTATUS status);
/* rdpsnd.c */
void rdpsnd_record(const void *data, unsigned int size);
RD_BOOL rdpsnd_init(char *optarg);
void rdpsnd_show_help(void);
void rdpsnd_add_fds(int *n, fd_set * rfds, fd_set * wfds, struct timeval *tv);
void rdpsnd_check_fds(fd_set * rfds, fd_set * wfds);
struct audio_packet *rdpsnd_queue_current_packet(void);
RD_BOOL rdpsnd_queue_empty(void);
void rdpsnd_queue_next(unsigned long completed_in_us);
int rdpsnd_queue_next_tick(void);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,6 +164,7 @@
 		    char *directory, RD_BOOL reconnect);
 void rdp_reset_state(void);
 void rdp_disconnect(void);
+void rdp_protocol_error(const char *message, STREAM s);
 /* rdpdr.c */
 int get_device_index(RD_NTHANDLE handle);
 void convert_to_unix_filename(char *filename);
@@ -224,7 +225,7 @@
 /* asn.c */
 RD_BOOL ber_in_header(STREAM s, int *tagval, int *length);
 void ber_out_header(STREAM s, int tagval, int length);
-RD_BOOL ber_parse_header(STREAM s, int tagval, int *length);
+RD_BOOL ber_parse_header(STREAM s, int tagval, uint32 *length);
 void ber_out_integer(STREAM s, int value);
 void ber_out_sequence(STREAM s, STREAM contents);
 
```
