#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <msg.h>
#include <scan_dir.h>
#include <vstring.h>
#include <vstream.h>
#include <stringops.h>
#include <htable.h>
#include <mymalloc.h>

#include <mail_queue.h>
#include <mail_open_ok.h>
#include <mail_scan_dir.h>
#include <mail_params.h>
#include <record.h>
#include <rec_type.h>
#include <quote_822_local.h>
#include <bounce_log.h>

#include <postqueue.h>

#define STR(x) vstring_str(x)
static void postqueue_emit_recipient_json(VSTREAM *out, VSTRING *quote_buf,
					          int *rcpt_count, const char *orig_addr,
					          const char *addr, const char *log_class,
					          const char *why)
{
#define QUOTE_JSON(res, src) printable(quote_for_json((res), (src), -1), '?')
    if (*rcpt_count > 0)
	vstream_fprintf(out, ", ");
    vstream_fprintf(out, "{");
    vstream_fprintf(out, "\"orig_address\": \"%s\", ",
		    QUOTE_JSON(quote_buf, orig_addr));
    vstream_fprintf(out, "\"address\": \"%s\"",
		    QUOTE_JSON(quote_buf, addr));
    if (why != 0 && *why != 0)
	vstream_fprintf(out, ", \"%s\": \"%s\"",
			strcmp(log_class, MAIL_QUEUE_DEFER) == 0 ? "delay_reason" :
			strcmp(log_class, MAIL_QUEUE_BOUNCE) == 0 ? "bounce_reason" :
			"other_reason",
			QUOTE_JSON(quote_buf, why));
    vstream_fprintf(out, "}");
    (*rcpt_count)++;
}

static void postqueue_emit_bounce_json(VSTREAM *out, const char *queue_id,
					       VSTRING *quote_buf, int *rcpt_count,
					       HTABLE *dup_filter)
{
    const char *log_names[] = {MAIL_QUEUE_DEFER, MAIL_QUEUE_BOUNCE, 0};
    const char **cpp;
    RCPT_BUF *rcpt_buf = rcpb_create();
    DSN_BUF *dsn_buf = dsb_create();

    for (cpp = log_names; *cpp; cpp++) {
	BOUNCE_LOG *bp;
	RECIPIENT *rcpt = &rcpt_buf->rcpt;
	DSN    *dsn = &dsn_buf->dsn;

	bp = bounce_log_open(*cpp, queue_id, O_RDONLY, 0);
	if (bp == 0)
	    continue;
	while (bounce_log_read(bp, rcpt_buf, dsn_buf) != 0) {
	    if (var_dup_filter_limit == 0 || dup_filter->used < var_dup_filter_limit)
		if (htable_locate(dup_filter, rcpt->address) == 0)
		    htable_enter(dup_filter, rcpt->address, (void *) 0);
	    postqueue_emit_recipient_json(out, quote_buf, rcpt_count,
					  rcpt->orig_addr, rcpt->address,
					  *cpp, dsn->reason);
	}
	if (bounce_log_close(bp))
	    msg_warn("close %s %s: %m", *cpp, queue_id);
    }
    rcpb_free(rcpt_buf);
    dsb_free(dsn_buf);
}

static void postqueue_scan_report_json(VSTREAM *out, const char *queue_name,
					       const char *queue_id, VSTREAM *qfile,
					       long size, time_t mtime, mode_t mode)
{
    VSTRING *buf = vstring_alloc(100);
    VSTRING *printable_quoted_addr = vstring_alloc(100);
    VSTRING *orcpt_buf = vstring_alloc(100);
    VSTRING *queue_q = vstring_alloc(100);
    VSTRING *id_q = vstring_alloc(100);
    VSTRING *sender_q = vstring_alloc(100);
    VSTRING *quote_buf = vstring_alloc(100);
    HTABLE *dup_filter = htable_create(var_dup_filter_limit > 0 ?
				       var_dup_filter_limit : 1);
    int     rec_type;
    char   *start;
    long    msg_size = size;
    time_t  arrival_time = 0;
    int     sender_seen = 0;
    int     msg_size_ok = 0;
    int     rcpt_count = 0;
    const char *have_orcpt = 0;

    while ((rec_type = rec_get(qfile, buf, 0)) > 0) {
	start = STR(buf);
	switch (rec_type) {
	case REC_TYPE_TIME:
	    if (arrival_time == 0)
		arrival_time = atol(start);
	    break;
	case REC_TYPE_SIZE:
	    if (msg_size_ok == 0 && strcmp(queue_name, MAIL_QUEUE_MAILDROP) != 0) {
		msg_size_ok = (start[strspn(start, "0123456789 ")] == 0
			       && (msg_size = atol(start)) >= 0);
		if (msg_size_ok == 0)
		    msg_size = size;
	    }
	    break;
	case REC_TYPE_FROM:
	    if (*start == 0)
		start = var_empty_addr;
	    quote_822_local(printable_quoted_addr, start);
	    printable(STR(printable_quoted_addr), '?');
	    if (sender_seen++ > 0)
		goto cleanup;
	    vstream_fprintf(out, "{");
	    vstream_fprintf(out, "\"queue_name\": \"%s\", ",
			    printable(quote_for_json(queue_q, queue_name, -1), '?'));
	    vstream_fprintf(out, "\"queue_id\": \"%s\", ",
			    printable(quote_for_json(id_q, queue_id, -1), '?'));
	    vstream_fprintf(out, "\"arrival_time\": %ld, ",
			    arrival_time > 0 ? (long) arrival_time : (long) mtime);
	    vstream_fprintf(out, "\"message_size\": %ld, ", msg_size);
	    vstream_fprintf(out, "\"forced_expire\": %s, ",
			    (mode & MAIL_QUEUE_STAT_EXPIRE) != 0 ? "true" : "false");
	    vstream_fprintf(out, "\"sender\": \"%s\", ",
			    printable(quote_for_json(sender_q, STR(printable_quoted_addr), -1), '?'));
	    vstream_fprintf(out, "\"recipients\": [");
	    postqueue_emit_bounce_json(out, queue_id, quote_buf, &rcpt_count, dup_filter);
	    break;
	case REC_TYPE_ORCP:
	    quote_822_local(orcpt_buf, start);
	    have_orcpt = printable(STR(orcpt_buf), '?');
	    break;
	case REC_TYPE_RCPT:
	    if (sender_seen == 0)
		goto cleanup;
	    if (*start == 0)
		start = var_empty_addr;
	    quote_822_local(printable_quoted_addr, start);
	    printable(STR(printable_quoted_addr), '?');
	    if (have_orcpt == 0)
		have_orcpt = STR(vstring_strcpy(orcpt_buf, STR(printable_quoted_addr)));
	    if (htable_locate(dup_filter, STR(printable_quoted_addr)) == 0)
		postqueue_emit_recipient_json(out, quote_buf, &rcpt_count,
					      have_orcpt, STR(printable_quoted_addr),
					      "", "");
	    have_orcpt = 0;
	    break;
	case REC_TYPE_MESG:
	    if (msg_size_ok && vstream_fseek(qfile, msg_size, SEEK_CUR) < 0)
		goto cleanup;
	    break;
	case REC_TYPE_END:
	    break;
	default:
	    break;
	}
    }
    if (sender_seen > 0) {
	vstream_fprintf(out, "]}\n");
	if (vstream_fflush(out) && errno != EPIPE)
	    msg_warn("output write error: %m");
    }
cleanup:
    if (dup_filter)
	htable_free(dup_filter, (void (*) (void *)) 0);
    vstring_free(buf);
    vstring_free(printable_quoted_addr);
    vstring_free(orcpt_buf);
    vstring_free(queue_q);
    vstring_free(id_q);
    vstring_free(sender_q);
    vstring_free(quote_buf);
}

int
postqueue_scan_queue_json(VSTREAM *out, const char *queue_name)
{
    SCAN_DIR *scan;
    char   *(*scan_next) (SCAN_DIR *) = 0;
    char   *id;
    char   *saved_id = 0;

    if (strcmp(queue_name, MAIL_QUEUE_MAILDROP) == 0)
	scan_next = scan_dir_next;
    else if (strcmp(queue_name, MAIL_QUEUE_ACTIVE) == 0
	     || strcmp(queue_name, MAIL_QUEUE_INCOMING) == 0
	     || strcmp(queue_name, MAIL_QUEUE_DEFERRED) == 0
	     || strcmp(queue_name, MAIL_QUEUE_HOLD) == 0)
	scan_next = mail_scan_dir_next;
    else
	return (0);

    scan = scan_dir_open(queue_name);
    if (scan == 0)
	return (-1);

    while ((id = scan_next(scan)) != 0) {
	struct stat st;
	const char *path;
	int     status;
	VSTREAM *qfile;

	if (saved_id) {
	    if (strcmp(saved_id, id) == 0) {
		msg_warn("readdir loop on queue %s id %s", queue_name, id);
		break;
	    }
	    myfree(saved_id);
	}
	saved_id = mystrdup(id);
	status = mail_open_ok(queue_name, id, &st, &path);
	(void) path;
	if (status != MAIL_OPEN_YES)
	    continue;
	qfile = mail_queue_open(queue_name, id, O_RDONLY, 0);
	if (qfile == 0) {
	    if (errno != ENOENT)
		msg_warn("open %s %s: %m", queue_name, id);
	    continue;
	}
	postqueue_scan_report_json(out, queue_name, id, qfile,
				   (long) st.st_size, st.st_mtime, st.st_mode);
	if (vstream_fclose(qfile))
	    msg_warn("close file %s %s: %m", queue_name, id);
    }
    if (saved_id)
	myfree(saved_id);
    scan_dir_close(scan);
    return (0);
}
