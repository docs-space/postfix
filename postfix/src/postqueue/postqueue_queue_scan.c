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
#include <is_header.h>
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
					       HTABLE *dup_filter,
					       int dup_filter_limit)
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
	    if (dup_filter_limit == 0 || dup_filter->used < dup_filter_limit)
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
					       long size, time_t mtime, mode_t mode,
					       const char *empty_addr,
					       int dup_filter_limit)
{
    VSTRING *buf = vstring_alloc(100);
    VSTRING *printable_quoted_addr = vstring_alloc(100);
    VSTRING *orcpt_buf = vstring_alloc(100);
    VSTRING *queue_q = vstring_alloc(100);
    VSTRING *id_q = vstring_alloc(100);
    VSTRING *sender_q = vstring_alloc(100);
    VSTRING *quote_buf = vstring_alloc(100);
    HTABLE *dup_filter = htable_create(dup_filter_limit > 0 ?
				       dup_filter_limit : 1);
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
		start = (char *) empty_addr;
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
	    postqueue_emit_bounce_json(out, queue_id, quote_buf, &rcpt_count,
				       dup_filter, dup_filter_limit);
	    break;
	case REC_TYPE_ORCP:
	    quote_822_local(orcpt_buf, start);
	    have_orcpt = printable(STR(orcpt_buf), '?');
	    break;
	case REC_TYPE_RCPT:
	    if (sender_seen == 0)
		goto cleanup;
	    if (*start == 0)
		start = (char *) empty_addr;
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

static void postqueue_scan_report_message_json(VSTREAM *out, const char *queue_name,
					       const char *queue_id, VSTREAM *qfile,
					       time_t mtime, const char *empty_addr,
					       int include_envelope,
					       int include_headers, int include_body)
{
    VSTRING *buf = vstring_alloc(100);
    VSTRING *printable_quoted_addr = vstring_alloc(100);
    VSTRING *orcpt_buf = vstring_alloc(100);
    VSTRING *queue_q = vstring_alloc(100);
    VSTRING *id_q = vstring_alloc(100);
    VSTRING *sender_q = vstring_alloc(100);
    VSTRING *quote_buf = vstring_alloc(100);
    VSTRING *recipients_buf = vstring_alloc(256);
    VSTRING *headers_buf = vstring_alloc(256);
    VSTRING *body_buf = vstring_alloc(256);
    int     rec_type;
    int     prev_type = 0;
    char   *start;
    time_t  arrival_time = 0;
    const char *have_orcpt = 0;
    int     rcpt_count = 0;
    int     sender_seen = 0;
    int     in_message = 0;
    int     in_body = 0;
#define QUOTE_JSON(res, src) printable(quote_for_json((res), (src), -1), '?')
#define TEXT_RECORD(type) ((type) == REC_TYPE_CONT || (type) == REC_TYPE_NORM)

    while ((rec_type = rec_get(qfile, buf, 0)) > 0) {
	start = STR(buf);
	switch (rec_type) {
	case REC_TYPE_TIME:
	    if (arrival_time == 0)
		arrival_time = atol(start);
	    break;
	case REC_TYPE_FROM:
	    if (*start == 0)
		start = (char *) empty_addr;
	    quote_822_local(printable_quoted_addr, start);
	    printable(STR(printable_quoted_addr), '?');
	    if (sender_seen++ == 0)
		vstring_strcpy(sender_q, STR(printable_quoted_addr));
	    break;
	case REC_TYPE_ORCP:
	    quote_822_local(orcpt_buf, start);
	    have_orcpt = printable(STR(orcpt_buf), '?');
	    break;
	case REC_TYPE_RCPT:
	    if (*start == 0)
		start = (char *) empty_addr;
	    quote_822_local(printable_quoted_addr, start);
	    printable(STR(printable_quoted_addr), '?');
	    if (have_orcpt == 0)
		have_orcpt = STR(vstring_strcpy(orcpt_buf, STR(printable_quoted_addr)));
	    if (include_envelope) {
		if (rcpt_count > 0)
		    vstring_strcat(recipients_buf, ", ");
		vstring_sprintf_append(recipients_buf,
				       "{\"orig_address\": \"%s\", \"address\": \"%s\"}",
				       QUOTE_JSON(quote_buf, have_orcpt),
				       QUOTE_JSON(quote_buf, STR(printable_quoted_addr)));
		rcpt_count++;
	    }
	    have_orcpt = 0;
	    break;
	case REC_TYPE_MESG:
	    in_message = 1;
	    in_body = 0;
	    break;
	case REC_TYPE_XTRA:
	case REC_TYPE_END:
	    in_message = 0;
	    break;
	default:
	    if (in_message && TEXT_RECORD(rec_type)) {
		if (in_body == 0
		    && prev_type != REC_TYPE_CONT
		    && !(is_header(start) || IS_SPACE_TAB(start[0])))
		    in_body = 1;
		if (in_body) {
		    if (include_body) {
			vstring_memcat(body_buf, start, VSTRING_LEN(buf));
			if (rec_type == REC_TYPE_NORM)
			    VSTRING_ADDCH(body_buf, '\n');
		    }
		} else if (include_headers) {
		    vstring_memcat(headers_buf, start, VSTRING_LEN(buf));
		    if (rec_type == REC_TYPE_NORM)
			VSTRING_ADDCH(headers_buf, '\n');
		}
	    }
	    break;
	}
	prev_type = rec_type;
    }
    vstream_fprintf(out, "{");
    vstream_fprintf(out, "\"queue_name\": \"%s\", ",
		    QUOTE_JSON(queue_q, queue_name));
    vstream_fprintf(out, "\"queue_id\": \"%s\", ",
		    QUOTE_JSON(id_q, queue_id));
    vstream_fprintf(out, "\"arrival_time\": %ld",
		    (long) (arrival_time > 0 ? arrival_time : mtime));
    if (include_envelope) {
	if (rcpt_count == 0) {
	    vstream_fprintf(out, ", \"envelope\": {");
	    vstream_fprintf(out, "\"sender\": \"%s\", ",
			    QUOTE_JSON(quote_buf,
				       sender_seen > 0 ? STR(sender_q) : empty_addr));
	    vstream_fprintf(out, "\"recipients\": [%s]}",
			    STR(recipients_buf));
	} else {
	    vstream_fprintf(out, ", \"envelope\": {");
	    vstream_fprintf(out, "\"sender\": \"%s\", ",
			    QUOTE_JSON(quote_buf,
				       sender_seen > 0 ? STR(sender_q) : empty_addr));
	    vstream_fprintf(out, "\"recipients\": [%s]}",
			    STR(recipients_buf));
	}
    }
    if (include_headers) {
	vstream_fprintf(out, ", \"headers\": \"%s\"",
			QUOTE_JSON(quote_buf, STR(headers_buf)));
    }
    if (include_body) {
	vstream_fprintf(out, ", \"body\": \"%s\"",
			QUOTE_JSON(quote_buf, STR(body_buf)));
    }
    vstream_fprintf(out, "}\n");
    if (vstream_fflush(out) && errno != EPIPE)
	msg_warn("output write error: %m");

#undef TEXT_RECORD
#undef QUOTE_JSON
    vstring_free(buf);
    vstring_free(printable_quoted_addr);
    vstring_free(orcpt_buf);
    vstring_free(queue_q);
    vstring_free(id_q);
    vstring_free(sender_q);
    vstring_free(quote_buf);
    vstring_free(recipients_buf);
    vstring_free(headers_buf);
    vstring_free(body_buf);
}

static char *(*postqueue_scan_next(const char *queue_name)) (SCAN_DIR *)
{
    if (strcmp(queue_name, MAIL_QUEUE_MAILDROP) == 0)
	return (scan_dir_next);
    if (strcmp(queue_name, MAIL_QUEUE_ACTIVE) == 0
	|| strcmp(queue_name, MAIL_QUEUE_INCOMING) == 0
	|| strcmp(queue_name, MAIL_QUEUE_DEFERRED) == 0
	|| strcmp(queue_name, MAIL_QUEUE_HOLD) == 0)
	return (mail_scan_dir_next);
    return (0);
}

static int postqueue_scan_queue_one_json(VSTREAM *out, const char *queue_name,
					 const char *empty_addr,
					 int dup_filter_limit,
					 const char *target_id,
					 int *match_count)
{
    SCAN_DIR *scan;
    char   *(*scan_next) (SCAN_DIR *);
    char   *id;
    char   *saved_id = 0;

    scan_next = postqueue_scan_next(queue_name);
    if (scan_next == 0)
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
	if (target_id != 0 && strcmp(target_id, id) != 0)
	    continue;
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
	if (target_id != 0 && match_count != 0) {
	    if (*match_count > 0) {
		(*match_count)++;
		(void) vstream_fclose(qfile);
		break;
	    }
	    postqueue_scan_report_json(out, queue_name, id, qfile,
				       (long) st.st_size, st.st_mtime, st.st_mode,
				       empty_addr, dup_filter_limit);
	    (*match_count)++;
	} else {
	    postqueue_scan_report_json(out, queue_name, id, qfile,
				       (long) st.st_size, st.st_mtime, st.st_mode,
				       empty_addr, dup_filter_limit);
	}
	if (vstream_fclose(qfile))
	    msg_warn("close file %s %s: %m", queue_name, id);
    }
    if (saved_id)
	myfree(saved_id);
    scan_dir_close(scan);
    return (0);
}

int
postqueue_scan_queue_json(VSTREAM *out, const char *queue_name,
			  const char *empty_addr, int dup_filter_limit)
{
    if (empty_addr == 0 || *empty_addr == 0)
	empty_addr = "MAILER-DAEMON";
    return (postqueue_scan_queue_one_json(out, queue_name, empty_addr,
					  dup_filter_limit, 0, 0));
}

int
postqueue_scan_queue_json_by_id(VSTREAM *out, const char *queue_id,
				const char *empty_addr, int dup_filter_limit)
{
    static const char *queue_names[] = {
	MAIL_QUEUE_MAILDROP,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_DEFERRED,
	MAIL_QUEUE_HOLD,
	0,
    };
    const char **queue_name;
    int     match_count = 0;

    if (queue_id == 0 || *queue_id == 0)
	return (POSTQUEUE_ID_LOOKUP_NOT_FOUND);
    if (empty_addr == 0 || *empty_addr == 0)
	empty_addr = "MAILER-DAEMON";
    for (queue_name = queue_names; *queue_name != 0; queue_name++) {
	if (postqueue_scan_queue_one_json(out, *queue_name, empty_addr,
					  dup_filter_limit, queue_id,
					  &match_count) < 0)
	    return (POSTQUEUE_ID_LOOKUP_ERROR);
	if (match_count > 1)
	    return (POSTQUEUE_ID_LOOKUP_DUPLICATE);
    }
    return (match_count > 0 ? POSTQUEUE_ID_LOOKUP_FOUND :
	    POSTQUEUE_ID_LOOKUP_NOT_FOUND);
}

int
postqueue_scan_message_json_by_id(VSTREAM *out, const char *queue_id,
				  const char *empty_addr, int dup_filter_limit,
				  int include_envelope, int include_headers,
				  int include_body)
{
    static const char *queue_names[] = {
	MAIL_QUEUE_MAILDROP,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_DEFERRED,
	MAIL_QUEUE_HOLD,
	0,
    };
    const char **queue_name;
    int     match_count = 0;

    (void) dup_filter_limit;
    if (queue_id == 0 || *queue_id == 0)
	return (POSTQUEUE_MESSAGE_LOOKUP_NOT_FOUND);
    if (empty_addr == 0 || *empty_addr == 0)
	empty_addr = "MAILER-DAEMON";
    for (queue_name = queue_names; *queue_name != 0; queue_name++) {
	SCAN_DIR *scan;
	char   *(*scan_next) (SCAN_DIR *);
	char   *id;
	char   *saved_id = 0;

	scan_next = postqueue_scan_next(*queue_name);
	if (scan_next == 0)
	    continue;
	scan = scan_dir_open(*queue_name);
	if (scan == 0)
	    return (POSTQUEUE_MESSAGE_LOOKUP_ERROR);
	while ((id = scan_next(scan)) != 0) {
	    struct stat st;
	    const char *path;
	    int     status;
	    VSTREAM *qfile;

	    if (saved_id) {
		if (strcmp(saved_id, id) == 0) {
		    msg_warn("readdir loop on queue %s id %s", *queue_name, id);
		    break;
		}
		myfree(saved_id);
	    }
	    saved_id = mystrdup(id);
	    if (strcmp(queue_id, id) != 0)
		continue;
	    status = mail_open_ok(*queue_name, id, &st, &path);
	    (void) path;
	    if (status != MAIL_OPEN_YES)
		continue;
	    qfile = mail_queue_open(*queue_name, id, O_RDONLY, 0);
	    if (qfile == 0) {
		if (errno != ENOENT)
		    msg_warn("open %s %s: %m", *queue_name, id);
		continue;
	    }
	    if (match_count > 0) {
		match_count++;
		(void) vstream_fclose(qfile);
		break;
	    }
	    postqueue_scan_report_message_json(out, *queue_name, id, qfile,
					       st.st_mtime, empty_addr,
					       include_envelope,
					       include_headers,
					       include_body);
	    match_count++;
	    if (vstream_fclose(qfile))
		msg_warn("close file %s %s: %m", *queue_name, id);
	}
	if (saved_id)
	    myfree(saved_id);
	scan_dir_close(scan);
	if (match_count > 1)
	    return (POSTQUEUE_MESSAGE_LOOKUP_DUPLICATE);
    }
    return (match_count > 0 ? POSTQUEUE_MESSAGE_LOOKUP_FOUND :
	    POSTQUEUE_MESSAGE_LOOKUP_NOT_FOUND);
}
