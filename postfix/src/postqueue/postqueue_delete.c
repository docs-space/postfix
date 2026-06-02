#include <sys_defs.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

#include <msg.h>
#include <vstring.h>

#include <mail_open_ok.h>
#include <mail_queue.h>

#include <postqueue.h>

int
postqueue_delete_exec(const char *queue_id)
{
    static const char *msg_queue_names[] = {
	MAIL_QUEUE_MAILDROP,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_DEFERRED,
	MAIL_QUEUE_HOLD,
	0,
    };
    static const char *log_queue_names[] = {
	MAIL_QUEUE_BOUNCE,
	MAIL_QUEUE_DEFER,
	MAIL_QUEUE_TRACE,
	0,
    };
    struct stat st;
    const char **msg_qpp;
    const char **log_qpp;
    const char *msg_path;
    VSTRING *log_path_buf;
    int     found;
    int     tries;

    if (queue_id == 0 || *queue_id == 0 || !mail_queue_id_ok(queue_id))
	return (POSTQUEUE_DELETE_INVALID);

    log_path_buf = vstring_alloc(100);
    found = 0;
    for (tries = 0; found == 0 && tries < 2; tries++) {
	for (msg_qpp = msg_queue_names; *msg_qpp != 0; msg_qpp++) {
	    if (mail_open_ok(*msg_qpp, queue_id, &st, &msg_path) != MAIL_OPEN_YES)
		continue;
	    for (log_qpp = log_queue_names; *log_qpp != 0; log_qpp++) {
		if (remove(mail_queue_path(log_path_buf, *log_qpp, queue_id)) < 0
		    && errno != ENOENT)
		    msg_warn("%s: remove logfile %s/%s: %m",
			     queue_id, *log_qpp, queue_id);
	    }
	    if (remove(msg_path) == 0) {
		found = 1;
		break;
	    }
	    if (errno != ENOENT) {
		msg_warn("%s: remove %s: %m", queue_id, msg_path);
		vstring_free(log_path_buf);
		return (POSTQUEUE_DELETE_ERROR);
	    }
	}
    }
    vstring_free(log_path_buf);
    return (found ? POSTQUEUE_DELETE_DELETED : POSTQUEUE_DELETE_NOT_FOUND);
}
