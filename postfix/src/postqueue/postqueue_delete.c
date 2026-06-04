#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <msg.h>
#include <vstring.h>
#include <scan_dir.h>
#include <mymalloc.h>

#include <mail_conf.h>
#include <mail_proto.h>
#include <mail_params.h>
#include <mail_open_ok.h>
#include <mail_queue.h>
#include <mail_scan_dir.h>
#include <user_acl.h>

#include <postqueue.h>

extern char *var_showq_acl;

int     postqueue_delete_exec(const char *);

static const CONFIG_STR_TABLE postqueue_clear_str_table[] = {
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    0,
};

static char *(*postqueue_clear_scan_next(const char *queue_name)) (SCAN_DIR *)
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

static int postqueue_clear_queue_exec(const char *queue_name)
{
    SCAN_DIR *scan;
    char   *(*scan_next) (SCAN_DIR *);
    char   *id;
    char   *saved_id = 0;
    int     status;

    scan_next = postqueue_clear_scan_next(queue_name);
    if (scan_next == 0)
	return (POSTQUEUE_CLEAR_INVALID);
    scan = scan_dir_open(queue_name);
    if (scan == 0)
	return (POSTQUEUE_CLEAR_ERROR);

    while ((id = scan_next(scan)) != 0) {
	struct stat st;
	const char *path;

	if (saved_id) {
	    if (strcmp(saved_id, id) == 0) {
		msg_warn("readdir loop on queue %s id %s", queue_name, id);
		break;
	    }
	    myfree(saved_id);
	}
	saved_id = mystrdup(id);
	if (mail_open_ok(queue_name, id, &st, &path) != MAIL_OPEN_YES)
	    continue;
	status = postqueue_delete_exec(id);
	if (status == POSTQUEUE_DELETE_ERROR) {
	    if (saved_id)
		myfree(saved_id);
	    scan_dir_close(scan);
	    return (POSTQUEUE_CLEAR_ERROR);
	}
    }
    if (saved_id)
	myfree(saved_id);
    scan_dir_close(scan);
    return (POSTQUEUE_CLEAR_OK);
}

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

/* postqueue_clear_queue - delete all messages in one named queue */

int
postqueue_clear_queue(const char *queue_name)
{
    const char *errstr;
    uid_t   uid = getuid();

    if (queue_name == 0 || *queue_name == 0 || !mail_queue_name_ok(queue_name))
	return (POSTQUEUE_CLEAR_INVALID);
    mail_conf_read();
    get_mail_conf_str_table(postqueue_clear_str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_clear_queue: %s(%ld) is not allowed to modify the mail queue",
		 errstr, (long) uid);
	return (POSTQUEUE_CLEAR_ERROR);
    }
    return (postqueue_clear_queue_exec(queue_name));
}
