#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
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

static const CONFIG_STR_TABLE postqueue_requeue_str_table[] = {
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    0,
};

static int postqueue_modify_acl_ok(void)
{
    const char *errstr;
    uid_t   uid = getuid();

    mail_conf_read();
    get_mail_conf_str_table(postqueue_requeue_str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue: %s(%ld) is not allowed to modify the mail queue",
		 errstr, (long) uid);
	return (0);
    }
    return (1);
}

static int postqueue_requeue_touch_maildrop(const char *queue_id)
{
    struct stat st;
    const char *msg_path;
    struct utimbuf tbuf;
    VSTRING *path_buf;

    if (mail_open_ok(MAIL_QUEUE_MAILDROP, queue_id, &st, &msg_path) != MAIL_OPEN_YES)
	return (-1);
    path_buf = vstring_alloc(100);
    mail_queue_path(path_buf, MAIL_QUEUE_MAILDROP, queue_id);
    tbuf.actime = tbuf.modtime = time((time_t *) 0);
    if (utime(vstring_str(path_buf), &tbuf) < 0) {
	msg_warn("%s: reset time stamps: %m", vstring_str(path_buf));
	vstring_free(path_buf);
	return (-1);
    }
    vstring_free(path_buf);
    return (0);
}

static int postqueue_requeue_exec(const char *queue_id)
{
    static const char *src_queues[] = {
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_DEFERRED,
	MAIL_QUEUE_HOLD,
	0,
    };
    struct stat st;
    const char **qpp;
    const char *msg_path;
    int     tries;

    for (tries = 0; tries < 2; tries++) {
	for (qpp = src_queues; *qpp != 0; qpp++) {
	    if (mail_open_ok(*qpp, queue_id, &st, &msg_path) != MAIL_OPEN_YES)
		continue;
	    if (mail_queue_rename(queue_id, *qpp, MAIL_QUEUE_MAILDROP) != 0)
		return (POSTQUEUE_REQUEUE_ERROR);
	    if (postqueue_requeue_touch_maildrop(queue_id) < 0)
		return (POSTQUEUE_REQUEUE_ERROR);
	    return (POSTQUEUE_REQUEUE_OK);
	}
    }
    return (POSTQUEUE_REQUEUE_NOT_FOUND);
}

static char *(*postqueue_requeue_scan_next(const char *queue_name)) (SCAN_DIR *)
{
    if (strcmp(queue_name, MAIL_QUEUE_INCOMING) == 0
	|| strcmp(queue_name, MAIL_QUEUE_ACTIVE) == 0
	|| strcmp(queue_name, MAIL_QUEUE_DEFERRED) == 0
	|| strcmp(queue_name, MAIL_QUEUE_HOLD) == 0)
	return (mail_scan_dir_next);
    return (0);
}

static int postqueue_requeue_queue_exec(const char *queue_name)
{
    SCAN_DIR *scan;
    char   *(*scan_next) (SCAN_DIR *);
    char   *id;
    char   *saved_id = 0;
    int     status;

    scan_next = postqueue_requeue_scan_next(queue_name);
    if (scan_next == 0)
	return (POSTQUEUE_REQUEUE_QUEUE_INVALID);
    scan = scan_dir_open(queue_name);
    if (scan == 0)
	return (POSTQUEUE_REQUEUE_QUEUE_ERROR);

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
	status = postqueue_requeue_exec(id);
	if (status == POSTQUEUE_REQUEUE_ERROR) {
	    if (saved_id)
		myfree(saved_id);
	    scan_dir_close(scan);
	    return (POSTQUEUE_REQUEUE_QUEUE_ERROR);
	}
    }
    if (saved_id)
	myfree(saved_id);
    scan_dir_close(scan);
    return (POSTQUEUE_REQUEUE_QUEUE_OK);
}

int
postqueue_requeue_by_id(const char *queue_id)
{
    if (queue_id == 0 || *queue_id == 0 || !mail_queue_id_ok(queue_id))
	return (POSTQUEUE_REQUEUE_INVALID);
    if (!postqueue_modify_acl_ok())
	return (POSTQUEUE_REQUEUE_ERROR);
    return (postqueue_requeue_exec(queue_id));
}

int
postqueue_requeue_queue(const char *queue_name)
{
    if (queue_name == 0 || *queue_name == 0 || !mail_queue_name_ok(queue_name))
	return (POSTQUEUE_REQUEUE_QUEUE_INVALID);
    if (postqueue_requeue_scan_next(queue_name) == 0)
	return (POSTQUEUE_REQUEUE_QUEUE_INVALID);
    if (!postqueue_modify_acl_ok())
	return (POSTQUEUE_REQUEUE_QUEUE_ERROR);
    return (postqueue_requeue_queue_exec(queue_name));
}
