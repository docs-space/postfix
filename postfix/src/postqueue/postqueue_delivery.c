#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <msg.h>
#include <scan_dir.h>
#include <mymalloc.h>
#include <events.h>

#include <mail_conf.h>
#include <mail_proto.h>
#include <mail_params.h>
#include <mail_open_ok.h>
#include <mail_queue.h>
#include <mail_scan_dir.h>
#include <mail_flush.h>
#include <flush_clnt.h>
#include <user_acl.h>

#include <postqueue.h>

static const CONFIG_STR_TABLE postqueue_delivery_str_table[] = {
    VAR_FLUSH_ACL, DEF_FLUSH_ACL, &var_flush_acl, 0, 0,
    0,
};

static int postqueue_flush_acl_ok(void)
{
    const char *errstr;
    uid_t   uid = getuid();

    mail_conf_read();
    get_mail_conf_str_table(postqueue_delivery_str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_FLUSH_ACL, var_flush_acl,
					  uid)) != 0) {
	msg_warn("postqueue: %s(%ld) is not allowed to flush the mail queue",
		 errstr, (long) uid);
	return (0);
    }
    return (1);
}

static int postqueue_flush_in_deferred_or_incoming(const char *queue_id)
{
    struct stat st;
    const char *msg_path;

    if (mail_open_ok(MAIL_QUEUE_DEFERRED, queue_id, &st, &msg_path) == MAIL_OPEN_YES)
	return (1);
    if (mail_open_ok(MAIL_QUEUE_INCOMING, queue_id, &st, &msg_path) == MAIL_OPEN_YES)
	return (1);
    return (0);
}

static char *(*postqueue_force_delivery_scan_next(const char *queue_name)) (SCAN_DIR *)
{
    if (strcmp(queue_name, MAIL_QUEUE_INCOMING) == 0
	|| strcmp(queue_name, MAIL_QUEUE_DEFERRED) == 0)
	return (mail_scan_dir_next);
    return (0);
}

static int postqueue_force_delivery_queue_exec(const char *queue_name)
{
    SCAN_DIR *scan;
    char   *(*scan_next) (SCAN_DIR *);
    char   *id;
    char   *saved_id = 0;
    int     status;

    scan_next = postqueue_force_delivery_scan_next(queue_name);
    if (scan_next == 0)
	return (POSTQUEUE_FORCE_QUEUE_INVALID);
    scan = scan_dir_open(queue_name);
    if (scan == 0)
	return (POSTQUEUE_FORCE_QUEUE_ERROR);

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
	status = postqueue_flush_by_id(id);
	if (status == POSTQUEUE_FLUSH_ERROR) {
	    if (saved_id)
		myfree(saved_id);
	    scan_dir_close(scan);
	    return (POSTQUEUE_FORCE_QUEUE_ERROR);
	}
    }
    if (saved_id)
	myfree(saved_id);
    scan_dir_close(scan);
    return (POSTQUEUE_FORCE_QUEUE_OK);
}

int
postqueue_flush_by_id(const char *queue_id)
{
    int     flush_status;

    if (queue_id == 0 || *queue_id == 0 || !mail_queue_id_ok(queue_id))
	return (POSTQUEUE_FLUSH_INVALID);
    if (!postqueue_flush_acl_ok())
	return (POSTQUEUE_FLUSH_ERROR);
    if (!postqueue_flush_in_deferred_or_incoming(queue_id))
	return (POSTQUEUE_FLUSH_NOT_FOUND);

    switch (flush_status = flush_send_file(queue_id)) {
    case FLUSH_STAT_OK:
	return (POSTQUEUE_FLUSH_OK);
    case FLUSH_STAT_BAD:
	return (POSTQUEUE_FLUSH_NOT_FOUND);
    default:
	return (POSTQUEUE_FLUSH_ERROR);
    }
}

int
postqueue_force_delivery_queue(const char *queue_name)
{
    if (queue_name == 0 || *queue_name == 0 || !mail_queue_name_ok(queue_name))
	return (POSTQUEUE_FORCE_QUEUE_INVALID);
    if (strcmp(queue_name, MAIL_QUEUE_DEFERRED) != 0
	&& strcmp(queue_name, MAIL_QUEUE_INCOMING) != 0)
	return (POSTQUEUE_FORCE_QUEUE_INVALID);
    if (!postqueue_flush_acl_ok())
	return (POSTQUEUE_FORCE_QUEUE_ERROR);
    return (postqueue_force_delivery_queue_exec(queue_name));
}

int
postqueue_trigger_delivery(void)
{
    if (!postqueue_flush_acl_ok())
	return (POSTQUEUE_TRIGGER_ERROR);
    if (mail_flush_deferred() < 0)
	return (POSTQUEUE_TRIGGER_ERROR);
    if (mail_flush_maildrop() < 0)
	return (POSTQUEUE_TRIGGER_ERROR);
    event_drain(2);
    return (POSTQUEUE_TRIGGER_OK);
}
