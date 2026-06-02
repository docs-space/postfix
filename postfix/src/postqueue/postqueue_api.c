/*++
/* NAME
/*	postqueue_api 3
/* SUMMARY
/*	programmatic queue listing for postapi
/*--*/

#include <sys_defs.h>
#include <unistd.h>
#include <errno.h>

#include <mail_conf.h>
#include <mail_params.h>
#include <mail_addr.h>
#include <mail_proto.h>
#include <attr.h>
#include <connect.h>
#include <msg.h>
#include <vstream.h>
#include <user_acl.h>

#include <postqueue.h>

extern char *var_showq_acl;
extern int postqueue_delete_exec(const char *);

static int postqueue_dup_filter_limit;
static char *postqueue_empty_addr;

static const CONFIG_INT_TABLE int_table[] = {
    VAR_DUP_FILTER_LIMIT, DEF_DUP_FILTER_LIMIT, &postqueue_dup_filter_limit, 0, 0,
    0,
};

static const CONFIG_STR_TABLE str_table[] = {
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    VAR_EMPTY_ADDR, DEF_EMPTY_ADDR, &postqueue_empty_addr, 1, 0,
    0,
};

 /* showq_client_json - run the showq protocol client (JSON listing) */

static void
showq_client_json(VSTREAM *showq, VSTREAM *fp)
{
    if (attr_scan(showq, ATTR_FLAG_STRICT,
		  RECV_ATTR_STREQ(MAIL_ATTR_PROTO, MAIL_ATTR_PROTO_SHOWQ),
		  ATTR_TYPE_END) != 0)
	msg_fatal("malformed showq server response");
    showq_json_fp(showq, fp);
}

/* postqueue_list_json - write queue listing in JSON LINES format to fp */

int
postqueue_list_json(VSTREAM *fp)
{
    const char *errstr;
    VSTREAM *showq;
    uid_t   uid = getuid();

    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_list_json: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (-1);
    }
    if ((showq = mail_connect(MAIL_CLASS_PUBLIC, var_showq_service, BLOCKING)) == 0) {
	msg_warn("postqueue_list_json: connect to the %s %s service: %m",
		 var_mail_name, var_showq_service);
	return (-1);
    }
    showq_client_json(showq, fp);
    if (vstream_fclose(showq))
	msg_warn("postqueue_list_json: close showq: %m");
    return (0);
}

/* postqueue_list_json_by_queue - write one queue listing as JSON LINES */

int
postqueue_list_json_by_queue(VSTREAM *fp, const char *queue_name)
{
    const char *errstr;
    uid_t   uid = getuid();

    if (queue_name == 0 || *queue_name == 0)
	return (0);
    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_list_json_by_queue: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (-1);
    }
    if (postqueue_scan_queue_json(fp, queue_name, postqueue_empty_addr,
				  postqueue_dup_filter_limit) < 0) {
	msg_warn("postqueue_list_json_by_queue: queue scan failed for %s",
		 queue_name);
	return (-1);
    }
    return (0);
}

/* postqueue_list_json_by_id - write one queue item as JSON LINES by queue_id */

int
postqueue_list_json_by_id(VSTREAM *fp, const char *queue_id)
{
    const char *errstr;
    uid_t   uid = getuid();
    int     status;

    if (queue_id == 0 || *queue_id == 0)
	return (POSTQUEUE_ID_LOOKUP_NOT_FOUND);
    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_list_json_by_id: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (POSTQUEUE_ID_LOOKUP_ERROR);
    }
    status = postqueue_scan_queue_json_by_id(fp, queue_id, postqueue_empty_addr,
					     postqueue_dup_filter_limit);
    if (status == POSTQUEUE_ID_LOOKUP_ERROR)
	msg_warn("postqueue_list_json_by_id: queue scan failed for %s", queue_id);
    return (status);
}

/* postqueue_message_json_by_id - write one queue message as JSON by queue_id */

int
postqueue_message_json_by_id(VSTREAM *fp, const char *queue_id,
			     int include_envelope, int include_headers,
			     int include_body)
{
    const char *errstr;
    uid_t   uid = getuid();
    int     status;

    if (queue_id == 0 || *queue_id == 0)
	return (POSTQUEUE_MESSAGE_LOOKUP_NOT_FOUND);
    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_message_json_by_id: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (POSTQUEUE_MESSAGE_LOOKUP_ERROR);
    }
    status = postqueue_scan_message_json_by_id(fp, queue_id, postqueue_empty_addr,
					       postqueue_dup_filter_limit,
					       include_envelope,
					       include_headers,
					       include_body);
    if (status == POSTQUEUE_MESSAGE_LOOKUP_ERROR)
	msg_warn("postqueue_message_json_by_id: queue scan failed for %s", queue_id);
    return (status);
}

/* postqueue_delete_by_id - delete one queue item by queue_id */

int
postqueue_delete_by_id(const char *queue_id)
{
    const char *errstr;
    uid_t   uid = getuid();

    if (queue_id == 0 || *queue_id == 0)
	return (POSTQUEUE_DELETE_INVALID);
    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_delete_by_id: %s(%ld) is not allowed to modify the mail queue",
		 errstr, (long) uid);
	return (POSTQUEUE_DELETE_ERROR);
    }
    return (postqueue_delete_exec(queue_id));
}
