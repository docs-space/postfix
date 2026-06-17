/*++
/* NAME
/*	router_deliver 3
/* SUMMARY
/*	router delivery orchestration
/* LICENSE
/*	The Secure Mailer license must be distributed with this software.
/*--*/

/* System library. */

#include <sys_defs.h>

/* Utility library. */

#include <msg.h>
#include <vstream.h>
#include <mymalloc.h>

/* Global library. */

#include <mail_params.h>
#include <mail_proto.h>
#include <mail_connect.h>
#include <deliver_request.h>
#include <recipient_list.h>
#include <dsb_scan.h>
#include <rcpt_print.h>
#include <rcpt_buf.h>

/* Application-specific. */

#include "router.h"

#define ROUTER_INVOKE_OK		0
#define ROUTER_INVOKE_DEFER		1
#define ROUTER_INVOKE_ERROR		2
#define ROUTER_INVOKE_DEFER_INTERNAL	3
#define ROUTER_INVOKE_UNKNOWN		4

/* router_invoke_initial_reply - retrieve initial delivery process response */

static int router_invoke_initial_reply(VSTREAM *stream)
{
    if (attr_scan(stream, ATTR_FLAG_STRICT,
		  RECV_ATTR_STREQ(MAIL_ATTR_PROTO, MAIL_ATTR_PROTO_DELIVER),
		  ATTR_TYPE_END) != 0) {
	msg_warn("%s: malformed response", VSTREAM_PATH(stream));
	return (-1);
    }
    return (0);
}

/* router_invoke_send_request - send delivery request to transport */

static int router_invoke_send_request(VSTREAM *stream, DELIVER_REQUEST *request,
				              const char *nexthop,
				              RECIPIENT_LIST *rcpts, int flags)
{
    RECIPIENT *rcpt;
    int     stat;

    attr_print(stream, ATTR_FLAG_NONE,
	       SEND_ATTR_INT(MAIL_ATTR_FLAGS, flags),
	       SEND_ATTR_STR(MAIL_ATTR_QUEUE, request->queue_name),
	       SEND_ATTR_STR(MAIL_ATTR_QUEUEID, request->queue_id),
	       SEND_ATTR_LONG(MAIL_ATTR_OFFSET, request->data_offset),
	       SEND_ATTR_LONG(MAIL_ATTR_SIZE, request->data_size),
	       SEND_ATTR_STR(MAIL_ATTR_NEXTHOP, nexthop),
	       SEND_ATTR_STR(MAIL_ATTR_ENCODING, request->encoding),
	       SEND_ATTR_INT(MAIL_ATTR_SENDOPTS, request->sendopts),
	       SEND_ATTR_STR(MAIL_ATTR_SENDER, request->sender),
	       SEND_ATTR_STR(MAIL_ATTR_DSN_ENVID, request->dsn_envid),
	       SEND_ATTR_INT(MAIL_ATTR_DSN_RET, request->dsn_ret),
	       SEND_ATTR_FUNC(msg_stats_print, (const void *) &request->msg_stats),
	     SEND_ATTR_STR(MAIL_ATTR_LOG_CLIENT_NAME, request->client_name),
	     SEND_ATTR_STR(MAIL_ATTR_LOG_CLIENT_ADDR, request->client_addr),
	     SEND_ATTR_STR(MAIL_ATTR_LOG_CLIENT_PORT, request->client_port),
	     SEND_ATTR_STR(MAIL_ATTR_LOG_PROTO_NAME, request->client_proto),
	       SEND_ATTR_STR(MAIL_ATTR_LOG_HELO_NAME, request->client_helo),
	       SEND_ATTR_STR(MAIL_ATTR_SASL_METHOD, request->sasl_method),
	     SEND_ATTR_STR(MAIL_ATTR_SASL_USERNAME, request->sasl_username),
	       SEND_ATTR_STR(MAIL_ATTR_SASL_SENDER, request->sasl_sender),
	       SEND_ATTR_STR(MAIL_ATTR_LOG_IDENT, request->log_ident),
	     SEND_ATTR_STR(MAIL_ATTR_RWR_CONTEXT, request->rewrite_context),
	       SEND_ATTR_INT(MAIL_ATTR_RCPT_COUNT, rcpts->len),
	       ATTR_TYPE_END);
    for (rcpt = rcpts->info; rcpt < rcpts->info + rcpts->len; rcpt++)
	attr_print(stream, ATTR_FLAG_NONE,
		   SEND_ATTR_FUNC(rcpt_print, (const void *) rcpt),
		   ATTR_TYPE_END);

    if (vstream_fflush(stream)) {
	msg_warn("%s: bad write: %m", VSTREAM_PATH(stream));
	stat = -1;
    } else {
	stat = 0;
    }
    return (stat);
}

/* router_invoke_read_undelivered - read optional undelivered recipient list */

static int router_invoke_read_undelivered(VSTREAM *stream,
					          RECIPIENT_LIST *undelivered_out)
{
    static RCPT_BUF *rcpt_buf;
    int     undel_count;
    int     n;

    if (rcpt_buf == 0)
	rcpt_buf = rcpb_create();
    if (attr_scan(stream, ATTR_FLAG_STRICT,
		  RECV_ATTR_INT(MAIL_ATTR_UNDELIVERED_RCPT_COUNT, &undel_count),
		  ATTR_TYPE_END) != 1) {
	msg_warn("%s: malformed undelivered count", VSTREAM_PATH(stream));
	return (-1);
    }
    recipient_list_init(undelivered_out, RCPT_LIST_INIT_STATUS);
    for (n = 0; n < undel_count; n++) {
	if (attr_scan(stream, ATTR_FLAG_STRICT,
		      RECV_ATTR_FUNC(rcpb_scan, (void *) rcpt_buf),
		      ATTR_TYPE_END) != 1) {
	    msg_warn("%s: malformed undelivered recipient", VSTREAM_PATH(stream));
	    recipient_list_free(undelivered_out);
	    return (-1);
	}
	recipient_list_add(undelivered_out, rcpt_buf->offset,
			   vstring_str(rcpt_buf->dsn_orcpt),
			   rcpt_buf->dsn_notify,
			   vstring_str(rcpt_buf->orig_addr),
			   vstring_str(rcpt_buf->address));
    }
    return (0);
}

/* router_invoke_final_reply - retrieve final delivery process response */

static int router_invoke_final_reply(VSTREAM *stream, DSN_BUF *dsb,
				             int expect_undelivered,
				             RECIPIENT_LIST *undelivered_out)
{
    int     stat;

    if (expect_undelivered
	&& router_invoke_read_undelivered(stream, undelivered_out) < 0)
	return (ROUTER_INVOKE_UNKNOWN);
    if (attr_scan(stream, ATTR_FLAG_STRICT,
		  RECV_ATTR_FUNC(dsb_scan, (void *) dsb),
		  RECV_ATTR_INT(MAIL_ATTR_STATUS, &stat),
		  ATTR_TYPE_END) != 2) {
	msg_warn("%s: malformed response", VSTREAM_PATH(stream));
	return (ROUTER_INVOKE_UNKNOWN);
    }
    return (stat ? ROUTER_INVOKE_DEFER_INTERNAL : ROUTER_INVOKE_OK);
}

/* router_invoke_transport - deliver one route group via transport service */

static int router_invoke_transport(const char *transport, const char *nexthop,
				           DELIVER_REQUEST *request,
				           RECIPIENT_LIST *rcpts,
				           int is_final_group,
				           RECIPIENT_LIST *undelivered_out)
{
    const char *myname = "router_invoke_transport";
    VSTREAM *stream;
    DSN_BUF *dsb;
    int     flags;
    int     status;
    int     expect_undelivered;

    if (rcpts == 0 || rcpts->len <= 0)
	return (ROUTER_INVOKE_OK);

    if (msg_verbose)
	msg_info("%s: passing queue id %s to transport=%s nexthop=%s (%d recipients)",
		 myname, request->queue_id, transport, nexthop, rcpts->len);

    stream = mail_connect_wait(MAIL_CLASS_PRIVATE, transport);
    dsb = dsb_create();
    flags = request->flags;
    if (!is_final_group)
	flags |= DEL_REQ_FLAG_ROUTER_NON_FINAL;
    else
	flags &= ~DEL_REQ_FLAG_ROUTER_NON_FINAL;
    expect_undelivered = (flags & DEL_REQ_FLAG_ROUTER_NON_FINAL) != 0;

    if (router_invoke_initial_reply(stream) != 0
	|| router_invoke_send_request(stream, request, nexthop, rcpts, flags) != 0) {
	status = ROUTER_INVOKE_ERROR;
    } else {
	status = router_invoke_final_reply(stream, dsb, expect_undelivered,
					   undelivered_out);
	if (status == ROUTER_INVOKE_UNKNOWN)
	    status = ROUTER_INVOKE_ERROR;
    }

    vstream_fclose(stream);
    dsb_free(dsb);

    if (status == ROUTER_INVOKE_DEFER_INTERNAL)
	return (ROUTER_INVOKE_DEFER);
    if (status == ROUTER_INVOKE_OK)
	return (ROUTER_INVOKE_OK);
    return (ROUTER_INVOKE_ERROR);
}

/* router_rcpt_list_copy - duplicate recipient list */

static void router_rcpt_list_copy(RECIPIENT_LIST *dst, RECIPIENT_LIST *src)
{
    RECIPIENT *rcpt;

    recipient_list_init(dst, RCPT_LIST_INIT_STATUS);
    for (rcpt = src->info; rcpt < src->info + src->len; rcpt++)
	recipient_list_add(dst, rcpt->offset, rcpt->dsn_orcpt,
			   rcpt->dsn_notify, rcpt->orig_addr, rcpt->address);
}

/* router_rcpt_list_replace - replace dst contents with src */

static void router_rcpt_list_replace(RECIPIENT_LIST *dst, RECIPIENT_LIST *src)
{
    recipient_list_free(dst);
    router_rcpt_list_copy(dst, src);
}

/* router_service - perform service for client */

void    router_service(VSTREAM *client_stream, char *service,
			           char **unused_argv)
{
    const char *myname = "router_service";
    DELIVER_REQUEST *request;
    ROUTER_ROUTE *route;
    RECIPIENT_LIST remaining;
    RECIPIENT_LIST next_remaining;
    int     saved_flags;
    int     status;
    int     agg_status;
    int     i;
    int     is_final;

    if ((request = deliver_request_read(client_stream)) == 0)
	return;

    if ((route = router_parse(request->nexthop)) == 0)
	msg_fatal("invalid router nexthop: \"%s\"", request->nexthop);

    router_rcpt_list_copy(&remaining, &request->rcpt_list);
    recipient_list_init(&next_remaining, RCPT_LIST_INIT_STATUS);
    saved_flags = request->flags;
    agg_status = DEL_STAT_FINAL;

    for (i = 0; i < route->count; i++) {
	if (remaining.len <= 0)
	    break;
	is_final = (i == route->count - 1);
	request->flags = saved_flags;

	status = router_invoke_transport(route->groups[i].transport,
					 route->groups[i].nexthop,
					 request, &remaining, is_final,
					 &next_remaining);
	if (status == ROUTER_INVOKE_OK) {
	    remaining.len = 0;
	    agg_status = DEL_STAT_FINAL;
	    break;
	}
	if (status == ROUTER_INVOKE_ERROR) {
	    agg_status = DEL_STAT_DEFER;
	    break;
	}
	if (!is_final) {
	    if (msg_verbose)
		msg_info("%s: group %d (%s) soft fail, %d undelivered recipient(s)",
			 myname, i, route->groups[i].transport,
			 next_remaining.len);
	    router_rcpt_list_replace(&remaining, &next_remaining);
	    recipient_list_free(&next_remaining);
	    recipient_list_init(&next_remaining, RCPT_LIST_INIT_STATUS);
	    continue;
	}
	agg_status = DEL_STAT_DEFER;
    }

    recipient_list_free(&next_remaining);
    recipient_list_free(&remaining);
    router_route_free(route);
    deliver_request_done(client_stream, request, agg_status);
}
