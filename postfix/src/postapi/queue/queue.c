/*++
/* NAME
/*	postapi_queue 3
/* SUMMARY
/*	PostAPI Queue controller
/*--*/

#include <sys_defs.h>
#include <string.h>
#include <errno.h>

#include <jansson.h>

#include <msg.h>
#include <vstream.h>
#include <vstring.h>
#include <postqueue.h>

#include "postapi_dispatch.h"
#include "queue.h"

 /* queue_dispatch - GET /api/v1/Queue/All */

POSTAPI_RESP *
queue_dispatch(int authorized, const char *method, const char *action,
	               json_t *query, json_t *body)
{
    VSTREAM *mem;
    VSTRING *buf;

    (void) query;
    (void) body;

    if (!authorized)
	return (postapi_resp_json(401,
				 json_pack("{s:s}", "error", "unauthorized")));
    if (strcmp(action, "All") != 0)
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    if (strcmp(method, "GET") != 0)
	return (postapi_resp_json(405,
				 json_pack("{s:s}", "error", "method_not_allowed")));

    buf = vstring_alloc(256);
    if ((mem = vstream_memopen(buf, O_WRONLY)) == 0) {
	vstring_free(buf);
	return (postapi_resp_json(503,
				 json_pack("{s:s}", "error", "service_unavailable")));
    }
    if (postqueue_list_json(mem) < 0) {
	(void) vstream_fclose(mem);
	vstring_free(buf);
	return (postapi_resp_json(503,
				 json_pack("{s:s}", "error", "service_unavailable")));
    }
    if (vstream_fclose(mem) != 0) {
	vstring_free(buf);
	return (postapi_resp_json(503,
				 json_pack("{s:s}", "error", "service_unavailable")));
    }
    return (postapi_resp_ndjson(200, buf));
}
