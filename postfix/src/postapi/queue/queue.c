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
#include <mymalloc.h>
#include <postqueue.h>

#include "postapi_dispatch.h"
#include "queue.h"

 /* queue_dispatch - GET /api/v1/Queue/All (empty action is not found) */

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
    if (strcmp(action, "All") == 0) {
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
	{
	    json_t *arr;

	    arr = postapi_ndjson_to_json_array(vstring_str(buf), VSTRING_LEN(buf));
	    vstring_free(buf);
	    if (arr == 0)
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "invalid_queue_json")));
	    return (postapi_resp_json(200, arr));
	}
    } else if (strcmp(action, "Items") == 0) {
	const json_t *queue_names;
	size_t  queue_count;
	const char **queue_name_vec;
	size_t  n;
	json_t *items;
	POSTAPI_RESP *resp;

	if (strcmp(method, "POST") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	if (body == 0 || !json_is_object(body))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "invalid_body")));
	queue_names = json_object_get(body, "queue_name");
	if (queue_names == 0 || !json_is_array(queue_names))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "invalid_body")));

	queue_count = json_array_size(queue_names);
	queue_name_vec = queue_count > 0 ?
	    (const char **) mymalloc(sizeof(*queue_name_vec) * queue_count) : 0;
	for (n = 0; n < queue_count; n++) {
	    json_t *entry = json_array_get(queue_names, n);

	    if (!json_is_string(entry)) {
		if (queue_name_vec)
		    myfree((void *) queue_name_vec);
		return (postapi_resp_json(400,
					  json_pack("{s:s}", "error", "invalid_body")));
	    }
	    queue_name_vec[n] = json_string_value(entry);
	}

	buf = vstring_alloc(256);
	if ((mem = vstream_memopen(buf, O_WRONLY)) == 0) {
	    if (queue_name_vec)
		myfree((void *) queue_name_vec);
	    vstring_free(buf);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error", "service_unavailable")));
	}
	for (n = 0; n < queue_count; n++) {
	    if (postqueue_list_json_by_queue(mem, queue_name_vec[n]) < 0) {
		(void) vstream_fclose(mem);
		if (queue_name_vec)
		    myfree((void *) queue_name_vec);
		vstring_free(buf);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error", "service_unavailable")));
	    }
	}
	if (queue_name_vec)
	    myfree((void *) queue_name_vec);
	if (vstream_fclose(mem) != 0) {
	    vstring_free(buf);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error", "service_unavailable")));
	}
	items = postapi_ndjson_to_json_array(vstring_str(buf), VSTRING_LEN(buf));
	vstring_free(buf);
	if (items == 0)
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error", "invalid_queue_json")));
	resp = postapi_resp_json(200,
				 json_pack("{s:o,s:I}", "items", items,
					   "totalCount", (json_int_t) json_array_size(items)));
	return (resp);
    }

    return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
}
