/*++
/* NAME
/*	postapi_dispatch 3
/* SUMMARY
/*	PostAPI request router
/*--*/

#include <sys_defs.h>
#include <string.h>
#include <stdlib.h>

#include <microhttpd.h>
#include <jansson.h>

#include <mymalloc.h>
#include <vstring.h>

#include "postapi_dispatch.h"
#include "queue/queue.h"
#include "postconf/postconf.h"

#define POSTAPI_API_PREFIX	"/api/v1"
#define POSTAPI_API_PREFIX_LEN	(sizeof(POSTAPI_API_PREFIX) - 1)

typedef POSTAPI_RESP *(*POSTAPI_CTRL_FN) (int, const char *, const char *,
			                           json_t *, json_t *);

static struct {
    const char *name;
    POSTAPI_CTRL_FN dispatch;
} postapi_controllers[] = {
    {"Queue", queue_dispatch},
    {"PostConf", postconf_dispatch},
    {0, 0},
};

 /* postapi_resp_free - release response object */

void
postapi_resp_free(POSTAPI_RESP *resp)
{
    if (resp == 0)
	return;
    if (resp->json)
	json_decref(resp->json);
    if (resp->ndjson)
	vstring_free(resp->ndjson);
    myfree(resp);
}

 /* postapi_resp_json - JSON object response */

POSTAPI_RESP *
postapi_resp_json(unsigned int code, json_t *obj)
{
    POSTAPI_RESP *resp;

    resp = (POSTAPI_RESP *) mymalloc(sizeof(*resp));
    resp->http_code = code;
    resp->is_ndjson = 0;
    resp->json = obj;
    resp->ndjson = 0;
    return (resp);
}

 /* postapi_resp_ndjson - raw NDJSON body */

POSTAPI_RESP *
postapi_resp_ndjson(unsigned int code, VSTRING *body)
{
    POSTAPI_RESP *resp;

    resp = (POSTAPI_RESP *) mymalloc(sizeof(*resp));
    resp->http_code = code;
    resp->is_ndjson = 1;
    resp->json = 0;
    resp->ndjson = body;
    return (resp);
}

 /* postapi_query_append - append one value for a query key (arrays on repeat) */

static int
postapi_query_append(json_t *query, const char *key, const char *value)
{
    json_t *val;
    json_t *existing;
    json_t *arr;

    val = json_string(value);
    if (val == 0)
	return (-1);
    existing = json_object_get(query, key);
    if (existing == 0) {
	if (json_object_set_new(query, key, val) < 0) {
	    json_decref(val);
	    return (-1);
	}
	return (0);
    }
    if (json_is_array(existing)) {
	if (json_array_append_new(existing, val) < 0) {
	    json_decref(val);
	    return (-1);
	}
	return (0);
    }
    arr = json_array();
    if (arr == 0
	|| json_array_append_new(arr, json_incref(existing)) < 0
	|| json_array_append_new(arr, val) < 0) {
	json_decref(arr);
	json_decref(val);
	return (-1);
    }
    if (json_object_set_new(query, key, arr) < 0) {
	json_decref(arr);
	return (-1);
    }
    return (0);
}

 /* postapi_query_iter - collect query key/value pairs into a JSON object */

static enum MHD_Result
postapi_query_iter(void *cls, enum MHD_ValueKind kind,
		   const char *key, const char *value)
{
    json_t *query = (json_t *) cls;

    (void) kind;
    if (key == 0)
	return MHD_YES;
    if (value == 0)
	value = "";
    if (postapi_query_append(query, key, value) < 0)
	return MHD_NO;
    return MHD_YES;
}

 /* postapi_query_parse - build JSON object from the request query string */

json_t *
postapi_query_parse(struct MHD_Connection *connection)
{
    json_t *query;

    query = json_object();
    if (connection != 0)
	(void) MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND,
					 postapi_query_iter, query);
    return (query);
}

 /* postapi_query_free - release query object from postapi_query_parse */

void
postapi_query_free(json_t *query)
{
    if (query)
	json_decref(query);
}

 /* postapi_dispatch - route request to a controller */

POSTAPI_RESP *
postapi_dispatch(const char *url, const char *method, int authorized,
		         json_t *query, json_t *body)
{
    VSTRING *path_buf;
    const char *path;
    const char *slash;
    const char *controller;
    const char *action;
    size_t  ctrl_len;
    POSTAPI_CTRL_FN fn;
    POSTAPI_RESP *resp;
    int     n;

    path_buf = vstring_alloc(strlen(url) + 1);
    {
	const char *qmark = strchr(url, '?');

	if (qmark != 0)
	    vstring_strncpy(path_buf, url, qmark - url);
	else
	    vstring_strcpy(path_buf, url);
    }
    url = vstring_str(path_buf);

    if (strncmp(url, POSTAPI_API_PREFIX, POSTAPI_API_PREFIX_LEN) != 0) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    path = url + POSTAPI_API_PREFIX_LEN;
    while (*path == '/')
	path++;
    if (*path == 0) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    slash = strchr(path, '/');
    if (slash == 0 || slash[1] == 0) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    if (strchr(slash + 1, '/') != 0) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    controller = path;
    ctrl_len = (size_t) (slash - path);
    action = slash + 1;
    fn = 0;
    for (n = 0; postapi_controllers[n].name != 0; n++) {
	if (strlen(postapi_controllers[n].name) == ctrl_len
	    && strncmp(controller, postapi_controllers[n].name, ctrl_len) == 0) {
	    fn = postapi_controllers[n].dispatch;
	    break;
	}
    }
    if (fn == 0) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    resp = fn(authorized, method, action, query, body);
    vstring_free(path_buf);
    return (resp);
}

 /* postapi_send_response - queue MHD response from POSTAPI_RESP */

enum MHD_Result
postapi_send_response(struct MHD_Connection *connection, POSTAPI_RESP *resp)
{
    struct MHD_Response *mhd_resp;
    enum MHD_Result q;
    char   *dump;
    size_t  len;
    enum MHD_ResponseMemoryMode mem_mode;

    if (resp == 0)
	return MHD_NO;
    if (resp->is_ndjson) {
	if (resp->ndjson == 0) {
	    postapi_resp_free(resp);
	    return MHD_NO;
	}
	len = VSTRING_LEN(resp->ndjson);
	dump = vstring_export(resp->ndjson);
	resp->ndjson = 0;
	mem_mode = MHD_RESPMEM_MUST_FREE;
    } else {
	if (resp->json == 0) {
	    postapi_resp_free(resp);
	    return MHD_NO;
	}
	dump = json_dumps(resp->json, JSON_COMPACT);
	json_decref(resp->json);
	resp->json = 0;
	if (dump == 0) {
	    postapi_resp_free(resp);
	    return MHD_NO;
	}
	len = strlen(dump);
	mem_mode = MHD_RESPMEM_MUST_FREE;
    }
    mhd_resp = MHD_create_response_from_buffer(len, dump, mem_mode);
    if (mhd_resp == 0) {
	if (mem_mode == MHD_RESPMEM_MUST_FREE)
	    free(dump);
	postapi_resp_free(resp);
	return MHD_NO;
    }
    (void) MHD_add_response_header(mhd_resp, "Content-Type",
				  "application/json; charset=utf-8");
    (void) MHD_add_response_header(mhd_resp, "Connection", "close");
    q = MHD_queue_response(connection, resp->http_code, mhd_resp);
    MHD_destroy_response(mhd_resp);
    postapi_resp_free(resp);
    return (q);
}
