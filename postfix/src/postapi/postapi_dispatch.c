/*++
/* NAME
/*	postapi_dispatch 3
/* SUMMARY
/*	PostAPI request router
/*--*/

#include <sys_defs.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>

#include <microhttpd.h>
#include <jansson.h>

#include <msg.h>
#include <mymalloc.h>
#include <vstring.h>

#include "postapi_dispatch.h"
#include "queue/queue.h"
#include "postconf/postconf.h"
#include "service/service.h"

#define POSTAPI_API_PREFIX	"/api/v1"
#define POSTAPI_API_PREFIX_LEN	(sizeof(POSTAPI_API_PREFIX) - 1)

typedef POSTAPI_RESP *(*POSTAPI_CTRL_FN) (int, const char *, const char *,
			                           json_t *, json_t *);

static jmp_buf postapi_ctrl_jmp_buf;

 /* postapi_ctrl_longjmp - trap msg_fatal/msg_panic from a controller */

static NORETURN postapi_ctrl_longjmp(int code)
{
    longjmp(postapi_ctrl_jmp_buf, code);
}

 /* postapi_call_controller - invoke controller; return 5xx on failure */

static POSTAPI_RESP *
postapi_call_controller(const char *controller, POSTAPI_CTRL_FN fn,
		        int authorized, const char *method, const char *action,
		        json_t *query, json_t *body)
{
    POSTAPI_RESP *resp;
    int     except;

    msg_set_longjmp_action(postapi_ctrl_longjmp);
    except = setjmp(postapi_ctrl_jmp_buf);
    if (except == 0) {
	resp = fn(authorized, method, action, query, body);
	msg_set_longjmp_action(0);
	if (resp == 0) {
	    msg_warn("postapi: controller %s returned no response", controller);
	    return (postapi_resp_json(500,
				      json_pack("{s:s}", "error",
						"internal_server_error")));
	}
	return (resp);
    }
    msg_set_longjmp_action(0);
    msg_warn("postapi: controller %s aborted: %s", controller,
	     except == MSG_LONGJMP_PANIC ? "panic" : "fatal");
    return (postapi_resp_json(except == MSG_LONGJMP_PANIC ? 500 : 503,
			      json_pack("{s:s}", "error",
					except == MSG_LONGJMP_PANIC ?
					"internal_server_error" :
					"service_unavailable")));
}

static struct {
    const char *name;
    POSTAPI_CTRL_FN dispatch;
} postapi_controllers[] = {
    {"Queue", queue_dispatch},
    {"PostConf", postconf_dispatch},
    {"Service", service_dispatch},
    {0, 0},
};

 /* postapi_route_parse_path - split /api/v1/<Controller>[/<Action>] */

static int
postapi_route_parse_path(const char *url, VSTRING *path_buf,
			         const char **controller, size_t *controller_len,
			         const char **action)
{
    const char *path;
    const char *slash;

    {
	const char *qmark = strchr(url, '?');

	if (qmark != 0)
	    vstring_strncpy(path_buf, url, qmark - url);
	else
	    vstring_strcpy(path_buf, url);
    }
    url = vstring_str(path_buf);

    if (strncmp(url, POSTAPI_API_PREFIX, POSTAPI_API_PREFIX_LEN) != 0)
	return (0);
    path = url + POSTAPI_API_PREFIX_LEN;
    while (*path == '/')
	path++;
    if (*path == 0)
	return (0);
    slash = strchr(path, '/');
    if (slash == 0) {
	*controller = path;
	*controller_len = strlen(path);
	*action = "";
	return (1);
    }
    if (slash[1] == 0)
	return (0);
    *controller = path;
    *controller_len = (size_t) (slash - path);
    *action = slash + 1;
    if (*action == 0)
	return (0);
    return (1);
}

 /* postapi_route_lookup - map controller name to handler */

static int
postapi_route_lookup(const char *controller, size_t controller_len,
		             POSTAPI_CTRL_FN *fn_out, const char **ctrl_name_out)
{
    int     n;

    for (n = 0; postapi_controllers[n].name != 0; n++) {
	if (strlen(postapi_controllers[n].name) == controller_len
	    && strncmp(controller, postapi_controllers[n].name,
		       controller_len) == 0) {
	    if (fn_out)
		*fn_out = postapi_controllers[n].dispatch;
	    if (ctrl_name_out)
		*ctrl_name_out = postapi_controllers[n].name;
	    return (1);
	}
    }
    return (0);
}

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

 /* postapi_ndjson_to_json_array - parse JSON Lines into one JSON array */

json_t *
postapi_ndjson_to_json_array(const char *data, ssize_t len)
{
    const char *cp;
    const char *end;
    json_t *arr;
    json_error_t jerr;

    if (data == 0 || len < 0)
	return (0);
    arr = json_array();
    if (arr == 0)
	return (0);
    cp = data;
    end = data + len;
    while (cp < end) {
	const char *nl;
	size_t  line_len;
	json_t *obj;

	while (cp < end && (*cp == '\n' || *cp == '\r'))
	    cp++;
	if (cp >= end)
	    break;
	nl = memchr(cp, '\n', (size_t) (end - cp));
	line_len = nl ? (size_t) (nl - cp) : (size_t) (end - cp);
	while (line_len > 0
	       && (cp[line_len - 1] == '\r' || cp[line_len - 1] == '\n'))
	    line_len--;
	if (line_len == 0) {
	    cp = nl ? nl + 1 : end;
	    continue;
	}
	obj = json_loadb(cp, line_len, 0, &jerr);
	if (obj == 0) {
	    json_decref(arr);
	    return (0);
	}
	if (json_array_append_new(arr, obj) < 0) {
	    json_decref(obj);
	    json_decref(arr);
	    return (0);
	}
	cp = nl ? nl + 1 : end;
    }
    return (arr);
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
    const char *controller;
    const char *action;
    size_t  ctrl_len;
    POSTAPI_CTRL_FN fn;
    POSTAPI_RESP *resp;
    const char *ctrl_name;

    path_buf = vstring_alloc(strlen(url) + 1);
    if (!postapi_route_parse_path(url, path_buf, &controller, &ctrl_len, &action)) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    if (!postapi_route_lookup(controller, ctrl_len, &fn, &ctrl_name)) {
	vstring_free(path_buf);
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    }
    resp = postapi_call_controller(ctrl_name, fn, authorized, method, action,
				  query, body);
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
