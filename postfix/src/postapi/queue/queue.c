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
#include <mail_queue.h>
#include <postqueue.h>

#include "postapi_dispatch.h"
#include "queue.h"

static int queue_query_parse_bool(json_t *query, const char *key, int defval,
			          int *out)
{
    const json_t *value;
    const char *text;

    value = query ? json_object_get(query, key) : 0;
    if (value == 0) {
	*out = defval;
	return (0);
    }
    if (!json_is_string(value))
	return (-1);
    text = json_string_value(value);
    if (text == 0)
	return (-1);
    if (strcmp(text, "true") == 0) {
	*out = 1;
	return (0);
    }
    if (strcmp(text, "false") == 0) {
	*out = 0;
	return (0);
    }
    return (-1);
}

 /* queue_delete_messages - DELETE body: JSON array of queue ids */

static POSTAPI_RESP *
queue_delete_messages(json_t *body)
{
    json_t *deleted;
    size_t  n;
    size_t  count;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    deleted = json_array();
    if (deleted == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    count = json_array_size(body);
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_id;
	int     status;

	if (!json_is_string(entry)) {
	    json_decref(deleted);
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error",
						"invalid_body")));
	}
	queue_id = json_string_value(entry);
	status = postqueue_delete_by_id(queue_id);
	if (status == POSTQUEUE_DELETE_DELETED) {
	    if (json_array_append_new(deleted, json_string(queue_id)) < 0) {
		json_decref(deleted);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "service_unavailable")));
	    }
	} else if (status == POSTQUEUE_DELETE_ERROR) {
	    json_decref(deleted);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    return (postapi_resp_json(200, deleted));
}

 /* queue_clear_queues - DELETE body: JSON array of queue names to clear */

static POSTAPI_RESP *
queue_clear_queues(json_t *body)
{
    json_t *cleared;
    size_t  n;
    size_t  count;
    int     status;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    cleared = json_array();
    if (cleared == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    count = json_array_size(body);
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_name;

	if (!json_is_string(entry))
	    continue;
	queue_name = json_string_value(entry);
	if (queue_name == 0 || *queue_name == 0)
	    continue;
	status = postqueue_clear_queue(queue_name);
	if (status == POSTQUEUE_CLEAR_INVALID)
	    continue;
	if (status == POSTQUEUE_CLEAR_ERROR) {
	    json_decref(cleared);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (json_array_append_new(cleared, json_string(queue_name)) < 0) {
	    json_decref(cleared);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    return (postapi_resp_json(200, cleared));
}

 /* queue_patch_messages - PATCH body: JSON array of queue ids */

static POSTAPI_RESP *
queue_patch_messages(json_t *body, int (*apply)(const char *))
{
    json_t *done;
    size_t  n;
    size_t  count;
    int     status;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    done = json_array();
    if (done == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    count = json_array_size(body);
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_id;

	if (!json_is_string(entry)) {
	    json_decref(done);
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error",
						"invalid_body")));
	}
	queue_id = json_string_value(entry);
	if (queue_id == 0 || *queue_id == 0)
	    continue;
	status = apply(queue_id);
	if (status == POSTQUEUE_HOLD_ERROR || status == POSTQUEUE_RELEASE_ERROR) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (status != POSTQUEUE_HOLD_OK && status != POSTQUEUE_RELEASE_OK)
	    continue;
	if (json_array_append_new(done, json_string(queue_id)) < 0) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    return (postapi_resp_json(200, done));
}

 /* queue_force_delivery_messages - PATCH Message/ForceDelivery */

static POSTAPI_RESP *
queue_force_delivery_messages(json_t *body)
{
    json_t *done;
    size_t  n;
    size_t  count;
    int     status;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    count = json_array_size(body);
    if (count == 0) {
	done = json_array();
	if (done == 0)
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	if (postqueue_trigger_delivery() != POSTQUEUE_TRIGGER_OK) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	return (postapi_resp_json(200, done));
    }
    done = json_array();
    if (done == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_id;

	if (!json_is_string(entry)) {
	    json_decref(done);
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error",
						"invalid_body")));
	}
	queue_id = json_string_value(entry);
	if (queue_id == 0 || *queue_id == 0)
	    continue;
	status = postqueue_flush_by_id(queue_id);
	if (status == POSTQUEUE_FLUSH_ERROR) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (status != POSTQUEUE_FLUSH_OK)
	    continue;
	if (json_array_append_new(done, json_string(queue_id)) < 0) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    if (postqueue_trigger_delivery() != POSTQUEUE_TRIGGER_OK) {
	json_decref(done);
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    }
    return (postapi_resp_json(200, done));
}

 /* queue_force_delivery_queues - PATCH Queue/ForceDelivery */

static POSTAPI_RESP *
queue_force_delivery_queues(json_t *body)
{
    json_t *done;
    size_t  n;
    size_t  count;
    int     status;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    count = json_array_size(body);
    if (count == 0) {
	done = json_array();
	if (done == 0)
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	if (postqueue_trigger_delivery() != POSTQUEUE_TRIGGER_OK) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	return (postapi_resp_json(200, done));
    }
    done = json_array();
    if (done == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_name;

	if (!json_is_string(entry))
	    continue;
	queue_name = json_string_value(entry);
	if (queue_name == 0 || *queue_name == 0)
	    continue;
	status = postqueue_force_delivery_queue(queue_name);
	if (status == POSTQUEUE_FORCE_QUEUE_INVALID)
	    continue;
	if (status == POSTQUEUE_FORCE_QUEUE_ERROR) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (json_array_append_new(done, json_string(queue_name)) < 0) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    if (postqueue_trigger_delivery() != POSTQUEUE_TRIGGER_OK) {
	json_decref(done);
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    }
    return (postapi_resp_json(200, done));
}

 /* queue_requeue_messages - POST body: JSON array of queue ids */

static POSTAPI_RESP *
queue_requeue_messages(json_t *body)
{
    json_t *done;
    size_t  n;
    size_t  count;
    int     status;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    done = json_array();
    if (done == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    count = json_array_size(body);
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_id;

	if (!json_is_string(entry)) {
	    json_decref(done);
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error",
						"invalid_body")));
	}
	queue_id = json_string_value(entry);
	if (queue_id == 0 || *queue_id == 0)
	    continue;
	status = postqueue_requeue_by_id(queue_id);
	if (status == POSTQUEUE_REQUEUE_ERROR) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (status != POSTQUEUE_REQUEUE_OK)
	    continue;
	if (json_array_append_new(done, json_string(queue_id)) < 0) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    return (postapi_resp_json(200, done));
}

 /* queue_requeue_queues - POST body: JSON array of queue names or [] */

static POSTAPI_RESP *
queue_requeue_queues(json_t *body)
{
    static const char *all_requeue_queues[] = {
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_DEFERRED,
	MAIL_QUEUE_HOLD,
	0,
    };
    json_t *done;
    size_t  n;
    size_t  count;
    int     status;
    const char **qpp;

    if (body == 0 || !json_is_array(body))
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));
    done = json_array();
    if (done == 0)
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    count = json_array_size(body);
    if (count == 0) {
	for (qpp = all_requeue_queues; *qpp != 0; qpp++) {
	    status = postqueue_requeue_queue(*qpp);
	    if (status == POSTQUEUE_REQUEUE_QUEUE_ERROR) {
		json_decref(done);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "service_unavailable")));
	    }
	    if (status != POSTQUEUE_REQUEUE_QUEUE_OK)
		continue;
	    if (json_array_append_new(done, json_string(*qpp)) < 0) {
		json_decref(done);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "service_unavailable")));
	    }
	}
	return (postapi_resp_json(200, done));
    }
    for (n = 0; n < count; n++) {
	json_t *entry = json_array_get(body, n);
	const char *queue_name;

	if (!json_is_string(entry))
	    continue;
	queue_name = json_string_value(entry);
	if (queue_name == 0 || *queue_name == 0)
	    continue;
	status = postqueue_requeue_queue(queue_name);
	if (status == POSTQUEUE_REQUEUE_QUEUE_INVALID)
	    continue;
	if (status == POSTQUEUE_REQUEUE_QUEUE_ERROR) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	if (json_array_append_new(done, json_string(queue_name)) < 0) {
	    json_decref(done);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
    }
    return (postapi_resp_json(200, done));
}

 /* queue_dispatch - Queue endpoints */

POSTAPI_RESP *
queue_dispatch(int authorized, const char *method, const char *action,
	               json_t *query, json_t *body)
{
    VSTREAM *mem;
    VSTRING *buf;

    if (!authorized)
	return (postapi_resp_json(401,
				 json_pack("{s:s}", "error", "unauthorized")));
    if (*action == 0) {
	const json_t *id_value;
	const char *queue_id;
	int     lookup_status;

	if (strcmp(method, "DELETE") == 0)
	    return (queue_clear_queues(body));
	if (strcmp(method, "GET") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	if (query == 0 || !json_is_object(query))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	id_value = json_object_get(query, "id");
	if (id_value == 0 || !json_is_string(id_value))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	queue_id = json_string_value(id_value);
	if (queue_id == 0 || *queue_id == 0)
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	buf = vstring_alloc(256);
	if ((mem = vstream_memopen(buf, O_WRONLY)) == 0) {
	    vstring_free(buf);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error", "service_unavailable")));
	}
	lookup_status = postqueue_list_json_by_id(mem, queue_id);
	if (lookup_status == POSTQUEUE_ID_LOOKUP_ERROR) {
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
	if (lookup_status == POSTQUEUE_ID_LOOKUP_DUPLICATE) {
	    vstring_free(buf);
	    return (postapi_resp_json(409,
				      json_pack("{s:s}", "error", "duplicate_queue_id")));
	}
	if (lookup_status == POSTQUEUE_ID_LOOKUP_NOT_FOUND) {
	    vstring_free(buf);
	    return (postapi_resp_ndjson(204, vstring_alloc(1)));
	}
	{
	    json_t *arr;
	    json_t *item;

	    arr = postapi_ndjson_to_json_array(vstring_str(buf), VSTRING_LEN(buf));
	    vstring_free(buf);
	    if (arr == 0 || json_array_size(arr) != 1) {
		if (arr)
		    json_decref(arr);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "invalid_queue_json")));
	    }
	    item = json_incref(json_array_get(arr, 0));
	    json_decref(arr);
	    return (postapi_resp_json(200, item));
	}
    } else if (strcmp(action, "Requeuing") == 0) {
	if (strcmp(method, "POST") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_requeue_queues(body));
    } else if (strcmp(action, "Message/Requeuing") == 0) {
	if (strcmp(method, "POST") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_requeue_messages(body));
    } else if (strcmp(action, "ForceDelivery") == 0) {
	if (strcmp(method, "PATCH") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_force_delivery_queues(body));
    } else if (strcmp(action, "Message/ForceDelivery") == 0) {
	if (strcmp(method, "PATCH") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_force_delivery_messages(body));
    } else if (strcmp(action, "Message/Hold") == 0) {
	if (strcmp(method, "PATCH") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_patch_messages(body, postqueue_hold_by_id));
    } else if (strcmp(action, "Message/UnHold") == 0) {
	if (strcmp(method, "PATCH") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	return (queue_patch_messages(body, postqueue_release_by_id));
    } else if (strcmp(action, "Message") == 0) {
	const json_t *id_value;
	const char *queue_id;
	int     include_envelope;
	int     include_headers;
	int     include_body;
	int     lookup_status;

	if (strcmp(method, "DELETE") == 0)
	    return (queue_delete_messages(body));
	if (strcmp(method, "GET") != 0)
	    return (postapi_resp_json(405,
				      json_pack("{s:s}", "error", "method_not_allowed")));
	if (query == 0 || !json_is_object(query))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	id_value = json_object_get(query, "id");
	if (id_value == 0 || !json_is_string(id_value))
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	queue_id = json_string_value(id_value);
	if (queue_id == 0 || *queue_id == 0)
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "missing_id")));
	if (queue_query_parse_bool(query, "include_envelope", 1,
				   &include_envelope) < 0
	    || queue_query_parse_bool(query, "include_headers", 1,
				      &include_headers) < 0
	    || queue_query_parse_bool(query, "include_body", 1,
				      &include_body) < 0)
	    return (postapi_resp_json(400,
				      json_pack("{s:s}", "error", "invalid_query")));
	buf = vstring_alloc(256);
	if ((mem = vstream_memopen(buf, O_WRONLY)) == 0) {
	    vstring_free(buf);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error", "service_unavailable")));
	}
	lookup_status = postqueue_message_json_by_id(mem, queue_id,
						     include_envelope,
						     include_headers,
						     include_body);
	if (lookup_status == POSTQUEUE_MESSAGE_LOOKUP_ERROR) {
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
	if (lookup_status == POSTQUEUE_MESSAGE_LOOKUP_DUPLICATE) {
	    vstring_free(buf);
	    return (postapi_resp_json(409,
				      json_pack("{s:s}", "error", "duplicate_queue_id")));
	}
	if (lookup_status == POSTQUEUE_MESSAGE_LOOKUP_NOT_FOUND) {
	    vstring_free(buf);
	    return (postapi_resp_ndjson(204, vstring_alloc(1)));
	}
	{
	    json_t *arr;
	    json_t *item;

	    arr = postapi_ndjson_to_json_array(vstring_str(buf), VSTRING_LEN(buf));
	    vstring_free(buf);
	    if (arr == 0 || json_array_size(arr) != 1) {
		if (arr)
		    json_decref(arr);
		return (postapi_resp_json(503,
					  json_pack("{s:s}", "error",
						    "invalid_queue_json")));
	    }
	    item = json_incref(json_array_get(arr, 0));
	    json_decref(arr);
	    return (postapi_resp_json(200, item));
	}
    } else if (strcmp(action, "All") == 0) {
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
