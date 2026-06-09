/*++
/* NAME
/*	postapi_postconf 3
/* SUMMARY
/*	PostAPI PostConf controller
/*--*/

#include <sys_defs.h>
#include <string.h>

#include <jansson.h>

#include <argv.h>
#include <msg.h>
#include <mymalloc.h>
#include <vstream.h>
#include <vstring.h>
#include <postconf.h>

#include "postapi_dispatch.h"
#include "postapi.h"
#include "postconf.h"

static int postconf_json_value_to_string(json_t *value, VSTRING *buf)
{
    if (json_is_string(value)) {
	vstring_strcpy(buf, json_string_value(value));
	return (0);
    }
    if (json_is_boolean(value)) {
	vstring_strcpy(buf, json_is_true(value) ? "yes" : "no");
	return (0);
    }
    if (json_is_integer(value)) {
	vstring_sprintf(buf, "%lld", (long long) json_integer_value(value));
	return (0);
    }
    if (json_is_real(value)) {
	vstring_sprintf(buf, "%g", json_real_value(value));
	return (0);
    }
    return (-1);
}

static POSTAPI_RESP *
postconf_update_config(json_t *body)
{
    const char *key;
    json_t *value;
    json_t *applied;
    ARGV   *pairs;
    VSTRING *err;
    VSTRING *value_buf;
    VSTRING *pair_buf;
    void   *iter;
    json_t *applied_val;

    // #region agent log
    msg_info("postapi: dbg[H1]: postconf_update_config enter body_size=%lu",
	     body != 0 && json_is_object(body) ?
	     (unsigned long) json_object_size(body) : 0UL);
    // #endregion

    if (!postapi_config_allowlist_configured())
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    // #region agent log
    msg_info("postapi: dbg[H1a]: allowlist configured");
    // #endregion
    if (body == 0 || !json_is_object(body) || json_object_size(body) == 0)
	return (postapi_resp_json(400,
				  json_pack("{s:s}", "error", "invalid_body")));

    // #region agent log
    msg_info("postapi: dbg[H1b]: body ok");
    // #endregion
    pairs = argv_alloc(10);
    value_buf = vstring_alloc(64);
    pair_buf = vstring_alloc(128);
    applied = json_object();
    err = vstring_alloc(256);
    if (applied == 0) {
	argv_free(pairs);
	vstring_free(value_buf);
	vstring_free(pair_buf);
	vstring_free(err);
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    }

    // #region agent log
    msg_info("postapi: dbg[H1c]: alloc ok");
    // #endregion
    iter = json_object_iter(body);
    while (iter) {
	key = json_object_iter_key(iter);
	value = json_object_iter_value(iter);
	// #region agent log
	msg_info("postapi: dbg[H1d]: key=%s allowed=%s",
		 key != 0 ? key : "(null)",
		 postapi_config_allowed(key) ? "yes" : "no");
	// #endregion
	if (!postapi_config_allowed(key)) {
	    json_decref(applied);
	    argv_free(pairs);
	    vstring_free(value_buf);
	    vstring_free(pair_buf);
	    vstring_free(err);
		return (postapi_resp_json(400,
				      json_pack("{s:s,s:s}", "error",
						"forbidden_parameter",
						"parameter",
						key != 0 ? key : "")));
	}
	if (postconf_json_value_to_string(value, value_buf) < 0) {
	    json_decref(applied);
	    argv_free(pairs);
	    vstring_free(value_buf);
	    vstring_free(pair_buf);
	    vstring_free(err);
	    return (postapi_resp_json(400,
				      json_pack("{s:s,s:s}", "error",
						"invalid_parameter_value",
						"parameter",
						key != 0 ? key : "")));
	}
	// #region agent log
	msg_info("postapi: dbg[H1e]: value=%s", vstring_str(value_buf));
	// #endregion
	vstring_sprintf(pair_buf, "%s=%s", key, vstring_str(value_buf));
	// #region agent log
	msg_info("postapi: dbg[H1f]: pair=%s", vstring_str(pair_buf));
	// #endregion
	argv_add(pairs, vstring_str(pair_buf), (char *) 0);
	// #region agent log
	msg_info("postapi: dbg[H1g]: argv argc=%d", pairs->argc);
	// #endregion
	applied_val = json_string(vstring_str(value_buf));
	// #region agent log
	msg_info("postapi: dbg[H1h]: applied_val=%p", (void *) applied_val);
	// #endregion
	if (applied_val == 0
	    || json_object_set_new(applied, key, applied_val) < 0) {
	    if (applied_val != 0)
		json_decref(applied_val);
	    json_decref(applied);
	    argv_free(pairs);
	    vstring_free(value_buf);
	    vstring_free(pair_buf);
	    vstring_free(err);
	    return (postapi_resp_json(503,
				      json_pack("{s:s}", "error",
						"service_unavailable")));
	}
	// #region agent log
	msg_info("postapi: dbg[H1i]: applied set ok");
	// #endregion
	iter = json_object_iter_next(body, iter);
    }

    // #region agent log
    msg_info("postapi: dbg[H2]: before validate argc=%d", pairs->argc);
    // #endregion
    if (msg_verbose)
	msg_info("postapi: PostConf: validate start");
    if (postconf_validate_overrides(pairs, err) < 0) {
	POSTAPI_RESP *resp;

	if (msg_verbose)
	    msg_info("postapi: PostConf: validate failed: %s",
		     vstring_str(err));
	resp = postapi_resp_json(400,
				 json_pack("{s:s,s:s}", "error",
					   "configuration_check_failed",
					   "detail", vstring_str(err)));
	json_decref(applied);
	argv_free(pairs);
	vstring_free(value_buf);
	vstring_free(pair_buf);
	vstring_free(err);
	return (resp);
    }
    if (msg_verbose)
	msg_info("postapi: PostConf: validate ok");
    if (msg_verbose)
	msg_info("postapi: PostConf: apply start");
    if (postconf_apply_overrides(pairs) < 0) {
	if (msg_verbose)
	    msg_info("postapi: PostConf: apply failed");
	json_decref(applied);
	argv_free(pairs);
	vstring_free(value_buf);
	vstring_free(pair_buf);
	vstring_free(err);
	return (postapi_resp_json(503,
				  json_pack("{s:s}", "error",
					    "service_unavailable")));
    }
    if (msg_verbose)
	msg_info("postapi: PostConf: apply ok, reload scheduled");
    postconf_request_reload();

    // #region agent log
    msg_info("postapi: dbg[H5]: apply ok");
    // #endregion
    argv_free(pairs);
    vstring_free(value_buf);
    vstring_free(pair_buf);
    vstring_free(err);
    return (postapi_resp_json(200, applied));
}

 /* postconf_dispatch - PostConf endpoints */

POSTAPI_RESP *
postconf_dispatch(int authorized, const char *method, const char *action,
	          json_t *query, json_t *body)
{
    VSTREAM *mem;
    VSTRING *buf;

    if (!authorized)
	return (postapi_resp_json(401,
				 json_pack("{s:s}", "error", "unauthorized")));

    if (*action == 0) {
	if (strcmp(method, "POST") == 0)
	    return (postconf_update_config(body));
	return (postapi_resp_json(405,
				  json_pack("{s:s}", "error",
					    "method_not_allowed")));
    }

    (void) query;
    if (strcmp(action, "All") != 0)
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    if (strcmp(method, "GET") != 0)
	return (postapi_resp_json(405,
				 json_pack("{s:s}", "error", "method_not_allowed")));

    buf = vstring_alloc(4096);
    if ((mem = vstream_memopen(buf, O_WRONLY)) == 0) {
	vstring_free(buf);
	return (postapi_resp_json(503,
				 json_pack("{s:s}", "error", "service_unavailable")));
    }
    postconf_list_json(mem);
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
					       "invalid_parameter_json")));
	return (postapi_resp_json(200, arr));
    }
}
