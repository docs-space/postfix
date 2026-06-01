/*++
/* NAME
/*	postapi_postconf 3
/* SUMMARY
/*	PostAPI PostConf controller
/*--*/

#include <sys_defs.h>
#include <string.h>

#include <jansson.h>

#include <vstream.h>
#include <vstring.h>
#include <postconf.h>

#include "postapi_dispatch.h"
#include "postconf.h"

 /* postconf_dispatch - GET /api/v1/PostConf/All */

POSTAPI_RESP *
postconf_dispatch(int authorized, const char *method, const char *action,
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
