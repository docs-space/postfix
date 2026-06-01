/*++
/* NAME
/*	postapi_service 3
/* SUMMARY
/*	PostAPI Service controller
/*--*/

#include <sys_defs.h>
#include <string.h>

#include <jansson.h>

#include "postapi_dispatch.h"
#include "postapi.h"
#include "service.h"

 /* service_dispatch - GET /api/v1/Service */

POSTAPI_RESP *
service_dispatch(int authorized, const char *method, const char *action,
		 json_t *query, json_t *body)
{
    (void) query;
    (void) body;

    if (!authorized)
	return (postapi_resp_json(401,
				 json_pack("{s:s}", "error", "unauthorized")));
    if (*action != 0)
	return (postapi_resp_json(404, json_pack("{s:s}", "error", "not_found")));
    if (strcmp(method, "GET") != 0)
	return (postapi_resp_json(405,
				 json_pack("{s:s}", "error", "method_not_allowed")));

    return (postapi_resp_json(200,
			       json_pack("{s:s}", "instance_name",
					 postapi_get_instance_name())));
}
