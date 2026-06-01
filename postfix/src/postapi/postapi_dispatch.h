#ifndef _POSTAPI_DISPATCH_H_INCLUDED_
#define _POSTAPI_DISPATCH_H_INCLUDED_

/*++
/* NAME
/*	postapi_dispatch 3h
/* SUMMARY
/*	PostAPI request router and HTTP response helpers
/* SYNOPSIS
/*	#include <postapi_dispatch.h>
/* DESCRIPTION
/*	Route /api/v1/<Controller>/<Action> to controller handlers and
/*	send JSON or raw NDJSON HTTP responses via libmicrohttpd.
/*
/*	postapi_query_parse() reads MHD_GET_ARGUMENT_KIND into a JSON
/*	object (duplicate keys become JSON arrays of values). The \fIurl\fR
/*	path is taken without a \fB?\fR suffix before routing.
/*--*/

#include <microhttpd.h>
#include <jansson.h>
#include <vstring.h>

typedef struct POSTAPI_RESP POSTAPI_RESP;

struct POSTAPI_RESP {
    unsigned int http_code;
    int     is_ndjson;
    json_t *json;
    VSTRING *ndjson;
};

extern json_t *postapi_query_parse(struct MHD_Connection *connection);
extern void postapi_query_free(json_t *query);

extern POSTAPI_RESP *postapi_dispatch(const char *url, const char *method,
				          int authorized, json_t *query,
				          json_t *body);
extern void postapi_resp_free(POSTAPI_RESP *resp);

extern POSTAPI_RESP *postapi_resp_json(unsigned int code, json_t *obj);
extern POSTAPI_RESP *postapi_resp_ndjson(unsigned int code, VSTRING *body);

extern enum MHD_Result postapi_send_response(struct MHD_Connection *connection,
				             POSTAPI_RESP *resp);

#endif
