#ifndef _POSTAPI_SERVICE_H_INCLUDED_
#define _POSTAPI_SERVICE_H_INCLUDED_

/*++
/* NAME
/*	postapi_service 3h
/* SUMMARY
/*	PostAPI Service controller
/*--*/

#include <jansson.h>
#include <postapi_dispatch.h>

extern POSTAPI_RESP *service_dispatch(int authorized, const char *method,
				      const char *action, json_t *query,
				      json_t *body);

#endif
