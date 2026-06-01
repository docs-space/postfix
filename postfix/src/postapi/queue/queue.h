#ifndef _POSTAPI_QUEUE_H_INCLUDED_
#define _POSTAPI_QUEUE_H_INCLUDED_

/*++
/* NAME
/*	postapi_queue 3h
/* SUMMARY
/*	PostAPI Queue controller
/*--*/

#include <jansson.h>
#include <postapi_dispatch.h>

extern POSTAPI_RESP *queue_dispatch(int authorized, const char *method,
				            const char *action, json_t *query,
				            json_t *body);

#endif
