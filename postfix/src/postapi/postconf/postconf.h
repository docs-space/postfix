#ifndef _POSTAPI_POSTCONF_CTRL_H_INCLUDED_
#define _POSTAPI_POSTCONF_CTRL_H_INCLUDED_

/*++
/* NAME
/*	postapi_postconf 3h
/* SUMMARY
/*	PostAPI PostConf controller
/*--*/

#include <jansson.h>
#include <postapi_dispatch.h>

extern POSTAPI_RESP *postconf_dispatch(int authorized, const char *method,
				               const char *action, json_t *query,
				               json_t *body);

#endif
