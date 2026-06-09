#ifndef _POSTAPI_INSTANCE_H_INCLUDED_
#define _POSTAPI_INSTANCE_H_INCLUDED_

/*++
/* NAME
/*	postapi_instance 3h
/* SUMMARY
/*	PostAPI instance identity from main.cf
/*--*/

const char *postapi_get_instance_name(void);
int     postapi_config_allowed(const char *name);
int     postapi_config_allowlist_configured(void);

#endif
