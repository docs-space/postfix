/*++
/* NAME
/*	postqueue 5h
/* SUMMARY
/*	postqueue internal interfaces
/* SYNOPSIS
/*	#include <postqueue.h>
/* DESCRIPTION
/* .nf

 /*
  * showq_compat.c
  */
extern void showq_compat(VSTREAM *);

 /*
  * showq_json.c
  */
extern void showq_json(VSTREAM *);
extern void showq_json_fp(VSTREAM *, VSTREAM *);

 /*
  * postqueue_api.c
  */
extern int postqueue_list_json(VSTREAM *);
extern int postqueue_list_json_by_queue(VSTREAM *, const char *);
extern int postqueue_list_json_by_id(VSTREAM *, const char *);
extern int postqueue_message_json_by_id(VSTREAM *, const char *,
				        int, int, int);

 /*
  * postqueue_queue_scan.c
  */
extern int postqueue_scan_queue_json(VSTREAM *, const char *, const char *, int);
extern int postqueue_scan_queue_json_by_id(VSTREAM *, const char *, const char *,
				           int);
extern int postqueue_scan_message_json_by_id(VSTREAM *, const char *,
					     const char *, int, int, int, int);

#define POSTQUEUE_ID_LOOKUP_NOT_FOUND	0
#define POSTQUEUE_ID_LOOKUP_FOUND	1
#define POSTQUEUE_ID_LOOKUP_DUPLICATE	2
#define POSTQUEUE_ID_LOOKUP_ERROR	-1

#define POSTQUEUE_MESSAGE_LOOKUP_NOT_FOUND	0
#define POSTQUEUE_MESSAGE_LOOKUP_FOUND		1
#define POSTQUEUE_MESSAGE_LOOKUP_DUPLICATE	2
#define POSTQUEUE_MESSAGE_LOOKUP_ERROR		-1

#define POSTQUEUE_DELETE_DELETED		1
#define POSTQUEUE_DELETE_NOT_FOUND		0
#define POSTQUEUE_DELETE_INVALID		-1
#define POSTQUEUE_DELETE_ERROR			-2

#define POSTQUEUE_CLEAR_OK			0
#define POSTQUEUE_CLEAR_INVALID			-1
#define POSTQUEUE_CLEAR_ERROR			-2

#define POSTQUEUE_HOLD_OK			1
#define POSTQUEUE_HOLD_NOT_FOUND		0
#define POSTQUEUE_HOLD_INVALID			-1
#define POSTQUEUE_HOLD_ERROR			-2

#define POSTQUEUE_RELEASE_OK			1
#define POSTQUEUE_RELEASE_NOT_FOUND		0
#define POSTQUEUE_RELEASE_INVALID		-1
#define POSTQUEUE_RELEASE_ERROR			-2

#define POSTQUEUE_FLUSH_OK			1
#define POSTQUEUE_FLUSH_NOT_FOUND		0
#define POSTQUEUE_FLUSH_INVALID			-1
#define POSTQUEUE_FLUSH_ERROR			-2

#define POSTQUEUE_FORCE_QUEUE_OK		0
#define POSTQUEUE_FORCE_QUEUE_INVALID		-1
#define POSTQUEUE_FORCE_QUEUE_ERROR		-2

#define POSTQUEUE_TRIGGER_OK			0
#define POSTQUEUE_TRIGGER_ERROR			-2

extern int postqueue_delete_by_id(const char *);
extern int postqueue_clear_queue(const char *);
extern int postqueue_hold_by_id(const char *);
extern int postqueue_release_by_id(const char *);
extern int postqueue_flush_by_id(const char *);
extern int postqueue_force_delivery_queue(const char *);
extern int postqueue_trigger_delivery(void);

/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*
/*	Wietse Venema
/*	Google, Inc.
/*	111 8th Avenue
/*	New York, NY 10011, USA
/*--*/
