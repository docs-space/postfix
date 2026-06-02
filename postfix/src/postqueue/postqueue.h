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
