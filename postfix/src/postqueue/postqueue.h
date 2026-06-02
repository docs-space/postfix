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

 /*
  * postqueue_queue_scan.c
  */
extern int postqueue_scan_queue_json(VSTREAM *, const char *);

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
