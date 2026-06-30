#ifndef _XSASL_INTERNAL_H_INCLUDED_
#define _XSASL_INTERNAL_H_INCLUDED_

/*++
/* NAME
/*	xsasl_internal 3h
/* SUMMARY
/*	Postfix auth daemon SASL plug-in
/* SYNOPSIS
/*	#include <xsasl_internal.h>
/* DESCRIPTION
/* .nf

 /*
  * XSASL library.
  */
#include <xsasl.h>

#if defined(USE_SASL_AUTH) && defined(USE_INTERNAL_SASL)

#define XSASL_TYPE_INTERNAL "internal"

extern XSASL_SERVER_IMPL *xsasl_internal_server_init(const char *, const char *);

#endif

#endif
