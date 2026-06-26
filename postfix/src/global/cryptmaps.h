#ifndef _CRYPTMAPS_H_INCLUDED_
#define _CRYPTMAPS_H_INCLUDED_

/*++
/* NAME
/*	cryptmaps 3h
/* SUMMARY
/*	expand {scheme}payload map lookup results
/* SYNOPSIS
/*	#include <cryptmaps.h>
/*
/*	void	cryptmaps_init()
/*
/*	const char *cryptmaps_expand(value)
/*	const char *value;
/* DESCRIPTION
/*	cryptmaps_expand() scans a map lookup result for
/*	\fB{scheme}payload\fR entries. PLAIN strips the macro,
/*	registered crypttypes (AES-128-CBC.HEX) are decrypted using
/*	\fBaccess_salt_maps\fR, and other schemes are copied unchanged.
/*
/*	The result is stored in memory that is overwritten upon
/*	each call. When the value contains no \fB{\fR character,
/*	the original pointer is returned.
/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/*--*/

extern void cryptmaps_init(void);
extern const char *cryptmaps_expand(const char *);

#endif
