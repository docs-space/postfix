#ifndef _AUTH_KEY_H_INCLUDED_
#define _AUTH_KEY_H_INCLUDED_

/*++
/* NAME
/*	auth_key 3h
/* SUMMARY
/*	postapi access token validation
/* SYNOPSIS
/*	#include "auth_key.h"
/*
/*	int	auth_key_validate(map_value, bearer_token, salt_maps)
/*	const char *map_value;
/*	const char *bearer_token;
/*	MAPS *salt_maps;
/* DESCRIPTION
/*	auth_key_validate() parses one or more credentials from a
/*	Postfix maps lookup result.  Each credential has the form
/*	\fB{algorithm}payload\fR.  Supported algorithms are PLAIN,
/*	SHA1.HEX and AES-256-CBC (compatible with mail.admin.api).
/*
/*	The function returns AUTH_KEY_OK when any credential matches
/*	the bearer token, AUTH_KEY_MISMATCH when none match, and
/*	AUTH_KEY_FORMAT_ERR on parse failures.
/*--*/

#include <maps.h>

#define AUTH_KEY_OK		0
#define AUTH_KEY_MISMATCH	1
#define AUTH_KEY_FORMAT_ERR	2

extern int auth_key_validate(const char *map_value, const char *bearer_token,
			             MAPS *salt_maps);

#endif
