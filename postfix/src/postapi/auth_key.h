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
/*	int	auth_key_validate(map_value, bearer_token)
/*	const char *map_value;
/*	const char *bearer_token;
/* DESCRIPTION
/*	auth_key_validate() compares a bearer token against one or more
/*	credentials from a maps lookup result (after cryptmaps_expand).
/*	Each comma-separated segment is either a plaintext credential or
/*	a \fB{SHA1.HEX}\fR digest of the bearer token.
/*--*/

#define AUTH_KEY_OK		0
#define AUTH_KEY_MISMATCH	1
#define AUTH_KEY_FORMAT_ERR	2

extern int auth_key_validate(const char *map_value, const char *bearer_token);

#endif
