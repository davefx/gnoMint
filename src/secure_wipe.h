//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2026 David Marín Carreño <davefx@gmail.com>
//
//  This file is part of gnoMint.
//
//  gnoMint is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.

#ifndef _GNOMINT_SECURE_WIPE_H_
#define _GNOMINT_SECURE_WIPE_H_

#include <stddef.h>

// Overwrite a buffer holding sensitive data (a password or private key) with
// zeros in a way the compiler may not optimise away.
//
// A plain memset() to a buffer that is about to be freed is "dead" and can be
// removed by the optimiser, leaving the secret in heap/stack memory (and
// potentially in swap). Writing through a volatile pointer prevents that
// elision and is portable to every platform gnoMint targets, including MinGW
// (where explicit_bzero() is unavailable).
static inline void gnomint_secure_wipe (void *buffer, size_t length)
{
	volatile unsigned char *p = (volatile unsigned char *) buffer;

	if (!buffer)
		return;
	while (length--)
		*p++ = 0;
}

#endif // _GNOMINT_SECURE_WIPE_H_
