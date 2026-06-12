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
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#include <config.h>

#include <errno.h>

#include "gnomint_time.h"

time_t gnomint_time_max (void)
{
	if (sizeof (time_t) >= 8)
		// Far beyond any certificate's lifetime; the clamp below never
		// actually triggers on 64-bit-time_t platforms.
		return (time_t) 0x7FFFFFFFFFFFFFFFLL;

	// 32-bit signed time_t: 2038-01-19 03:14:07 UTC.
	return (time_t) 0x7FFFFFFF;
}

time_t gnomint_mktime_checked (struct tm *tm, gboolean *overflowed)
{
	time_t result;

	errno = 0;
	result = mktime (tm);

	// Certificate expiration is always a future date, so the only way
	// mktime() returns (time_t)-1 here is genuine overflow of a 32-bit
	// time_t (errno EOVERFLOW), not the legitimate timestamp -1.
	if (result == (time_t) -1) {
		if (overflowed)
			*overflowed = TRUE;
		return gnomint_time_max ();
	}

	if (overflowed)
		*overflowed = FALSE;

	return result;
}
