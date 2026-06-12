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

struct tm *gnomint_gmtime (gint64 unixtime, struct tm *result)
{
	gint64 days, rem, z, era, doe, yoe, y, doy, mp, d, m;
	gint64 wday;
	// Days in the year before the start of each month (non-leap year).
	static const gint mdays_before[12] =
		{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

	// Split into whole days and the seconds within the day, handling
	// negative timestamps (pre-1970) with floored division.
	days = unixtime / 86400;
	rem = unixtime % 86400;
	if (rem < 0) {
		rem += 86400;
		days -= 1;
	}

	result->tm_hour = (gint) (rem / 3600);
	result->tm_min = (gint) ((rem % 3600) / 60);
	result->tm_sec = (gint) (rem % 60);

	// 1970-01-01 was a Thursday (tm_wday == 4).
	wday = (4 + (days % 7) + 7) % 7;
	result->tm_wday = (gint) wday;

	// Civil-from-days (Howard Hinnant's algorithm), shifting the epoch to
	// 0000-03-01 so that leap days fall at the end of the 400-year era.
	z = days + 719468;
	era = (z >= 0 ? z : z - 146096) / 146097;
	doe = z - era * 146097;                                   // [0, 146096]
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
	y = yoe + era * 400;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);            // [0, 365]
	mp = (5 * doy + 2) / 153;                                 // [0, 11]
	d = doy - (153 * mp + 2) / 5 + 1;                         // [1, 31]
	m = mp < 10 ? mp + 3 : mp - 9;                            // [1, 12]
	y += (m <= 2);

	result->tm_year = (gint) (y - 1900);
	result->tm_mon = (gint) (m - 1);
	result->tm_mday = (gint) d;

	// Day of the year, accounting for the leap day once March is reached.
	result->tm_yday = mdays_before[result->tm_mon] + (result->tm_mday - 1);
	if (result->tm_mon > 1 &&
	    ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
		result->tm_yday += 1;

	result->tm_isdst = 0;

	return result;
}

gboolean gnomint_time_display_is_uncertain (gint64 unixtime)
{
	// 64-bit time_t represents every realistic certificate date exactly.
	if (sizeof (time_t) >= 8)
		return FALSE;

	// 32-bit time_t: the representable range ends 2038-01-19 03:14:07 UTC.
	// A value within the final stretch before that ceiling, or wrapped to a
	// negative value, is the fingerprint of a later date that GnuTLS's
	// time_t getter could not represent. 2114380800 == 2037-01-01 UTC; any
	// date from then on is too close to the ceiling to be trusted here.
	return (unixtime < 0) || (unixtime >= 2114380800LL);
}
