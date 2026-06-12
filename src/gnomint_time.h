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

#ifndef _GNOMINT_TIME_H_
#define _GNOMINT_TIME_H_

#include <glib.h>
#include <time.h>

// The latest instant representable in this platform's time_t.
//
// Where time_t is 64-bit (amd64, win64, and 32-bit ports built with
// _TIME_BITS=64 such as armhf) this is effectively unlimited. Where time_t is
// 32-bit (notably i386, kept on 32-bit time_t for ABI compatibility by every
// major distribution) this is the Year-2038 limit: 2038-01-19 03:14:07 UTC.
// On those platforms the limit is not just gnoMint's — the system GnuTLS is
// built with the same 32-bit time_t and its X.509 validity API
// (gnutls_x509_crt_set_expiration_time(), which takes a time_t) cannot encode
// a later date either. See the note in configure.ac and issue #86.
time_t gnomint_time_max (void);

// mktime() wrapper that reports overflow instead of returning a silent garbage
// value. On a 32-bit-time_t platform, asking for a certificate that expires
// after 2038 makes mktime() fail (returns (time_t)-1, errno EOVERFLOW); the
// historical code stored that -1 and produced a wrong expiration date with no
// warning. This wrapper detects that case, clamps the result to
// gnomint_time_max(), and sets *overflowed (when non-NULL) to TRUE so the
// caller can warn the user. On success *overflowed is set to FALSE.
time_t gnomint_mktime_checked (struct tm *tm, gboolean *overflowed);

// 64-bit-safe replacement for gmtime_r(). Converts a Unix timestamp (seconds
// since 1970-01-01 UTC, carried as a gint64) into a broken-down UTC time.
//
// Unlike gmtime()/gmtime_r(), which take a time_t and therefore truncate at
// 2038 on 32-bit-time_t platforms (i386), this works for any year because it
// computes the calendar fields directly from the 64-bit value. gnoMint stores
// certificate dates as 64-bit integers in its database, so on i386 a date past
// 2038 read straight from the database can still be displayed correctly even
// though it could not have been produced through GnuTLS's time_t-based API on
// that platform. The result pointer is returned for convenience; it always
// succeeds (no errno). tm_isdst is set to 0 (UTC has no DST).
struct tm *gnomint_gmtime (gint64 unixtime, struct tm *result);

#endif // _GNOMINT_TIME_H_
