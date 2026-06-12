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

#endif // _GNOMINT_TIME_H_
