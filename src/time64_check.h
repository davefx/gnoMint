//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2009 David Marín Carreño <davefx@gmail.com>
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

#ifndef _TIME64_CHECK_H_
#define _TIME64_CHECK_H_

#include <time.h>

// Compile-time check that time_t is 64-bit, to prevent Y2K38 problems so
// gnoMint can handle certificates expiring after 2038-01-19 03:14:07 UTC.
//
// This is only enforced where 64-bit time_t is actually the ABI: either the
// platform is natively 64-bit time_t (e.g. amd64, where _TIME_BITS is left
// undefined and sizeof(time_t) == 8 anyway) or the toolchain has explicitly
// opted in with _TIME_BITS=64 (e.g. the armhf port). On legacy 32-bit-time_t
// platforms such as i386 the distribution toolchain keeps time_t at 32 bits for
// ABI compatibility with the system libraries; forcing 64-bit there would break
// the GnuTLS ABI (see issue #86 and the note in configure.ac), so we must NOT
// fail the build in that case.
#if defined(_TIME_BITS) && _TIME_BITS == 64
#if defined(__GNUC__) || defined(__clang__)
_Static_assert(sizeof(time_t) >= 8,
    "_TIME_BITS=64 was requested but time_t is not 64-bit on this platform.");
#elif defined(_MSC_VER)
// MSVC static assertion
static_assert(sizeof(time_t) >= 8,
    "_TIME_BITS=64 was requested but time_t is not 64-bit on this platform.");
#endif
#endif

#endif // _TIME64_CHECK_H_
