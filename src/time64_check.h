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

// Compile-time check to ensure time_t is 64-bit to prevent Y2K38 problems
// This ensures gnoMint can handle certificates expiring after 2038-01-19 03:14:07 UTC
#if defined(__GNUC__) || defined(__clang__)
_Static_assert(sizeof(time_t) >= 8, 
    "time_t must be at least 64 bits to avoid Y2K38 problem. "
    "Please ensure _TIME_BITS=64 and _FILE_OFFSET_BITS=64 are defined.");
#endif

#endif // _TIME64_CHECK_H_
