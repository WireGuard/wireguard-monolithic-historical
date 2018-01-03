/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_COMPATASM_H
#define _WG_COMPATASM_H

#include <linux/linkage.h>
#include <linux/kconfig.h>

/* PaX compatibility */
#if defined(RAP_PLUGIN)
#undef ENTRY
#define ENTRY RAP_ENTRY
#endif

#endif /* _WG_COMPATASM_H */
