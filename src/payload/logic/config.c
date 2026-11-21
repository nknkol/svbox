/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include "config.h"

_Static_assert(offsetof(payload_config_t, guard) == 0,
               "entry.S reads g_payload_config.guard at offset 0");

/* Filled in by the loader (located through the payload header). */
payload_config_t g_payload_config;
