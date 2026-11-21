/* SPDX-License-Identifier: MIT */
#ifndef SVBOX_RESOLVE_CORE_H
#define SVBOX_RESOLVE_CORE_H

#include "path/canon_core.h"

typedef struct {
    PathContext path;
    const char *cwd;
    int (*dirfd_guest)(void *opaque, int dirfd, char out[PATH_MAX]);
    int (*guest_to_host)(void *opaque, const char *guest, char host[PATH_MAX]);
    char (*scratch)[PATH_MAX];
} PathResolver;

int resolve_path_core(PathResolver *resolver, int dirfd, const char *user_path,
                      bool deref_final, char guest_out[PATH_MAX], char host_out[PATH_MAX]);

#endif /* SVBOX_RESOLVE_CORE_H */
