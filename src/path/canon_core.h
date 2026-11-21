/* SPDX-License-Identifier: MIT */
#ifndef SVBOX_CANON_CORE_H
#define SVBOX_CANON_CORE_H

#include <limits.h>
#include <stdbool.h>
#include <sys/param.h>

#include "path/path_types.h"

enum {
    FS_LINK_DEFAULT = 0,
    FS_LINK_CANONICALIZE = 1,
    FS_LINK_KEEP = 2,
};

typedef struct {
    int (*lookup)(void *opaque, Finality finality, unsigned int level,
                  const char *guest_path, char *host_path);
    int (*readlink)(void *opaque, const char *host_path, char *out, size_t size);
    int (*detranslate)(void *opaque, char *link_target, const char *referrer_host);
    int (*proc_link)(void *opaque, char *out, const char *parent_guest,
                     const char *component, Comparison comparison);
    void (*respell)(void *opaque, char *guest_path);
} PathOps;

typedef struct {
    char scratch[PATH_MAX];
    char host[PATH_MAX];
    char component[NAME_MAX];
} PathFrame;

#ifndef MAXSYMLINKS
#define MAXSYMLINKS 40
#endif
#define CANON_LEVELS (MAXSYMLINKS + 1)

typedef struct {
    void *opaque;
    const PathOps *ops;
    PathFrame *frames;
    unsigned int frame_count;
    PathFrame *(*deep)(void *opaque);
} PathContext;

int canonicalize_core(PathContext *ctx, const char *user_path, bool deref_final,
                      char guest_path[PATH_MAX], unsigned int depth);

#endif /* SVBOX_CANON_CORE_H */
