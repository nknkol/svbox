/* SPDX-License-Identifier: MIT */
#ifndef SVBOX_BINDING_CORE_H
#define SVBOX_BINDING_CORE_H

#include "path/path_types.h"

bool binding_matches_core(const char *root, Side side, const char *prefix, const char *path);
int binding_replace_core(char path[PATH_MAX], const char *from, const char *to);

typedef struct {
    const char *guest;
    const char *host;
} PathBinding;

typedef struct {
    const char *root;
    const PathBinding *entries;
    size_t count;
} BindingTable;

int binding_table_validate(const BindingTable *table);
int binding_table_mount_id(const BindingTable *table, const char *guest_path, size_t *mount_id);
int binding_table_map(const BindingTable *table, Side side, const char *in, char out[PATH_MAX]);

#endif /* SVBOX_BINDING_CORE_H */
