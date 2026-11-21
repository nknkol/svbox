/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <string.h>

#include "path/binding_core.h"

static bool is_valid_canonical_prefix(const char *p)
{
    if (!p || p[0] != '/')
        return false;

    size_t len = strlen(p);
    if (len >= PATH_MAX)
        return false;
    if (len == 1)
        return true;
    if (p[len - 1] == '/')
        return false;

    const char *cur = p + 1;
    while (*cur) {
        if (*cur == '/')
            return false; /* double slash */
        const char *seg = cur;
        while (*cur && *cur != '/')
            cur++;
        size_t slen = (size_t)(cur - seg);
        if ((slen == 1 && seg[0] == '.') ||
            (slen == 2 && seg[0] == '.' && seg[1] == '.'))
            return false;
        if (*cur == '/')
            cur++;
    }
    return true;
}

bool binding_matches_core(const char *root, Side side, const char *prefix, const char *path)
{
    (void)root;
    (void)side;
    Comparison c = compare_paths(prefix, path);
    return c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX;
}

int binding_replace_core(char path[PATH_MAX], const char *from, const char *to)
{
    if (!path || !from || !to)
        return -EINVAL;

    size_t from_len = strlen(from);
    size_t to_len = strlen(to);
    size_t path_len = strlen(path);

    Comparison c = compare_paths2(from, from_len, path, path_len);
    if (c != PATHS_ARE_EQUAL && c != PATH1_IS_PREFIX)
        return 0;

    /* Determine suffix starting from '/' (or empty) after stripping `from`. */
    const char *suffix;
    size_t suffix_len;
    if (from_len == 1 && from[0] == '/') {
        if (path_len == 1) {
            suffix = "";
            suffix_len = 0;
        } else {
            suffix = path; /* includes leading '/' */
            suffix_len = path_len;
        }
    } else {
        suffix = path + from_len;
        suffix_len = path_len - from_len;
    }

    /* Special case: replacing onto "/" */
    if (to_len == 1 && to[0] == '/') {
        if (suffix_len == 0) {
            path[0] = '/';
            path[1] = '\0';
            return 1;
        }
        /* suffix begins with '/' */
        if (suffix_len >= PATH_MAX)
            return -ENAMETOOLONG;
        memmove(path, suffix, suffix_len + 1);
        return 1;
    }

    /* General case: `to` is a non-root canonical path without trailing slash. */
    size_t new_len = to_len + suffix_len;
    if (new_len >= PATH_MAX)
        return -ENAMETOOLONG;

    memmove(path + to_len, suffix, suffix_len + 1);
    memcpy(path, to, to_len);
    return 1;
}

int binding_table_validate(const BindingTable *table)
{
    if (!table || !is_valid_canonical_prefix(table->root))
        return -EINVAL;
    if (table->count > 0 && !table->entries)
        return -EINVAL;

    for (size_t i = 0; i < table->count; i++) {
        const char *g = table->entries[i].guest;
        const char *h = table->entries[i].host;
        if (!is_valid_canonical_prefix(g) || !is_valid_canonical_prefix(h))
            return -EINVAL;
        if (g[0] == '/' && g[1] == '\0')
            return -EINVAL; /* guest "/" belongs exclusively to table->root */
    }
    return 0;
}

int binding_table_mount_id(const BindingTable *table, const char *guest_path, size_t *mount_id)
{
    if (!table || !guest_path || !mount_id || guest_path[0] != '/')
        return -EINVAL;

    size_t path_len = strlen(guest_path);
    size_t best_id = 0;
    size_t best_len = 1; /* root "/" */

    for (size_t i = 0; i < table->count; i++) {
        const char *g = table->entries[i].guest;
        if (!g)
            continue;
        size_t glen = strlen(g);
        Comparison c = compare_paths2(g, glen, guest_path, path_len);
        if ((c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX) && glen >= best_len) {
            best_len = glen;
            best_id = i + 1;
        }
    }

    *mount_id = best_id;
    return 0;
}

int binding_table_map(const BindingTable *table, Side side, const char *in, char out[PATH_MAX])
{
    if (!table || !in || !out || in[0] != '/')
        return -EINVAL;

    size_t in_len = strlen(in);
    if (in_len >= PATH_MAX)
        return -ENAMETOOLONG;

    const char *from = NULL;
    const char *to = NULL;

    if (side == GUEST) {
        size_t id = 0;
        int rc = binding_table_mount_id(table, in, &id);
        if (rc < 0)
            return rc;
        if (id == 0) {
            from = "/";
            to = table->root;
        } else {
            from = table->entries[id - 1].guest;
            to = table->entries[id - 1].host;
        }
    } else if (side == HOST) {
        size_t best_len = 0;

        /* Candidate 0: root */
        if (table->root) {
            size_t rlen = strlen(table->root);
            Comparison c = compare_paths2(table->root, rlen, in, in_len);
            if (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX) {
                best_len = rlen;
                from = table->root;
                to = "/";
            }
        }

        /* Active (non-shadowed) bind entries */
        for (size_t i = 0; i < table->count; i++) {
            const char *g = table->entries[i].guest;
            const char *h = table->entries[i].host;
            if (!g || !h)
                continue;
            /* Skip entries shadowed by a later binding with the same guest target. */
            size_t owner = 0;
            if (binding_table_mount_id(table, g, &owner) < 0 || owner != i + 1)
                continue;
            size_t hlen = strlen(h);
            Comparison c = compare_paths2(h, hlen, in, in_len);
            if ((c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX) && hlen >= best_len) {
                best_len = hlen;
                from = h;
                to = g;
            }
        }

        if (!from)
            return -EXDEV;
    } else {
        return -EINVAL;
    }

    if (out != in)
        memcpy(out, in, in_len + 1);

    int rc = binding_replace_core(out, from, to);
    return rc < 0 ? rc : 0;
}
