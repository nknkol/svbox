/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "path/path_types.h"

Comparison compare_paths2(const char *path1, size_t len1, const char *path2, size_t len2)
{
    if (!path1 || !path2 || len1 == 0 || len2 == 0)
        return PATHS_ARE_NOT_COMPARABLE;
    if (path1[0] != '/' || path2[0] != '/')
        return PATHS_ARE_NOT_COMPARABLE;

    /* Root "/" is a prefix of every other absolute path. */
    if (len1 == 1)
        return len2 == 1 ? PATHS_ARE_EQUAL : PATH1_IS_PREFIX;
    if (len2 == 1)
        return PATH2_IS_PREFIX;

    size_t min_len = len1 < len2 ? len1 : len2;
    for (size_t i = 0; i < min_len; i++) {
        if (path1[i] != path2[i])
            return PATHS_ARE_NOT_COMPARABLE;
    }

    if (len1 == len2)
        return PATHS_ARE_EQUAL;
    if (len1 < len2)
        return path2[len1] == '/' ? PATH1_IS_PREFIX : PATHS_ARE_NOT_COMPARABLE;
    return path1[len2] == '/' ? PATH2_IS_PREFIX : PATHS_ARE_NOT_COMPARABLE;
}

Comparison compare_paths(const char *path1, const char *path2)
{
    if (!path1 || !path2)
        return PATHS_ARE_NOT_COMPARABLE;
    return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

int join_paths(int count, char result[PATH_MAX], ...)
{
    va_list ap;
    size_t out_len = 0;

    if (!result || count < 0)
        return -EINVAL;

    result[0] = '\0';
    va_start(ap, result);

    for (int i = 0; i < count; i++) {
        const char *part = va_arg(ap, const char *);
        if (!part || !part[0])
            continue;

        size_t part_len = strlen(part);
        bool is_last = (i == count - 1);

        if (out_len == 0) {
            if (part_len >= PATH_MAX) {
                va_end(ap);
                return -ENAMETOOLONG;
            }
            memcpy(result, part, part_len + 1);
            out_len = part_len;
            continue;
        }

        /* Trim redundant separator between previous segment and next segment. */
        while (out_len > 1 && result[out_len - 1] == '/')
            out_len--;

        const char *seg = part;
        size_t seg_len = part_len;
        while (seg_len > 0 && seg[0] == '/') {
            seg++;
            seg_len--;
        }

        if (seg_len == 0) {
            /* Trailing slash-only segment preserves a single trailing slash. */
            if (is_last && result[out_len - 1] != '/') {
                if (out_len + 1 >= PATH_MAX) {
                    va_end(ap);
                    return -ENAMETOOLONG;
                }
                result[out_len++] = '/';
                result[out_len] = '\0';
            }
            continue;
        }

        size_t need_slash = (result[out_len - 1] != '/') ? 1 : 0;
        if (out_len + need_slash + seg_len >= PATH_MAX) {
            va_end(ap);
            return -ENAMETOOLONG;
        }
        if (need_slash)
            result[out_len++] = '/';
        memcpy(result + out_len, seg, seg_len);
        out_len += seg_len;
        result[out_len] = '\0';
    }

    va_end(ap);
    return 0;
}
