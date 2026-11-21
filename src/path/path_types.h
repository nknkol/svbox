/* SPDX-License-Identifier: MIT */
#ifndef SVBOX_PATH_TYPES_H
#define SVBOX_PATH_TYPES_H

#include <limits.h>
#ifndef PATH_MAX
#include <linux/limits.h>
#endif
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    REGULAR,
    SYMLINK,
} Type;

typedef enum {
    GUEST,
    HOST,
    PENDING,
} Side;

typedef struct {
    char path[PATH_MAX];
    size_t length;
    Side side;
} Path;

typedef enum {
    NOT_FINAL,
    FINAL_NORMAL,
    FINAL_SLASH,
    FINAL_DOT,
} Finality;

#define IS_FINAL(a) ((a) != NOT_FINAL)

typedef enum Comparison {
    PATHS_ARE_EQUAL,
    PATH1_IS_PREFIX,
    PATH2_IS_PREFIX,
    PATHS_ARE_NOT_COMPARABLE,
} Comparison;

int join_paths(int count, char result[PATH_MAX], ...);
Comparison compare_paths(const char *path1, const char *path2);
Comparison compare_paths2(const char *path1, size_t len1, const char *path2, size_t len2);

#endif /* SVBOX_PATH_TYPES_H */
