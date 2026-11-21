/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <string.h>

#include "path/canon_core.h"

static void pop_last_component(char path[PATH_MAX])
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
        len--;
    while (len > 1 && path[len - 1] != '/')
        len--;
    if (len > 1 && path[len - 1] == '/')
        len--;
    if (len == 0) {
        path[0] = '/';
        path[1] = '\0';
        return;
    }
    path[len] = '\0';
}

static int append_component(char path[PATH_MAX], const char *comp, size_t comp_len,
                            size_t *prev_len_out)
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
        len--;
    path[len] = '\0';
    if (prev_len_out)
        *prev_len_out = len;

    size_t need_slash = (len > 0 && path[len - 1] != '/') ? 1 : 0;
    if (len + need_slash + comp_len >= PATH_MAX)
        return -ENAMETOOLONG;

    if (need_slash)
        path[len++] = '/';
    memcpy(path + len, comp, comp_len);
    len += comp_len;
    path[len] = '\0';
    return 0;
}

static int append_trailing_slash(char path[PATH_MAX])
{
    size_t len = strlen(path);
    if (len == 0) {
        path[0] = '/';
        path[1] = '\0';
        return 0;
    }
    if (path[len - 1] == '/')
        return 0;
    if (len + 1 >= PATH_MAX)
        return -ENAMETOOLONG;
    path[len] = '/';
    path[len + 1] = '\0';
    return 0;
}

static int canon_with_frame(PathContext *ctx, const char *user_path, bool deref_final,
                            char guest_path[PATH_MAX], unsigned int depth, PathFrame *frame)
{
    if (!ctx || !ctx->ops || !ctx->ops->lookup || !user_path || !guest_path)
        return -EINVAL;
    if (!user_path[0])
        return -ENOENT;
    if (strlen(user_path) >= PATH_MAX)
        return -ENAMETOOLONG;

    const char *cursor = user_path;
    if (cursor[0] == '/') {
        guest_path[0] = '/';
        guest_path[1] = '\0';
    } else if (guest_path[0] != '/') {
        return -EINVAL;
    }

    /* Pure slash path (e.g. "/" or "///"). */
    while (*cursor == '/')
        cursor++;
    if (!*cursor) {
        int rc = ctx->ops->lookup(ctx->opaque, FINAL_NORMAL, depth, guest_path, frame->host);
        return rc < 0 ? rc : 0;
    }

    while (*cursor) {
        const char *seg_start = cursor;
        while (*cursor && *cursor != '/')
            cursor++;
        size_t comp_len = (size_t)(cursor - seg_start);
        if (comp_len >= NAME_MAX)
            return -ENAMETOOLONG;

        bool had_slash = (*cursor == '/');
        while (*cursor == '/')
            cursor++;

        Finality finality;
        if (*cursor != '\0') {
            finality = NOT_FINAL;
        } else if (had_slash) {
            finality = FINAL_SLASH;
        } else if (comp_len == 1 && seg_start[0] == '.') {
            finality = FINAL_DOT;
        } else {
            finality = FINAL_NORMAL;
        }

        /* "." component */
        if (comp_len == 1 && seg_start[0] == '.') {
            if (finality == FINAL_DOT) {
                int rc = append_component(guest_path, ".", 1, NULL);
                if (rc < 0)
                    return rc;
                rc = ctx->ops->lookup(ctx->opaque, FINAL_DOT, depth, guest_path, frame->host);
                if (rc < 0)
                    return rc;
            } else if (finality == FINAL_SLASH) {
                int rc = append_trailing_slash(guest_path);
                if (rc < 0)
                    return rc;
                rc = ctx->ops->lookup(ctx->opaque, FINAL_SLASH, depth, guest_path, frame->host);
                if (rc < 0)
                    return rc;
            }
            continue;
        }

        /* ".." component */
        if (comp_len == 2 && seg_start[0] == '.' && seg_start[1] == '.') {
            pop_last_component(guest_path);
            if (finality == FINAL_SLASH) {
                int rc = append_trailing_slash(guest_path);
                if (rc < 0)
                    return rc;
            }
            continue;
        }

        memcpy(frame->component, seg_start, comp_len);
        frame->component[comp_len] = '\0';

        size_t parent_len = 0;
        int rc = append_component(guest_path, frame->component, comp_len, &parent_len);
        if (rc < 0)
            return rc;

        if (ctx->ops->respell)
            ctx->ops->respell(ctx->opaque, guest_path);

        int is_link = ctx->ops->lookup(ctx->opaque, finality, depth, guest_path, frame->host);
        if (is_link < 0)
            return is_link;

        if (is_link == 0) {
            if (finality == FINAL_SLASH) {
                rc = append_trailing_slash(guest_path);
                if (rc < 0)
                    return rc;
            }
            continue;
        }

        /* Component is a symbolic link. */
        if (finality == FINAL_NORMAL && !deref_final)
            continue;

        /* Restore parent guest path before evaluating symlink target. */
        if (parent_len == 0) {
            guest_path[0] = '/';
            guest_path[1] = '\0';
        } else {
            guest_path[parent_len] = '\0';
        }

        /* Check /proc magic link hook if under /proc. */
        int proc_action = FS_LINK_DEFAULT;
        if (ctx->ops->proc_link) {
            Comparison proc_cmp = compare_paths("/proc", guest_path);
            if (proc_cmp == PATHS_ARE_EQUAL || proc_cmp == PATH1_IS_PREFIX) {
                proc_action = ctx->ops->proc_link(ctx->opaque, frame->scratch,
                                                  guest_path, frame->component, proc_cmp);
                if (proc_action < 0)
                    return proc_action;
            }
        }

        if (proc_action == FS_LINK_KEEP) {
            size_t keep_len = strlen(frame->scratch);
            if (keep_len >= PATH_MAX)
                return -ENAMETOOLONG;
            memcpy(guest_path, frame->scratch, keep_len + 1);
            if (finality == FINAL_SLASH) {
                rc = append_trailing_slash(guest_path);
                if (rc < 0)
                    return rc;
            }
            continue;
        }

        if (proc_action == FS_LINK_DEFAULT) {
            if (!ctx->ops->readlink)
                return -EOPNOTSUPP;
            int n = ctx->ops->readlink(ctx->opaque, frame->host, frame->scratch, PATH_MAX - 1);
            if (n < 0)
                return n;
            if (n == 0)
                return -ENOENT;
            if ((size_t)n >= PATH_MAX - 1)
                return -ENAMETOOLONG;
            frame->scratch[n] = '\0';

            if (ctx->ops->detranslate) {
                rc = ctx->ops->detranslate(ctx->opaque, frame->scratch, frame->host);
                if (rc < 0)
                    return rc;
            }
        }

        /* Follow symlink target recursively. */
        bool follow_target = (finality != FINAL_NORMAL) ? true : deref_final;
        rc = canonicalize_core(ctx, frame->scratch, follow_target, guest_path, depth + 1);
        if (rc < 0)
            return rc;

        if (finality == FINAL_SLASH) {
            rc = append_trailing_slash(guest_path);
            if (rc < 0)
                return rc;
            /* Verify resolved target is a directory when trailing slash was given. */
            rc = ctx->ops->lookup(ctx->opaque, FINAL_SLASH, depth + 1, guest_path, frame->host);
            if (rc < 0)
                return rc;
        }
    }

    return 0;
}

int canonicalize_core(PathContext *ctx, const char *user_path, bool deref_final,
                      char guest_path[PATH_MAX], unsigned int depth)
{
    if (depth >= CANON_LEVELS)
        return -ELOOP;

    if (ctx && ctx->frames && depth < ctx->frame_count)
        return canon_with_frame(ctx, user_path, deref_final, guest_path, depth,
                                &ctx->frames[depth]);

    if (ctx && ctx->deep) {
        PathFrame *extra = ctx->deep(ctx->opaque);
        if (!extra)
            return -ENOMEM;
        return canon_with_frame(ctx, user_path, deref_final, guest_path, depth,
                                &extra[depth - ctx->frame_count]);
    }

    PathFrame stack_frame;
    return canon_with_frame(ctx, user_path, deref_final, guest_path, depth, &stack_frame);
}
