/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "path/resolve_core.h"

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

static int resolve_with_bufs(PathResolver *r, int dirfd, const char *user_path,
                             bool deref_final, char guest_out[PATH_MAX],
                             char host_out[PATH_MAX], char base_buf[PATH_MAX])
{
    if (!r || !user_path || !guest_out || !host_out || !r->guest_to_host)
        return -EINVAL;
    if (!user_path[0])
        return -ENOENT;
    if (strlen(user_path) >= PATH_MAX)
        return -ENAMETOOLONG;

    if (user_path[0] == '/') {
        guest_out[0] = '/';
        guest_out[1] = '\0';
    } else if (dirfd == AT_FDCWD) {
        const char *cwd = (r->cwd && r->cwd[0] == '/') ? r->cwd : "/";
        size_t cwd_len = strlen(cwd);
        if (cwd_len >= PATH_MAX)
            return -ENAMETOOLONG;
        memcpy(guest_out, cwd, cwd_len + 1);
    } else {
        if (!r->dirfd_guest)
            return -EBADF;
        int rc = r->dirfd_guest(r->path.opaque, dirfd, base_buf);
        if (rc < 0)
            return rc;
        size_t blen = strlen(base_buf);
        if (blen == 0 || base_buf[0] != '/')
            return -EINVAL;
        if (blen >= PATH_MAX)
            return -ENAMETOOLONG;
        memcpy(guest_out, base_buf, blen + 1);
    }

    int rc = canonicalize_core(&r->path, user_path, deref_final, guest_out, 0);
    if (rc < 0)
        return rc;

    return r->guest_to_host(r->path.opaque, guest_out, host_out);
}

int resolve_path_core(PathResolver *resolver, int dirfd, const char *user_path,
                      bool deref_final, char guest_out[PATH_MAX], char host_out[PATH_MAX])
{
    if (resolver && resolver->scratch)
        return resolve_with_bufs(resolver, dirfd, user_path, deref_final,
                                 guest_out, host_out, resolver->scratch[0]);

    char stack_base[PATH_MAX];
    return resolve_with_bufs(resolver, dirfd, user_path, deref_final,
                             guest_out, host_out, stack_base);
}
