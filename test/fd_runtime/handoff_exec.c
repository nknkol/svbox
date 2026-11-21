/* SPDX-License-Identifier: MIT */
/* Test helper: launch svbox as a child loader via --__handoff-fd with
 * controlled svbox_handoff_t fields (for fd_state restore & revalidation tests).
 * Usage:
 *   handoff_exec <svbox> <fd_state> [options...] -- <target> [arg...]
 *   handoff_exec <svbox> <fd_state> <target> [arg...]   (shorthand)
 * Options:
 *   --root DIR
 *   -v HOST:GUEST
 *   --policy <d/r/w string>
 *   --guard track|observe|paths|files|access
 *   --revalidate-fds
 *   --exec-target PATH
 *   --exec-path PATH
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "config.h"

static void copy_str(char *dst, size_t cap, const char *src)
{
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 4)
        return 2;
    const char *loader = argv[1];
    int state_fd = atoi(argv[2]);

    static svbox_handoff_t h;
    memset(&h, 0, sizeof(h));
    h.magic = SVBOX_HANDOFF_MAGIC;
    h.version = SVBOX_HANDOFF_VERSION;
    h.size = sizeof(h);
    h.cfg.mode = CONFIG_MODE_COMPAT;
    h.cfg.guard = GUARD_TRACK;
    h.cfg.fake_group_count = -1;
    h.cfg.fd_state = state_fd;
    h.cfg.loader_fd = -1;
    h.cfg.mount_table_fd = -1;
    h.cfg.owner_db_fd = -1;
    copy_str(h.cfg.loader_path, sizeof(h.cfg.loader_path), loader);
    h.exec_fd = -1;
    h.exec_interp_fd = -1;

    int i = 3;
    while (i < argc) {
        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        }
        if (argv[i][0] != '-')
            break;
        if (!strcmp(argv[i], "--root") && i + 1 < argc) {
            h.cfg.mode = CONFIG_MODE_CONTAINER;
            copy_str(h.cfg.root, sizeof(h.cfg.root), argv[++i]);
        } else if (!strcmp(argv[i], "-v") && i + 1 < argc) {
            const char *spec = argv[++i];
            const char *c = strchr(spec, ':');
            if (!c || h.cfg.bind_count >= CONFIG_MAX_BINDS)
                return 2;
            struct bind_entry *b = &h.cfg.binds[h.cfg.bind_count++];
            size_t len = (size_t)(c - spec);
            if (len >= sizeof(b->dst))
                len = sizeof(b->dst) - 1;
            memcpy(b->dst, spec, len);
            b->dst[len] = '\0';
            copy_str(b->src, sizeof(b->src), c + 1);
        } else if (!strcmp(argv[i], "--policy") && i + 1 < argc) {
            copy_str(h.cfg.mount_access_observe, sizeof(h.cfg.mount_access_observe), argv[++i]);
        } else if (!strcmp(argv[i], "--guard") && i + 1 < argc) {
            const char *g = argv[++i];
            if (!strcmp(g, "track")) h.cfg.guard = GUARD_TRACK;
            else if (!strcmp(g, "observe")) h.cfg.guard = GUARD_OBSERVE;
            else if (!strcmp(g, "paths")) h.cfg.guard = GUARD_PATHS;
            else if (!strcmp(g, "files")) h.cfg.guard = GUARD_FILES;
            else if (!strcmp(g, "access")) h.cfg.guard = GUARD_READS;
            else return 2;
        } else if (!strcmp(argv[i], "--revalidate-fds")) {
            h.cfg.revalidate_file_fds = 1;
        } else if (!strcmp(argv[i], "--exec-target") && i + 1 < argc) {
            copy_str(h.exec_target, sizeof(h.exec_target), argv[++i]);
        } else if (!strcmp(argv[i], "--exec-path") && i + 1 < argc) {
            copy_str(h.exec_path, sizeof(h.exec_path), argv[++i]);
        } else {
            return 2;
        }
        i++;
    }
    if (i >= argc)
        return 2;
    const char *target = argv[i];
    if (!h.exec_target[0])
        copy_str(h.exec_target, sizeof(h.exec_target), target);
    if (!h.exec_path[0])
        copy_str(h.exec_path, sizeof(h.exec_path), target);
    if (!h.exec_exe[0])
        copy_str(h.exec_exe, sizeof(h.exec_exe), h.exec_path[0] == '/' ? h.exec_path : target);

    int hfd = memfd_create("test-handoff", 0);
    if (hfd < 0)
        return 3;
    const char *p = (const char *)&h;
    size_t written = 0;
    while (written < sizeof(h)) {
        ssize_t n = write(hfd, p + written, sizeof(h) - written);
        if (n <= 0)
            return 4;
        written += (size_t)n;
    }
    if (lseek(hfd, 0, SEEK_SET) != 0)
        return 5;

    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", hfd);
    char **child = calloc((size_t)(argc - i + 5), sizeof(char *));
    int pos = 0;
    child[pos++] = (char *)loader;
    child[pos++] = SVBOX_CHILD_HANDOFF_FD;
    child[pos++] = fd_str;
    child[pos++] = "--";
    for (; i < argc; i++)
        child[pos++] = argv[i];
    child[pos] = NULL;
    execv(loader, child);
    return 127;
}
