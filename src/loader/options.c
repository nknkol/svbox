/* SPDX-License-Identifier: MIT */
/* Command line parser and internal binary child-exec handoff reader.
 * Options end at "--" or at the first non-option, which is the program to run.
 * Every invalid option or malformed handoff is fatal. */
#include <asm/unistd.h>
#include "loader.h"
#include "vdev_proto.h"

static int is(const char *arg, const char *name)
{
	size_t n = z_strlen(name);
	return z_strncmp(arg, name, n + 1) == 0;
}

static const char *value(int argc, char **argv, int *i)
{
	if (*i + 1 >= argc || !argv[*i + 1][0])
		z_errx(1, "missing value for %s", argv[*i]);
	return argv[++*i];
}

static unsigned long number(const char *s, unsigned long max, const char *what)
{
	unsigned long v = 0;
	if (!*s)
		z_errx(1, "invalid %s", what);
	for (; *s; s++) {
		if (*s < '0' || *s > '9' || v > (max - (unsigned long)(*s - '0')) / 10)
			z_errx(1, "invalid %s", what);
		v = v * 10 + (unsigned long)(*s - '0');
	}
	return v;
}

/* "u:u:...": unsigned 32-bit values separated by sep. */
static int numbers(const char *s, char sep, uint32_t *out, int max, int exact)
{
	int count = 0;
	for (;;) {
		unsigned long long v = 0;
		const char *start = s;
		while (*s >= '0' && *s <= '9' && v <= 0xffffffffull)
			v = v * 10 + (unsigned)(*s++ - '0');
		if (s == start || v > 0xffffffffull || count == max || (*s && *s != sep))
			return -1;
		out[count++] = (uint32_t)v;
		if (!*s)
			break;
		s++;
	}
	return exact && count != exact ? -1 : count;
}

static uint64_t parse_cpuset(const char *s)
{
	uint64_t mask = 0;
	if (!*s)
		z_errx(1, "invalid --cpuset value");
	for (;;) {
		unsigned long lo = 0, hi = 0;
		const char *start = s;
		while (*s >= '0' && *s <= '9') {
			lo = lo * 10 + (unsigned long)(*s++ - '0');
			if (lo >= 64)
				z_errx(1, "invalid --cpuset cpu index (expect 0..63)");
		}
		if (s == start)
			z_errx(1, "invalid --cpuset syntax");
		hi = lo;
		if (*s == '-') {
			s++;
			const char *hstart = s;
			hi = 0;
			while (*s >= '0' && *s <= '9') {
				hi = hi * 10 + (unsigned long)(*s++ - '0');
				if (hi >= 64)
					z_errx(1, "invalid --cpuset cpu index (expect 0..63)");
			}
			if (s == hstart || hi < lo)
				z_errx(1, "invalid --cpuset range");
		}
		for (unsigned long c = lo; c <= hi; c++)
			mask |= (1ull << c);
		if (!*s)
			break;
		if (*s != ',')
			z_errx(1, "invalid --cpuset syntax");
		s++;
	}
	if (!mask)
		z_errx(1, "empty --cpuset mask");
	return mask;
}

static int32_t parse_nice(const char *s)
{
	int neg = 0;
	if (*s == '-') {
		neg = 1;
		s++;
	} else if (*s == '+') {
		s++;
	}
	unsigned long v = number(s, 20ul, "--nice value");
	int32_t res = neg ? -(int32_t)v : (int32_t)v;
	if (res < -20 || res > 19)
		z_errx(1, "invalid --nice value (expect -20..19)");
	return res;
}

static char parse_access_mode(const char *s, const char *what)
{
	if (is(s, "rw"))
		return 'w';
	if (is(s, "ro"))
		return 'r';
	if (is(s, "deny"))
		return 'd';
	z_errx(1, "invalid %s %s (expect rw|ro|deny)", what, s);
	return 'w';
}

static int parse_guard_level(const char *s)
{
	if (is(s, "none"))
		return GUARD_NONE;
	if (is(s, "track"))
		return GUARD_TRACK;
	if (is(s, "observe"))
		return GUARD_OBSERVE;
	if (is(s, "paths"))
		return GUARD_PATHS;
	if (is(s, "files"))
		return GUARD_FILES;
	if (is(s, "access"))
		return GUARD_READS;
	z_errx(1, "invalid --guard level %s (expect none|track|observe|paths|files|access)", s);
	return GUARD_NONE;
}

static void add_bind(payload_config_t *cfg, char *bind_modes, const char *spec)
{
	const char *c1 = z_strchr(spec, ':');
	if (!c1 || c1 == spec || !c1[1])
		z_errx(1, "--bind needs HOST:GUEST[:rw|ro|deny]");
	if (cfg->bind_count >= CONFIG_MAX_BINDS)
		z_errx(1, "too many bind mounts (at most %d)", CONFIG_MAX_BINDS);

	char mode = 'w';
	const char *guest_start = c1 + 1;
	size_t guest_len;
	const char *c2 = z_strchr(guest_start, ':');
	if (c2) {
		if (c2 == guest_start || !c2[1] || z_strchr(c2 + 1, ':'))
			z_errx(1, "invalid --bind specification %s (expect HOST:GUEST[:rw|ro|deny])", spec);
		mode = parse_access_mode(c2 + 1, "bind mode");
		guest_len = (size_t)(c2 - guest_start);
	} else {
		guest_len = z_strlen(guest_start);
	}

	int idx = cfg->bind_count++;
	struct bind_entry *b = &cfg->binds[idx];
	copy_substr(b->dst, CONFIG_MAX_PATH, spec, (size_t)(c1 - spec));
	copy_substr(b->src, CONFIG_MAX_PATH, guest_start, guest_len);
	bind_modes[idx] = mode;
}

static void add_lower(payload_config_t *cfg, const char *spec)
{
	if (cfg->lower_count >= CONFIG_MAX_LOWERS)
		z_errx(1, "too many --lower layers (at most %d)", CONFIG_MAX_LOWERS);
	const char *colon = z_strchr(spec, ':');
	int idx = cfg->lower_count++;
	if (colon) {
		size_t dir_len = (size_t)(colon - spec);
		const char *img = colon + 1;
		if (!dir_len || spec[0] != '/' || dir_len >= CONFIG_MAX_PATH ||
		    !img[0] || img[0] != '/' || z_strlen(img) >= CONFIG_MAX_PATH ||
		    z_strchr(img, ':'))
			z_errx(1, "--lower needs DIR[:IMAGE] with absolute host paths");
		copy_substr(cfg->lower[idx], CONFIG_MAX_PATH, spec, dir_len);
		copy_cstr(cfg->lower_image[idx], CONFIG_MAX_PATH, img);
	} else {
		if (spec[0] != '/' || z_strlen(spec) >= CONFIG_MAX_PATH)
			z_errx(1, "--lower needs an absolute host directory");
		copy_cstr(cfg->lower[idx], CONFIG_MAX_PATH, spec);
	}
}

/* --pass-fd N: the object open at N now (refused when N is not open or a
 * number the runtime holds); repeats of a number count once. */
static void pass_fd(payload_config_t *cfg, const char *v)
{
	unsigned long n = number(v, 2147483647ul, "--pass-fd value (an open FD number)");
	if (n >= CONFIG_RESERVED_FD_MIN)
		z_errx(1, "--pass-fd %s: FDs from %d up are the runtime's own", v, CONFIG_RESERVED_FD_MIN);
	for (int k = 0; k < cfg->passed_count; k++)
		if (cfg->passed[k].fd == (int32_t)n)
			return;
	struct stat st;
	long flags = z_syscall(__NR_fcntl, (long)n, 3 /* F_GETFL */, 0, 0, 0, 0);
	if (flags < 0 || z_syscall(__NR_fstat, (long)n, (long)&st, 0, 0, 0, 0) < 0)
		z_errx(1, "--pass-fd %s: not an open FD", v);
	if (cfg->passed_count >= CONFIG_MAX_PASSED_FDS)
		z_errx(1, "too many --pass-fd (at most %d)", CONFIG_MAX_PASSED_FDS);
	struct passed_fd *p = &cfg->passed[cfg->passed_count++];
	p->fd = (int32_t)n;
	p->flags = (uint32_t)flags & (3u /* O_ACCMODE */ | 02000u /* O_APPEND */);
	p->dev = st.st_dev;
	p->ino = st.st_ino;
}

static int has_nul(const char *s, size_t cap)
{
	for (size_t i = 0; i < cap; i++)
		if (!s[i])
			return 1;
	return 0;
}

/* Static storage for child handoff strings pointed to by loader_options. */
static svbox_handoff_t g_handoff;

static void read_handoff(int fd, payload_config_t *cfg, struct loader_options *opt)
{
	char *buf = (char *)&g_handoff;
	size_t total = 0;
	while (total < sizeof(g_handoff)) {
		ssize_t n = z_read(fd, buf + total, sizeof(g_handoff) - total);
		if (n <= 0) {
			z_close(fd);
			z_errx(1, "invalid child handoff payload");
		}
		total += (size_t)n;
	}
	char extra;
	ssize_t tail = z_read(fd, &extra, 1);
	z_close(fd);
	if (tail != 0)
		z_errx(1, "invalid child handoff size");

	if (g_handoff.magic != SVBOX_HANDOFF_MAGIC ||
	    g_handoff.version != SVBOX_HANDOFF_VERSION ||
	    g_handoff.size != sizeof(svbox_handoff_t))
		z_errx(1, "invalid child handoff header");

	const payload_config_t *hc = &g_handoff.cfg;
	if ((hc->mode != CONFIG_MODE_COMPAT && hc->mode != CONFIG_MODE_CONTAINER) ||
	    hc->guard < GUARD_NONE || hc->guard > GUARD_READS ||
	    hc->log_level < LOG_LEVEL_NONE || hc->log_level > LOG_LEVEL_DEBUG ||
	    hc->bind_count < 0 || hc->bind_count > CONFIG_MAX_BINDS ||
	    hc->lower_count < 0 || hc->lower_count > CONFIG_MAX_LOWERS ||
	    hc->owner_count < 0 || hc->owner_count > CONFIG_OWNERS ||
	    hc->passed_count < 0 || hc->passed_count > CONFIG_MAX_PASSED_FDS ||
	    hc->vdev_count < 0 || hc->vdev_count > CONFIG_MAX_VDEVS ||
	    hc->fake_group_count < -1 || hc->fake_group_count > 32)
		z_errx(1, "invalid child handoff bounds");

	if (!has_nul(hc->root, sizeof(hc->root)) ||
	    !has_nul(hc->loader_path, sizeof(hc->loader_path)) ||
	    !has_nul(hc->exec_exe, sizeof(hc->exec_exe)) ||
	    !has_nul(hc->glue_dir, sizeof(hc->glue_dir)) ||
	    !has_nul(hc->kernel_release, sizeof(hc->kernel_release)) ||
	    !has_nul(hc->kernel_sysname, sizeof(hc->kernel_sysname)) ||
	    !has_nul(hc->hostname, sizeof(hc->hostname)) ||
	    !has_nul(hc->mount_access_observe, sizeof(hc->mount_access_observe)) ||
	    !has_nul(hc->mount_scratch, sizeof(hc->mount_scratch)) ||
	    !has_nul(hc->net_peers, sizeof(hc->net_peers)) ||
	    !has_nul(g_handoff.exec_target, sizeof(g_handoff.exec_target)) ||
	    !has_nul(g_handoff.exec_path, sizeof(g_handoff.exec_path)) ||
	    !has_nul(g_handoff.exec_exe, sizeof(g_handoff.exec_exe)) ||
	    !has_nul(g_handoff.exec_interp, sizeof(g_handoff.exec_interp)) ||
	    !has_nul(g_handoff.exec_name, sizeof(g_handoff.exec_name)))
		z_errx(1, "unterminated string in child handoff");

	for (int i = 0; i < hc->bind_count; i++) {
		if (!has_nul(hc->binds[i].src, sizeof(hc->binds[i].src)) ||
		    !has_nul(hc->binds[i].dst, sizeof(hc->binds[i].dst)))
			z_errx(1, "unterminated bind in child handoff");
	}
	for (int i = 0; i < hc->lower_count; i++) {
		if (!has_nul(hc->lower[i], sizeof(hc->lower[i])) ||
		    !has_nul(hc->lower_image[i], sizeof(hc->lower_image[i])))
			z_errx(1, "unterminated lower in child handoff");
	}
	for (int i = 0; i < hc->vdev_count; i++) {
		if (!has_nul(hc->vdevs[i].guest, sizeof(hc->vdevs[i].guest)) ||
		    !has_nul(hc->vdevs[i].sock, sizeof(hc->vdevs[i].sock)))
			z_errx(1, "unterminated vdev in child handoff");
	}
	if (hc->mount_access_observe[0]) {
		size_t n = z_strlen(hc->mount_access_observe);
		if (n != (size_t)hc->bind_count + 1)
			z_errx(1, "invalid mount access vector in child handoff");
		for (size_t j = 0; j < n; j++) {
			char c = hc->mount_access_observe[j];
			if (c != 'd' && c != 'r' && c != 'w')
				z_errx(1, "invalid mount access character in child handoff");
		}
	}
	if (g_handoff.exec_interp[0] && (g_handoff.exec_interp[0] != '/' || hc->guard != GUARD_READS))
		z_errx(1, "invalid exec interpreter in child handoff");
	if (g_handoff.exec_exe[0] && g_handoff.exec_exe[0] != '/')
		z_errx(1, "invalid exec exe in child handoff");

	z_memcpy(cfg, hc, sizeof(*cfg));
	cfg->guest_auxv_bytes = 0;
	cfg->protected_count = 0;

	opt->child = 1;
	opt->exec_target = g_handoff.exec_target[0] ? g_handoff.exec_target : NULL;
	opt->exec_path = g_handoff.exec_path[0] ? g_handoff.exec_path : NULL;
	opt->exec_exe = g_handoff.exec_exe[0] ? g_handoff.exec_exe : NULL;
	opt->exec_interp = g_handoff.exec_interp[0] ? g_handoff.exec_interp : NULL;
	opt->exec_name = g_handoff.exec_name[0] ? g_handoff.exec_name : NULL;
	opt->exec_fd = g_handoff.exec_fd;
	opt->exec_interp_fd = g_handoff.exec_interp_fd;
}

void options_print_help(int fd)
{
	static const char help[] =
		"svbox " SVBOX_VERSION " - userspace syscall-rewriting sandbox and container runtime\n"
		"\n"
		"Usage: svbox [OPTIONS] [--] COMMAND [ARGS...]\n"
		"\n"
		"General:\n"
		"  -h, --help                     Show this help message and exit\n"
		"  -V, --version                  Show version information and exit\n"
		"  --mode compat|container        Execution mode (default: compat; container with --root)\n"
		"  --log-level 0..4               Diagnostic log verbosity (0=off .. 4=debug)\n"
		"\n"
		"Filesystem & Mounts:\n"
		"  --root DIR                     Container root directory (implies --mode container)\n"
		"  --root-mode rw|ro|deny         Rootfs access policy (default: rw)\n"
		"  -v, --bind HOST:GUEST[:MODE]   Bind mount HOST at GUEST; MODE is rw (default), ro, or deny\n"
		"  --lower DIR[:IMAGE]            Read-only lower layer under --root (optional EROFS image)\n"
		"  --link-copy                    Copy file when host storage refuses hard links\n"
		"  --emulate-mounts               Emulate mount(2)/umount2(2) via a private mount table\n"
		"  --mount-table PATH             Join/share an emulated mount table file\n"
		"  --mount-scratch DIR            Host directory backing emulated tmpfs mounts\n"
		"  --owner-db PATH                Virtual uid/gid/mode ownership database\n"
		"  --vdev GUEST:SOCK[:TYPE]       Userspace virtual char device proxy (TYPE: chr|binder)\n"
		"\n"
		"Security & Policy:\n"
		"  --guard LEVEL                  Guard level: none (default), track, observe, paths, files, access\n"
		"  --sandbox                      Preset: --guard access + stdio/pipes/local-io/streams/revalidate\n"
		"  --isolate                      Enable seccomp filter + broker process isolation\n"
		"  --allow-device DEV             Allow direct guest open of whitelisted device under --isolate\n"
		"  --pass-fd N                    Grant inherited FD N to guest under file/access guard\n"
		"  --allow-stdio                  Allow validated stdout/stderr output under file/access guard\n"
		"  --allow-pipes                  Allow writes to newly created pipe write ends\n"
		"  --allow-local-io               Allow writes to locally created sockets/eventfd/memfd\n"
		"  --allow-streams                Allow inherited pipe/socket/TTY reads under access guard\n"
		"  --revalidate-fds               Re-derive regular-file FD origins instead of trusting snapshots\n"
		"  --fd-capacity N                Cap tracked FD records (default: hard RLIMIT_NOFILE)\n"
		"  --seccomp-backstop             Trap unhooked syscalls via seccomp SIGSYS backstop\n"
		"  --trap-sigsys                  Convert host seccomp SIGSYS traps into -ENOSYS\n"
		"\n"
		"Resources & Scheduling:\n"
		"  --cpuset LIST                  Pin container to host CPUs (e.g. 0-3 or 4,5,6,7)\n"
		"  --mem-mb N                     Virtual /proc/meminfo MemTotal cap in MiB\n"
		"  --nice N                       Initial process nice value (-20..19)\n"
		"  --sched POLICY                 Initial scheduler policy: other|batch|idle\n"
		"\n"
		"Process & Identity:\n"
		"  -w, --workdir DIR              Guest working directory (absolute guest path)\n"
		"  -u, --user UID[:GID]           Initial guest uid and gid\n"
		"  --cap-add ALL|HEX              Add Linux capability bits to default bounding set\n"
		"  -e, --env KEY=VALUE            Set environment variable (repeatable)\n"
		"  --hostname NAME                Override uname nodename\n"
		"  --kernel-release VER           Override uname release\n"
		"  --kernel-sysname NAME          Override uname sysname\n"
		"  --net-addr IP                  Virtual container IPv4 address (127.128.0.0/9)\n"
		"  --net-peers FILE               Peer container mapping file\n"
		"\n"
		"Advanced:\n"
		"  --payload FILE                 Load an external payload binary instead of the embedded one\n"
		"  --dump-filter                  Print compiled isolation seccomp BPF program and exit\n";
	z_fdprintf(fd, "%s", help);
}

void options_parse(int argc, char **argv, payload_config_t *cfg, struct loader_options *opt)
{
	int mode_explicit = 0;
	int guard_explicit = 0;
	int root_mode_explicit = 0;
	int handoff_given = 0;
	int user_opts_given = 0;
	int exec_exe_given = 0;
	char root_mode = 'w';
	char bind_modes[CONFIG_MAX_BINDS];

	z_memset(opt, 0, sizeof(*opt));
	opt->exec_fd = -1;
	opt->exec_interp_fd = -1;
	opt->target = argc;
	z_memset(cfg, 0, sizeof(*cfg));
	cfg->mode = CONFIG_MODE_COMPAT;
	cfg->guard = GUARD_NONE;
	cfg->fake_group_count = -1;
	cfg->fd_state = -1;
	cfg->loader_fd = -1;
	cfg->mount_table_fd = -1;
	cfg->owner_db_fd = -1;
	cfg->nice_val = 0x7fffffff;
	cfg->sched_policy = -1;

	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (arg[0] != '-' || !arg[1]) {
			opt->target = i;
			break;
		}
		if (is(arg, "--")) {
			opt->target = i + 1;
			break;
		}
		/* Internal child-loader handoff options (never mixed with user CLI). */
		if (is(arg, SVBOX_CHILD_HANDOFF_FD)) {
			if (handoff_given || user_opts_given)
				z_errx(1, "unexpected internal handoff option");
			int hfd = (int)number(value(argc, argv, &i), 2147483647ul, "handoff fd");
			read_handoff(hfd, cfg, opt);
			handoff_given = 1;
			continue;
		}
		if (is(arg, SVBOX_CHILD_EXEC_EXE)) {
			if (!handoff_given || exec_exe_given)
				z_errx(1, "unexpected internal exec-exe option");
			const char *v = value(argc, argv, &i);
			if (v[0] != '/')
				z_errx(1, "invalid exec-exe value");
			exec_exe_given = 1;
			continue;
		}
		if (handoff_given)
			z_errx(1, "user options cannot follow internal handoff");
		user_opts_given = 1;

		if (is(arg, "-h") || is(arg, "--help")) {
			opt->show_help = 1;
			return;
		} else if (is(arg, "-V") || is(arg, "--version")) {
			opt->show_version = 1;
			return;
		} else if (is(arg, "--mode")) {
			const char *v = value(argc, argv, &i);
			if (is(v, "container"))
				cfg->mode = CONFIG_MODE_CONTAINER;
			else if (is(v, "compat"))
				cfg->mode = CONFIG_MODE_COMPAT;
			else
				z_errx(1, "invalid --mode %s (expect compat|container)", v);
			mode_explicit = 1;
		} else if (is(arg, "--root")) {
			copy_cstr(cfg->root, CONFIG_MAX_PATH, value(argc, argv, &i));
			if (!mode_explicit)
				cfg->mode = CONFIG_MODE_CONTAINER;
		} else if (is(arg, "--root-mode")) {
			if (root_mode_explicit)
				z_errx(1, "duplicate --root-mode option");
			root_mode = parse_access_mode(value(argc, argv, &i), "--root-mode");
			root_mode_explicit = 1;
		} else if (is(arg, "-v") || is(arg, "--bind")) {
			add_bind(cfg, bind_modes, value(argc, argv, &i));
		} else if (is(arg, "--lower")) {
			add_lower(cfg, value(argc, argv, &i));
		} else if (is(arg, "--guard")) {
			if (guard_explicit)
				z_errx(1, "duplicate --guard / --sandbox option");
			cfg->guard = parse_guard_level(value(argc, argv, &i));
			guard_explicit = 1;
		} else if (is(arg, "--sandbox")) {
			if (guard_explicit)
				z_errx(1, "duplicate --guard / --sandbox option");
			cfg->guard = GUARD_READS;
			cfg->allow_stdio_output = 1;
			cfg->allow_pipe_output = 1;
			cfg->allow_local_output = 1;
			cfg->allow_stream_input = 1;
			cfg->revalidate_file_fds = 1;
			guard_explicit = 1;
		} else if (is(arg, "--isolate")) {
			opt->isolate = 1;
		} else if (is(arg, "--allow-device")) {
			const char *v = value(argc, argv, &i);
			int index = z_strlen(v) < ISOLATE_PATH_MAX ? isolate_device_index(v) : -1;
			if (index < 0)
				z_errx(1, "unsupported isolated device %s", v);
			cfg->device_mask |= 1u << index;
		} else if (is(arg, "--pass-fd")) {
			pass_fd(cfg, value(argc, argv, &i));
		} else if (is(arg, "--allow-stdio")) {
			if (cfg->allow_stdio_output)
				z_errx(1, "duplicate --allow-stdio option");
			cfg->allow_stdio_output = 1;
		} else if (is(arg, "--allow-pipes")) {
			if (cfg->allow_pipe_output)
				z_errx(1, "duplicate --allow-pipes option");
			cfg->allow_pipe_output = 1;
		} else if (is(arg, "--allow-local-io")) {
			if (cfg->allow_local_output)
				z_errx(1, "duplicate --allow-local-io option");
			cfg->allow_local_output = 1;
		} else if (is(arg, "--allow-streams")) {
			if (cfg->allow_stream_input)
				z_errx(1, "duplicate --allow-streams option");
			cfg->allow_stream_input = 1;
		} else if (is(arg, "--revalidate-fds")) {
			if (cfg->revalidate_file_fds)
				z_errx(1, "duplicate --revalidate-fds option");
			cfg->revalidate_file_fds = 1;
		} else if (is(arg, "--fd-capacity")) {
			cfg->fd_capacity = (int32_t)number(value(argc, argv, &i), 1ul << 20, "fd capacity");
			if (!cfg->fd_capacity)
				z_errx(1, "fd capacity must be positive");
		} else if (is(arg, "--seccomp-backstop")) {
			cfg->seccomp_backstop = 1;
		} else if (is(arg, "--trap-sigsys")) {
			cfg->trap_sigsys = 1;
		} else if (is(arg, "--cpuset")) {
			cfg->cpu_mask |= parse_cpuset(value(argc, argv, &i));
		} else if (is(arg, "--mem-mb")) {
			cfg->mem_limit_mb = (uint32_t)number(value(argc, argv, &i), 1024ul * 1024ul, "--mem-mb");
			if (!cfg->mem_limit_mb)
				z_errx(1, "--mem-mb must be positive");
		} else if (is(arg, "--nice")) {
			cfg->nice_val = parse_nice(value(argc, argv, &i));
		} else if (is(arg, "--sched")) {
			const char *v = value(argc, argv, &i);
			if (is(v, "other"))
				cfg->sched_policy = 0; /* SCHED_OTHER */
			else if (is(v, "batch"))
				cfg->sched_policy = 3; /* SCHED_BATCH */
			else if (is(v, "idle"))
				cfg->sched_policy = 5; /* SCHED_IDLE */
			else
				z_errx(1, "invalid --sched %s (expect other|batch|idle)", v);
		} else if (is(arg, "--link-copy")) {
			cfg->link_copy = 1;
		} else if (is(arg, "--emulate-mounts")) {
			opt->emulate_mounts = 1;
		} else if (is(arg, "--mount-table")) {
			opt->mount_table = value(argc, argv, &i);
		} else if (is(arg, "--mount-scratch")) {
			const char *v = value(argc, argv, &i);
			if (v[0] != '/' || z_strlen(v) >= CONFIG_MAX_PATH - 48)
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(cfg->mount_scratch, CONFIG_MAX_PATH, v);
		} else if (is(arg, "--owner-db")) {
			opt->owner_db = value(argc, argv, &i);
		} else if (is(arg, "--vdev")) {
			const char *spec = value(argc, argv, &i);
			const char *c1 = z_strchr(spec, ':');
			if (!c1 || c1 == spec || !c1[1])
				z_errx(1, "--vdev needs GUEST:SOCK[:chr|binder]");
			const char *c2 = z_strchr(c1 + 1, ':');
			size_t glen = (size_t)(c1 - spec);
			size_t slen = c2 ? (size_t)(c2 - (c1 + 1)) : z_strlen(c1 + 1);
			if (spec[0] != '/' || c1[1] != '/' || glen >= CONFIG_MAX_PATH || slen == 0 || slen >= CONFIG_MAX_PATH)
				z_errx(1, "--vdev needs absolute GUEST and SOCK paths");
			int32_t vtype = VDEV_TYPE_CHR;
			if (c2) {
				if (is(c2 + 1, "chr"))
					vtype = VDEV_TYPE_CHR;
				else if (is(c2 + 1, "binder"))
					vtype = VDEV_TYPE_BINDER;
				else
					z_errx(1, "invalid --vdev type %s (expect chr|binder)", c2 + 1);
			}
			if (cfg->vdev_count >= CONFIG_MAX_VDEVS)
				z_errx(1, "too many --vdev entries");
			struct vdev_entry *ve = &cfg->vdevs[cfg->vdev_count++];
			z_memcpy(ve->guest, spec, glen);
			ve->guest[glen] = '\0';
			z_memcpy(ve->sock, c1 + 1, slen);
			ve->sock[slen] = '\0';
			ve->type = vtype;
		} else if (is(arg, "-w") || is(arg, "--workdir")) {
			const char *v = value(argc, argv, &i);
			if (v[0] != '/' || z_strlen(v) >= CONFIG_MAX_PATH)
				z_errx(1, "--workdir needs an absolute guest path");
			opt->cwd = v;
		} else if (is(arg, "-u") || is(arg, "--user")) {
			uint32_t ids[2];
			const char *v = value(argc, argv, &i);
			int n = numbers(v, ':', ids, 2, 0);
			if (n < 1)
				z_errx(1, "--user needs UID[:GID]");
			for (int k = 0; k < 4; k++) {
				cfg->fake_ids[k] = ids[0];
				cfg->fake_ids[4 + k] = n > 1 ? ids[1] : 0;
			}
			cfg->fake_group_count = 1;
			cfg->fake_groups[0] = n > 1 ? ids[1] : 0;
		} else if (is(arg, "--cap-add")) {
			const char *v = value(argc, argv, &i);
			if (is(v, "ALL") || is(v, "all")) {
				cfg->extra_caps = ~0ull;
			} else {
				const char *p = v;
				if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
					p += 2;
				uint64_t mask = 0;
				if (!*p)
					z_errx(1, "--cap-add expects ALL or a hex capability mask");
				for (; *p; p++) {
					uint64_t d;
					if (*p >= '0' && *p <= '9') d = (uint64_t)(*p - '0');
					else if (*p >= 'a' && *p <= 'f') d = (uint64_t)(*p - 'a' + 10);
					else if (*p >= 'A' && *p <= 'F') d = (uint64_t)(*p - 'A' + 10);
					else z_errx(1, "--cap-add expects ALL or a hex capability mask");
					mask = (mask << 4) | d;
				}
				cfg->extra_caps |= mask;
			}
		} else if (is(arg, "-e") || is(arg, "--env")) {
			const char *kv = value(argc, argv, &i);
			if (!z_strchr(kv, '='))
				z_errx(1, "--env needs KEY=VALUE");
			if (opt->env_count >= LOADER_MAX_ENVS)
				z_errx(1, "too many env entries");
			opt->envs[opt->env_count++] = kv;
		} else if (is(arg, "--hostname")) {
			const char *v = value(argc, argv, &i);
			if (z_strlen(v) >= sizeof(cfg->hostname))
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(cfg->hostname, sizeof(cfg->hostname), v);
		} else if (is(arg, "--kernel-release") || is(arg, "--kernel-sysname")) {
			char *field = arg[9] == 'r' ? cfg->kernel_release : cfg->kernel_sysname;
			const char *v = value(argc, argv, &i);
			if (z_strlen(v) >= sizeof(cfg->kernel_release))
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(field, sizeof(cfg->kernel_release), v);
		} else if (is(arg, "--net-addr")) {
			const char *v = value(argc, argv, &i);
			uint32_t ip = 0, part = 0;
			int dots = 0, digits = 0;
			for (const char *p = v; *p; p++) {
				if (*p >= '0' && *p <= '9' && digits < 3) {
					part = part * 10 + (uint32_t)(*p - '0');
					digits++;
				} else if (*p == '.' && digits && dots < 3) {
					ip = ip << 8 | part;
					part = 0;
					digits = 0;
					dots++;
				} else {
					z_errx(1, "--net-addr needs a dotted IPv4 address");
				}
				if (part > 255)
					z_errx(1, "--net-addr needs a dotted IPv4 address");
			}
			if (dots != 3 || !digits || ((ip << 8 | part) & 0xff800000u) != 0x7f800000u)
				z_errx(1, "--net-addr needs an address of 127.128.0.0/9");
			cfg->net_addr = ip << 8 | part;
		} else if (is(arg, "--net-peers")) {
			const char *v = value(argc, argv, &i);
			if (v[0] != '/' || z_strlen(v) >= CONFIG_MAX_PATH)
				z_errx(1, "--net-peers needs an absolute host file");
			copy_cstr(cfg->net_peers, CONFIG_MAX_PATH, v);
		} else if (is(arg, "--log-level")) {
			cfg->log_level = (int32_t)number(value(argc, argv, &i), LOG_LEVEL_DEBUG, "log level");
		} else if (is(arg, "--payload")) {
			opt->payload = value(argc, argv, &i);
		} else if (is(arg, "--dump-filter")) {
			opt->filter_dump = 1;
		} else {
			z_errx(1, "unknown option %s (use --help for usage)", arg);
		}
	}

	if (handoff_given)
		return;

	/* Finalize guard level and assemble mount access vector from --root-mode
	 * and per-bind :rw/:ro/:deny modes. */
	int has_ro = (root_mode == 'r');
	int has_deny = (root_mode == 'd');
	for (int k = 0; k < cfg->bind_count; k++) {
		if (bind_modes[k] == 'r')
			has_ro = 1;
		else if (bind_modes[k] == 'd')
			has_deny = 1;
	}
	if (has_ro || has_deny) {
		if (!guard_explicit) {
			cfg->guard = has_deny ? GUARD_READS : GUARD_PATHS;
		} else if (cfg->guard == GUARD_NONE) {
			z_errx(1, "read-only or denied mounts cannot be used with --guard none");
		} else if (cfg->guard == GUARD_TRACK) {
			z_errx(1, "read-only or denied mounts require --guard observe|paths|files|access");
		}
	}
	if (cfg->fd_capacity > 0 && cfg->guard == GUARD_NONE) {
		if (guard_explicit)
			z_errx(1, "--fd-capacity cannot be used with --guard none");
		cfg->guard = GUARD_TRACK;
	}
	if (cfg->guard >= GUARD_OBSERVE) {
		cfg->mount_access_observe[0] = root_mode;
		for (int k = 0; k < cfg->bind_count; k++)
			cfg->mount_access_observe[1 + k] = bind_modes[k];
		cfg->mount_access_observe[1 + cfg->bind_count] = '\0';
	}

	if (opt->emulate_mounts && opt->mount_table)
		z_errx(1, "--emulate-mounts and --mount-table are mutually exclusive");
	if (cfg->mount_scratch[0] && !opt->emulate_mounts && !opt->mount_table)
		z_errx(1, "--mount-scratch requires --emulate-mounts or --mount-table");
	if (cfg->lower_count && !cfg->root[0])
		z_errx(1, "--lower requires --root (the writable upper layer)");
	if (cfg->device_mask && !opt->isolate && !opt->filter_dump)
		z_errx(1, "--allow-device requires --isolate");
	if (cfg->revalidate_file_fds && cfg->guard < GUARD_FILES)
		z_errx(1, "--revalidate-fds requires --guard files or access");
	if (cfg->allow_local_output && cfg->guard < GUARD_FILES)
		z_errx(1, "--allow-local-io requires --guard files or access");
	if (cfg->allow_pipe_output && cfg->guard < GUARD_FILES)
		z_errx(1, "--allow-pipes requires --guard files or access");
	if (cfg->allow_stdio_output && cfg->guard < GUARD_FILES)
		z_errx(1, "--allow-stdio requires --guard files or access");
	if (cfg->allow_stream_input && cfg->guard != GUARD_READS)
		z_errx(1, "--allow-streams requires --guard access");
	if (cfg->passed_count && cfg->guard < GUARD_FILES)
		z_errx(1, "--pass-fd requires --guard files or access");
}
