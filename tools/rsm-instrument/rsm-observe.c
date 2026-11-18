// SPDX-License-Identifier: MPL-2.0

// Run in the Asterinas guest with CAP_SYS_MODULE and exclusive use of the
// global RSM management slot. Hooks observe all tasks during the workload.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { LOAD = 0, ATTACH = 4, DETACH = 5, READ_WORD = 7, UNLOAD = 8 };
enum { MAX_WORDS = 64, MAX_ARTIFACT = 1024 * 1024 };

struct attachment {
  const char *name;
  uint64_t hook;
  unsigned int phase;
};

struct map_read {
  const char *selector;
  uint64_t key;
  unsigned int count;
};

static long rsm(unsigned int cmd, unsigned long a, unsigned long b) {
  return syscall(500, cmd, a, b);
}

static int usage(void) {
  fprintf(stderr,
          "usage: rsm-observe ARTIFACT --attach entry|return|both HOOK ...\n"
          "       --read KEY|@HOOK COUNT ... -- COMMAND [ARG...]\n"
          "Repeat --attach or --read for more hooks or maps. COUNT starts at "
          "word zero.\n");
  return 2;
}

static int parse_number(const char *s, int base, uint64_t *value) {
  char *end;
  if (!isxdigit((unsigned char)*s))
    return -1;
  errno = 0;
  *value = strtoull(s, &end, base);
  return errno || *end ? -1 : 0;
}

static int find_hook(const char *name, uint64_t *id) {
  FILE *f = fopen("/proc/rsm/hooks", "r");
  if (!f) {
    perror("/proc/rsm/hooks");
    return -1;
  }
  char *line = NULL;
  size_t size = 0;
  int found = 0;
  while (getline(&line, &size, f) >= 0) {
    char *rest = line;
    char *hex = strsep(&rest, "\t");
    char *function = strsep(&rest, "\t");
    if (function && strcmp(function, name) == 0 &&
        parse_number(hex, 16, id) == 0) {
      found = 1;
      break;
    }
  }
  if (!found) {
    if (ferror(f))
      perror("/proc/rsm/hooks");
    else
      fprintf(stderr, "unknown hook: %s\n", name);
  }
  free(line);
  fclose(f);
  return found ? 0 : -1;
}

static int load_artifact(const char *filename) {
  FILE *f = fopen(filename, "rb");
  if (!f) {
    perror(filename);
    return -1;
  }
  struct stat st;
  void *image = NULL;
  int result = -1;
  if (fstat(fileno(f), &st) < 0) {
    perror(filename);
  } else if (st.st_size <= 0 || st.st_size > MAX_ARTIFACT) {
    fprintf(stderr, "%s: expected 1 to %d bytes\n", filename, MAX_ARTIFACT);
  } else if (!(image = malloc(st.st_size))) {
    perror("malloc artifact");
  } else if (fread(image, 1, st.st_size, f) != (size_t)st.st_size) {
    fprintf(stderr, "%s: could not read complete artifact\n", filename);
  } else if (rsm(LOAD, (uintptr_t)image, st.st_size) < 0) {
    fprintf(stderr, "load %s: %s\n", filename, strerror(errno));
  } else {
    result = 0;
  }
  free(image);
  fclose(f);
  return result;
}

static int report(const struct map_read *map) {
  uint64_t values[MAX_WORDS];
  for (unsigned int i = 0; i < map->count; i++) {
    struct {
      uint64_t key, index, value;
    } word = {.key = map->key, .index = i};
    if (rsm(READ_WORD, (uintptr_t)&word, 0) < 0) {
      if (i == 0 && errno == ENOENT) {
        printf("map %s: no samples\n", map->selector);
        return 0;
      }
      fprintf(stderr, "read %s word %u: %s\n", map->selector, i,
              strerror(errno));
      return -1;
    }
    values[i] = word.value;
  }
  printf("map %s:", map->selector);
  for (unsigned int i = 0; i < map->count; i++)
    printf(" %" PRIu64, values[i]);
  putchar('\n');
  return 0;
}

// Synchronous signal handling lets us forward termination signals to a live
// child and detach before the controller exits. The workload inherits stdio.
static void child_event(int signo) { (void)signo; }

static int run(char **command, const sigset_t *signals,
               const sigset_t *previous) {
  // Ensure child exit is queued even if the caller ignored SIGCHLD or asked
  // the kernel to reap automatically. The workload gets the caller's setting.
  struct sigaction original, action = {.sa_handler = child_event};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGCHLD, &action, &original) < 0) {
    perror("watch workload exit");
    return 1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork workload");
    return 1;
  }
  if (pid == 0) {
    if (sigaction(SIGCHLD, &original, NULL) == 0 &&
        sigprocmask(SIG_SETMASK, previous, NULL) == 0)
      execvp(command[0], command);
    int error = errno;
    fprintf(stderr, "%s: %s\n", command[0], strerror(error));
    _exit(error == ENOENT ? 127 : 126);
  }
  int status;
  for (;;) {
    pid_t child = waitpid(pid, &status, WNOHANG);
    if (child == pid)
      return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    if (child < 0) {
      if (errno == EINTR)
        continue;
      perror("waitpid workload");
      return 1;
    }
    int signo;
    int error = sigwait(signals, &signo);
    if (error == EINTR)
      continue;
    if (error) {
      fprintf(stderr, "sigwait: %s\n", strerror(error));
      return 1;
    }
    if (signo != SIGCHLD && kill(pid, signo) < 0 && errno != ESRCH)
      perror("signal workload");
  }
}

int main(int argc, char **argv) {
  if (argc < 2)
    return usage();
  struct attachment *hooks = calloc(argc, sizeof(*hooks));
  struct map_read *maps = calloc(argc, sizeof(*maps));
  if (!hooks || !maps) {
    perror("allocate arguments");
    return 1;
  }
  int nhooks = 0, nmaps = 0, i = 2;
  for (; i < argc && strcmp(argv[i], "--") != 0; i += 3) {
    if (argc - i < 3)
      return usage();
    const char *arg = argv[i + 1];
    if (strcmp(argv[i], "--attach") == 0) {
      const char *name = argv[i + 2];
      int entry = strcmp(arg, "entry") == 0 || strcmp(arg, "both") == 0;
      int leave = strcmp(arg, "return") == 0 || strcmp(arg, "both") == 0;
      uint64_t id;
      if (!entry && !leave)
        return usage();
      if (find_hook(name, &id) < 0)
        return 1;
      if (entry)
        hooks[nhooks++] = (struct attachment){name, id, 0};
      if (leave)
        hooks[nhooks++] = (struct attachment){name, id, 1};
    } else if (strcmp(argv[i], "--read") == 0) {
      uint64_t key, count;
      if (parse_number(argv[i + 2], 10, &count) < 0 || count == 0 ||
          count > MAX_WORDS)
        return usage();
      if (arg[0] == '@') {
        if (find_hook(arg + 1, &key) < 0)
          return 1;
      } else if (parse_number(arg, strncasecmp(arg, "0x", 2) == 0 ? 16 : 10,
                              &key) < 0) {
        return usage();
      }
      maps[nmaps++] = (struct map_read){arg, key, count};
    } else {
      return usage();
    }
  }
  if (!nhooks || !nmaps || i + 1 >= argc)
    return usage();

  sigset_t signals, previous;
  sigemptyset(&signals);
  sigaddset(&signals, SIGCHLD);
  sigaddset(&signals, SIGTERM);
  sigaddset(&signals, SIGINT);
  sigaddset(&signals, SIGHUP);
  sigaddset(&signals, SIGQUIT);
  if (sigprocmask(SIG_BLOCK, &signals, &previous) < 0) {
    perror("block signals");
    return 1;
  }
  if (load_artifact(argv[1]) < 0)
    return 1;

  int attached = 0, status = 1, failed = 0;
  for (; attached < nhooks; attached++) {
    struct attachment h = hooks[attached];
    if (rsm(ATTACH, h.hook, h.phase) < 0) {
      fprintf(stderr, "attach %s phase %u: %s\n", h.name, h.phase,
              strerror(errno));
      break;
    }
  }
  int complete = attached == nhooks;
  if (complete)
    status = run(&argv[i + 1], &signals, &previous);
  while (attached > 0) {
    struct attachment h = hooks[--attached];
    if (rsm(DETACH, h.hook, h.phase) < 0) {
      fprintf(stderr, "detach %s phase %u: %s\n", h.name, h.phase,
              strerror(errno));
      failed = 1;
    }
  }
  if (complete) {
    for (int m = 0; m < nmaps; m++)
      if (report(&maps[m]) < 0)
        failed = 1;
  }
  // A callback that captured the program before detach can finish afterwards.
  for (int retry = 0; rsm(UNLOAD, 0, 0) < 0; retry++) {
    if (errno != EBUSY || failed || retry == 100) {
      perror("unload");
      failed = 1;
      break;
    }
    usleep(10000);
  }
  return status ? status : failed;
}
