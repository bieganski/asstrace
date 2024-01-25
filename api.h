#include <vector>
#include <unistd.h>
#include <string>

using arch_reg_content_t = unsigned long long;

pid_t api_get_tracee_pid();

std::vector<std::string> api_get_tracee_cmdline();

/*
To be called from user-provided mock to notify that despite syscall was intercepted
and the replacement mock was called, the real syscall should be invoked anyway
(possibly with params modified by mock).
*/
void api_invoke_syscall_anyway();

void api_memcpy_to_tracee(pid_t pid, void* dst_tracee, void* src_tracer, size_t size);

void api_memcpy_from_tracee(pid_t pid, void* dst_tracer, void* src_tracee, size_t size);

/*
If path could not be resolved, 'path_buf' will contain empty string (path_buf[0] == 0).
path_buf must be enough to fit resolved path (probably of size PATH_MAX).
*/
void api_resolve_fd(pid_t pid, int fd, char* path_buf);