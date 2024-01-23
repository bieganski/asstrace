#include <vector>
#include <unistd.h>
#include <string>

using arch_reg_content_t = unsigned long long;

pid_t api_get_tracee_pid();

std::vector<std::string> api_get_tracee_cmdline();

void api_invoke_syscall_anyway();

