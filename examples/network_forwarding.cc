#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>

#include "api.h"

const char* target_addr = "127.0.0.1";
const unsigned short target_port = 8000;

extern "C" {

long asstrace_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    sockaddr* buf = (sockaddr*) malloc(addrlen);
    assert(buf);

    api_memcpy_from_tracee(api_get_tracee_pid(), buf, (void*) addr, addrlen);

    if (buf->sa_family != AF_INET) {
        api_invoke_syscall_anyway();
        return 1234;
    }

    assert(addrlen == sizeof(struct sockaddr_in));
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)buf;

    printf(">> network forwarding: %s:%d -> %s:%d\n", inet_ntoa(ipv4->sin_addr), ntohs(ipv4->sin_port), target_addr, target_port);

    ipv4->sin_port = htons(target_port);
    inet_pton(AF_INET, target_addr, &(ipv4->sin_addr));

    api_memcpy_to_tracee(api_get_tracee_pid(), (void*) addr, ipv4, addrlen);

    free(buf);

    api_invoke_syscall_anyway();
    return 1234;
}
}
