#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS memory diagnostics require Darwin" >&2
  exit 1
fi
go version
go env GOOS GOARCH CGO_ENABLED
uname -m

probe_dir=$(mktemp -d)
trap 'rm -rf -- "$probe_dir"' EXIT
cat > "$probe_dir/memory.c" <<'C'
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/task_info.h>
#include <stdio.h>
#include <sys/resource.h>

int main(void) {
    host_t host = mach_host_self();
    vm_size_t page_size = 0;
    vm_statistics64_data_t memory = {0};
    mach_msg_type_number_t memory_count = HOST_VM_INFO64_COUNT;
    kern_return_t page_status = host_page_size(host, &page_size);
    kern_return_t host_status = host_statistics64(
        host, HOST_VM_INFO64, (host_info64_t)&memory, &memory_count);
    kern_return_t deallocate_status = mach_port_deallocate(mach_task_self(), host);

    task_vm_info_data_t task_memory = {0};
    mach_msg_type_number_t task_count = TASK_VM_INFO_COUNT;
    kern_return_t task_status = task_info(
        mach_task_self(), TASK_VM_INFO, (task_info_t)&task_memory, &task_count);
    struct rlimit address_space = {0};
    errno = 0;
    int limit_status = getrlimit(RLIMIT_AS, &address_space);
    int limit_errno = errno;

    puts("CI diagnostic only: task memory below belongs to this standalone probe.");
    printf("host_page_size status=%d page_size=%" PRIuMAX "\n",
        page_status, (uintmax_t)page_size);
    printf("host_statistics64 status=%d count=%u expected_count=%u free_pages=%" PRIuMAX "\n",
        host_status, memory_count, (unsigned)HOST_VM_INFO64_COUNT,
        (uintmax_t)memory.free_count);
    printf("mach_port_deallocate status=%d\n", deallocate_status);
    printf("task_info status=%d count=%u expected_count=%u minimum_count=%u\n",
        task_status, task_count, (unsigned)TASK_VM_INFO_COUNT,
        (unsigned)TASK_VM_INFO_REV1_COUNT);
    printf("probe physical_footprint=%" PRIuMAX " virtual_size=%" PRIuMAX "\n",
        (uintmax_t)task_memory.phys_footprint, (uintmax_t)task_memory.virtual_size);
    printf("getrlimit status=%d errno=%d current=%" PRIuMAX " maximum=%" PRIuMAX
        " infinity=%" PRIuMAX "\n", limit_status, limit_errno,
        (uintmax_t)address_space.rlim_cur, (uintmax_t)address_space.rlim_max,
        (uintmax_t)RLIM_INFINITY);
    return 0;
}
C
cc -Wall -Wextra -Werror "$probe_dir/memory.c" -o "$probe_dir/memory"
"$probe_dir/memory"
