# To cross-compile it's enough to specify GCC compiler - includes will be resolved based on predefined compiler macros.
# See https://stackoverflow.com/a/66249936

# CXX := riscv64-linux-gnu-g++
CXX := g++

all: filter main

gen:
	bash ./gen_syscall_headers.sh 2>/dev/null

main:
	$(CXX) -rdynamic -fpermissive asstrace.cc -o asstrace

empty_filter: filter
	sed 's/asstrace_/ASSTRACE_/g' ./libfilter.so  > empty_libfilter.so

filter:
	$(CXX) -shared -fPIC filter.cc -o libfilter.so

run:
	./asstrace ./libfilter.so cat asstrace.cc 2>/dev/null | head
	@echo -------------------------------------
	./asstrace ./libfilter.so cat asstrace.cc 2>&1 >/dev/null | head

example_unlink: main
	make -C examples unlink

example_net: main
	make -C examples network_forwarding