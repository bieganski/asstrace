# To cross-compile it's enough to specify GCC compiler - includes will be resolved based on predefined compiler macros.
# See https://stackoverflow.com/a/66249936

# CXX := riscv64-linux-gnu-g++
CXX := arm-linux-gnueabihf-g++
# CXX := g++

LOADER := /home/m.bieganski/GBS-ROOT-M108-TZ_STANDARD-TIZEN_8.0-RELEASE/local/BUILD-ROOTS/scratch.armv7l.0/usr/lib/ld-2.30.so

LOADER_CMD := -Wl,dynamic-linker=$(LOADER)
LOADER_CMD := 

all: filter main

gen:
	bash ./gen_syscall_headers.sh 2>/dev/null

main:
	$(CXX) $(LOADER_CMD) -static -static-libgcc -static-libstdc++ -rdynamic -fpermissive asstrace.cc -o asstrace

empty_filter: filter
	sed 's/asstrace_/ASSTRACE_/g' ./libfilter.so  > empty_libfilter.so

filter:
	$(CXX) -shared -fPIC -static-libgcc -static-libstdc++ filter.cc -o libfilter.so

run:
	./asstrace ./libfilter.so cat asstrace.cc 2>/dev/null | head
	@echo -------------------------------------
	./asstrace ./libfilter.so cat asstrace.cc 2>&1 >/dev/null | head

example_unlink: main
	make -C examples unlink

example_net: main
	make -C examples network_forwarding