all: filter main

gen:
	bash ./gen_syscall_headers.sh 2>/dev/null

main:
	g++ -rdynamic -fpermissive asstrace.cc -o asstrace

filter:
	g++ -shared -fPIC filter.cc -o libfilter.so

run:
	./asstrace ./libfilter.so cat asstrace.cc 2>/dev/null | head
	@echo -------------------------------------
	./asstrace ./libfilter.so cat asstrace.cc 2>&1 >/dev/null | head

example_unlink: main
	make -C examples unlink
