all: filter main

main:
	bash ./gen_syscall_headers.sh 2>/dev/null
	g++ -rdynamic -fpermissive asstrace.cc -o asstrace

filter:
	g++ -shared -fPIC -o libfilter.so filter.cc

run:
	./asstrace ./libfilter.so cat asstrace.cc 2>/dev/null | head
	@echo -------------------------------------
	./asstrace ./libfilter.so cat asstrace.cc 2>&1 >/dev/null | head
