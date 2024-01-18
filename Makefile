all:
	bash ./gen_syscall_headers.sh 2>/dev/null
	g++ -rdynamic -fpermissive asstrace.cc -o asstrace

filter:
	gcc -shared -fPIC -o libfilter.so filter.c

run:
	./asstrace ./libfilter.so /bin/nm
