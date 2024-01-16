all:
	mkdir -p gen
	bash ./gen_syscall_headers.sh 2>/dev/null
	g++ -rdynamic asstrace.cc -o asstrace

filter:
	gcc -shared -fPIC -o libfilter.so filter.c

run:
	./asstrace ./libfilter.so /bin/nm

test:
	gcc test.c -o test -lfilter -L .
	LD_LIBRARY_PATH=. ./test
