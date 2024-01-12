all:
	python3 gen_syscall_names_header.py > gen/syscall_names.h
	g++ -rdynamic asstrace.cc -o asstrace

filter:
	gcc -shared -fPIC -o libfilter.so filter.c

run:
	./asstrace ./libfilter.so /bin/nm

test:
	gcc test.c -o test -lfilter -L .
	LD_LIBRARY_PATH=. ./test