all:
	python3 gen_syscall_names_header.py > gen/syscall_names.h
	g++ asstrace.cc -o asstrace