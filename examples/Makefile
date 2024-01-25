unlink:
	g++ -I.. -shared -fPIC unlink.cc -o libunlink.so
	../asstrace ./libunlink.so g++ ../asstrace.cc 2>/dev/null | grep prevented