unlink:
	g++ -I.. -shared -fPIC unlink.cc -o libunlink.so
	../asstrace ./libunlink.so g++ ../asstrace.cc 2>/dev/null | grep prevented

network_forwarding:
	bash -c "nc -l -p 8000 ; echo NETCAT SERVER RECEIVED DATA!" &
	g++ -I.. -shared -fPIC network_forwarding.cc -o libnet.so
	echo "<I am the payload>" | ../asstrace ./libnet.so nc -N 1.1.1.1 80 2>/dev/null