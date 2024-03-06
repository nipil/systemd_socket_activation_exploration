build: server

client:
	socat - TCP4:localhost:2000

listen: server
	systemd-socket-activate -l 2000 ./server listen /tmp/cmd_server

accept: server
	systemd-socket-activate -l 2000 ./server accept /tmp/cmd_server

clean:
	rm server

server: server.cpp
	g++ -o server server.cpp -l systemd
