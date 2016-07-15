go:main.o
	gcc -o go main.o -lpcap -I/usr/include/pcap
main.o:main.cpp
	gcc -c main.cpp -lpcap
