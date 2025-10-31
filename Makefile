all:
	x86_64-w64-mingw32-gcc -c teams-cookies-bof.c -o teams-cookies-bof.x64.o
	x86_64-w64-mingw32-strip --strip-unneeded teams-cookies-bof.x64.o
	i686-w64-mingw32-gcc -c teams-cookies-bof.c -o teams-cookies-bof.x86.o
x64:
	x86_64-w64-mingw32-gcc -c teams-cookies-bof.c -o teams-cookies-bof.x64.o
	x86_64-w64-mingw32-strip --strip-unneeded teams-cookies-bof.x64.o
clean:
	rm teams-cookies-bof.x64.o
	rm teams-cookies-bof.x86.o
