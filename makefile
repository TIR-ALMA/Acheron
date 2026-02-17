CC = g++
CFLAGS = -std=c++17 -Wall -O2 -D_WIN32_WINNT=0x0601
LIBS = -lsodium -lssl -lcrypto -lcurl -lwldap32 -lws2_32 -lbcrypt -lgdi32 -lole32 -loleaut32 -luuid -static

build:
	$(CC) $(CFLAGS) -o secure_geo_obfuscated main.cpp $(LIBS)

clean:
	rm -f secure_geo_obfuscated

.PHONY: build clean

