CC=g++
CFLAGS= -lpcap -lcrypto -O3
CFLAGS_DEBUG=-Wall -pedantic -g -DLOG_USE-COLOR -DDEBUG -fsanitize=leak -fsanitize=address $(CFLAGS)
TARGET = secret
SOURCES=$(wildcard src/*.cpp)
HEADERS=$(wildcard src/*.h)
OBJECTS=$(SOURCES:%.cpp=%.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $^ $(CFLAGS) -o $@

.cpp.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm src/*.o
	rm $(TARGET)

tar:
	tar -cf xdokou14.tar Makefile manual.pdf secret.1 $(SOURCES) $(HEADERS)