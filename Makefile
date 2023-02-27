CC=g++
CFLAGS=-I.

client: client.cpp requests.cpp helpers.cpp buffer.cpp json_library
	$(CC) -o client client.cpp requests.cpp helpers.cpp buffer.cpp -Wall

run: client
	./client

.PHONY : clean json_library

clean:
	rm -f *.o client

json_library:
	sudo apt-get install nlohmann-json-dev
