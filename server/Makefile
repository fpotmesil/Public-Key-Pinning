CXX=g++
SERVER_SRCS := $(wildcard *.cpp)
SERVER_OBJS := $(addprefix obj/,$(notdir $(SERVER_SRCS:.cpp=.o)))

#CXX_FLAGS := -g -std=c++17 -pedantic -Wall -Wextra -Wshadow -Wconversion -Werror -Wunreachable-code
CXX_FLAGS := -g -std=c++17 -pedantic -Wall -Wextra -Werror -Wunreachable-code
CXX_INC := -I/usr/local/openssl-3.0.8/include -I/usr/local/boost_1_81_0/include

LD_FLAGS := -L/usr/local/openssl-3.0.8/lib64 -L/usr/local/boost_1_81_0/lib -L/usr/lib64
LD_LIBS := -l:libssl.a -l:libcrypto.a -lpthread -ldl

.PHONY: all clean

all: obj server

server: $(SERVER_OBJS)
	$(CXX) $(LD_FLAGS) -o $@ $^ $(LD_LIBS)

obj/%.o: $(SERVER_SRCS)
	$(CXX) $(CXX_FLAGS) $(CXX_INC) -c -o $@ $<

obj:
	mkdir -p $@

clean:
	rm -f obj/* server
	rmdir obj





