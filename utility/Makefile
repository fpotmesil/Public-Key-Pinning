CXX=g++
VPATH := ../common
CERT_HASH_SRCS := $(wildcard *.cpp) $(wildcard ../common/*.cpp)
CERT_HASH_OBJS := $(addprefix obj/,$(notdir $(CERT_HASH_SRCS:.cpp=.o)))

#CXX_FLAGS := -g -std=c++17 -pedantic -Wall -Wextra -Wshadow -Wconversion -Werror -Wunreachable-code
CXX_FLAGS := -g -std=c++17 -pedantic -Wall -Wextra -Werror -Wunreachable-code
#
# For RHEL snapperhead, this is the include line to use:
#
CXX_INC := -I/usr/local/openssl-3.0.8/include -I/usr/local/boost_1_81_0/include -I/usr/include -I../common
#
# For Pi, this is the include line to use:
#
## CXX_INC := -I/usr/include

LD_FLAGS := -L/usr/local/openssl-3.0.8/lib64 -L/usr/local/boost_1_81_0/lib -L/usr/lib64
LD_LIBS := -l:libssl.a -l:libcrypto.a -lpthread -ldl -l:libboost_program_options.a -l:libboost_system.a


.PHONY: all clean

all: obj certificate-hash

certificate-hash: $(CERT_HASH_OBJS)
	$(CXX) $(LD_FLAGS) -o $@ $^ $(LD_LIBS)

#obj/%.o: $(COMMON_SRCS)
#	$(CXX) $(CXX_FLAGS) $(CXX_INC) -c -o $@ $<

obj/%.o: %.cpp
	$(CXX) $(CXX_FLAGS) $(CXX_INC) -c -o $@ $<

obj:
	mkdir -p $@

clean:
	rm -f obj/* certificate-hash
	rmdir obj





