CC=gcc
CXX=g++
BUILD    := ./build
OBJ_DIR  := $(BUILD)/objects
TARGET   := nDPILight
SRCHOME=../src
SRCEXTRALIB=./src/include
CFLAGS=-g -fPIC -DPIC -I$(SRCHOME)/include  -I$(SRCEXTRALIB) -g -O2
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap  -lpthread -lm
HEADERS=intrusion_detection.h reader_util.h $(SRCHOME)/include/ndpi_api.h \
        $(SRCHOME)/include/ndpi_typedefs.h $(SRCHOME)/include/ndpi_protocol_ids.h
SRC      :=     $(wildcard src/lib/*.cpp)   \
                $(wildcard nDPILight.cpp) \

all: build .$(TARGET)

EXECUTABLE_SOURCES := nDPILight.c
COMMON_SOURCES := $(filter-out $(EXECUTABLE_SOURCES),$(wildcard *.c ))
OBJECTS  := $(SRC:%.cpp=$(OBJ_DIR)/%.o)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

./$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -o ./$(TARGET) $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

build:
	@mkdir -p $(OBJ_DIR)

clean:
	/bin/rm -f nDPILight
	/bin/rm -r -f build