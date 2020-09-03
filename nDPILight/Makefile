CC			:= 	gcc
CXX			:= 	g++ -std=c++11
BUILD		:= 	./build
OBJ_DIR		:= 	$(BUILD)/objects
SRCHOME		:=	./src/include
NDPILIB		:=	../../nDPI/src
LIB_DIR         :=      /opt/napatech3/lib
LIBNT           :=      /opt/napatech3/include
LIBNDPI		:=	$(NDPILIB)/lib/libndpi.a
LIBFLAGS	:=	$(LIBNDPI)
CFLAGS		:=	-fPIC -DPIC -I$(LIBNT) -I$(SRCHOME) -I$(NDPILIB)/include -g -O2
LDFLAGS		:=	-lntapi -lpcap -lpthread
SRC      	:=	$(wildcard src/lib/*.cpp)	\
               	$(wildcard nDPILight.cpp)
TARGET		:= 	nDPILight

.PHONY : all clean


all: build ./$(TARGET)

EXECUTABLE_SOURCES	:=	nDPILight.c
COMMON_SOURCES		:=	$(filter-out $(EXECUTABLE_SOURCES),$(wildcard *.c ))
OBJECTS				:=	$(SRC:%.cpp=$(OBJ_DIR)/%.o)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -c $< -o $@

./$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -o ./$(TARGET) -L$(LIB_DIR) $^ $(NTOPNGOBJ) $(LIBFLAGS) $(LDFLAGS) 

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

build:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p logs
	@mkdir -p logs/allarms
	@touch logs/allarms/allarm.json

clean:
	/bin/rm -f nDPILight
	/bin/rm -r -f build
	/bin/rm -r -f logs
	/bin/rm -r -f logs/allarms
