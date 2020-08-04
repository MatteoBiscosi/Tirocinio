CC			:= 	gcc
CXX			:= 	g++ -std=c++11
BUILD		:= 	./build
OBJ_DIR		:= 	$(BUILD)/objects
LIBNT		:=	/opt/napatech3/include
LIBFLAGS	:=	$(LIBNDPI)
CFLAGS		:=	-fPIC -DPIC -I$(LIBNT)/ -g -O2
LDFLAGS		:=	-lpcap -lpthread
SRC      	:= 	$(wildcard main.cpp)
TARGET		:= 	test

.PHONY : all clean


all: build ./$(TARGET)

EXECUTABLE_SOURCES	:=	main.cpp
OBJECTS				:=	$(SRC:%.cpp=$(OBJ_DIR)/%.o)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

./$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CFLAGS) -o ./$(TARGET) $^ $(LIBFLAGS) $(LDFLAGS) 

build:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p logs

clean:
	/bin/rm -f nDPILight
	/bin/rm -r -f build
	/bin/rm -r -f logs