CC			:= 	gcc
CXX			:= 	g++ -std=c++11
BUILD		:= 	./build
OBJ_DIR		:= 	$(BUILD)/objects
LIB_DIR		:= 	/opt/napatech3/lib
LIBNT		:=	/opt/napatech3/include
LIBFLAGS	:=	$(LIBNDPI)
CFLAGS		:=	-fPIC -DPIC -I$(LIBNT) -g -O2
LDFLAGS		:=	-L$(LIB_DIR) -lntapi -lpcap -lpthread
SRC      	:= 	$(wildcard main.cpp)
TARGET		:= 	test

.PHONY : all clean


all: build ./$(TARGET)

EXECUTABLE_SOURCES	:=	main.cpp
OBJECTS			:=	$(SRC:%.cpp=$(OBJ_DIR)/%.o)


$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) -D_NT_NTAPI_NO_COMPAT $(CFLAGS) -c $< -o $@ 

%.o: %.cpp
	$(CXX) -D_NT_NTAPI_NO_COMPAT $(CFLAGS) -c $< -o $@ $(LDFLAGS)

./$(TARGET):$(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) -o ./$(TARGET) $^ $(LIBFLAGS) $(LDFLAGS) 

build:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p logs

clean:
	/bin/rm -f nDPILight
	/bin/rm -r -f build
	/bin/rm -r -f logs
