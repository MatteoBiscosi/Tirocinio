# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /matteo/clion-2020.1.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /matteo/clion-2020.1.2/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /matteo/tirocinio/Tirocinio/nDPILight

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/nDPILight.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/nDPILight.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/nDPILight.dir/flags.make

CMakeFiles/nDPILight.dir/nDPILight.cpp.o: CMakeFiles/nDPILight.dir/flags.make
CMakeFiles/nDPILight.dir/nDPILight.cpp.o: ../nDPILight.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/nDPILight.dir/nDPILight.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/nDPILight.dir/nDPILight.cpp.o -c /matteo/tirocinio/Tirocinio/nDPILight/nDPILight.cpp

CMakeFiles/nDPILight.dir/nDPILight.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nDPILight.dir/nDPILight.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /matteo/tirocinio/Tirocinio/nDPILight/nDPILight.cpp > CMakeFiles/nDPILight.dir/nDPILight.cpp.i

CMakeFiles/nDPILight.dir/nDPILight.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nDPILight.dir/nDPILight.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /matteo/tirocinio/Tirocinio/nDPILight/nDPILight.cpp -o CMakeFiles/nDPILight.dir/nDPILight.cpp.s

CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o: CMakeFiles/nDPILight.dir/flags.make
CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o: ../src/lib/pcap_reader.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o -c /matteo/tirocinio/Tirocinio/nDPILight/src/lib/pcap_reader.cpp

CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /matteo/tirocinio/Tirocinio/nDPILight/src/lib/pcap_reader.cpp > CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.i

CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /matteo/tirocinio/Tirocinio/nDPILight/src/lib/pcap_reader.cpp -o CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.s

CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o: CMakeFiles/nDPILight.dir/flags.make
CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o: ../src/lib/napatech_reader.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o -c /matteo/tirocinio/Tirocinio/nDPILight/src/lib/napatech_reader.cpp

CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /matteo/tirocinio/Tirocinio/nDPILight/src/lib/napatech_reader.cpp > CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.i

CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /matteo/tirocinio/Tirocinio/nDPILight/src/lib/napatech_reader.cpp -o CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.s

CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o: CMakeFiles/nDPILight.dir/flags.make
CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o: ../src/lib/reader_thread.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o -c /matteo/tirocinio/Tirocinio/nDPILight/src/lib/reader_thread.cpp

CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /matteo/tirocinio/Tirocinio/nDPILight/src/lib/reader_thread.cpp > CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.i

CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /matteo/tirocinio/Tirocinio/nDPILight/src/lib/reader_thread.cpp -o CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.s

CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o: CMakeFiles/nDPILight.dir/flags.make
CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o: ../src/lib/flow_info.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o -c /matteo/tirocinio/Tirocinio/nDPILight/src/lib/flow_info.cpp

CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /matteo/tirocinio/Tirocinio/nDPILight/src/lib/flow_info.cpp > CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.i

CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /matteo/tirocinio/Tirocinio/nDPILight/src/lib/flow_info.cpp -o CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.s

# Object files for target nDPILight
nDPILight_OBJECTS = \
"CMakeFiles/nDPILight.dir/nDPILight.cpp.o" \
"CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o" \
"CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o" \
"CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o" \
"CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o"

# External object files for target nDPILight
nDPILight_EXTERNAL_OBJECTS =

nDPILight: CMakeFiles/nDPILight.dir/nDPILight.cpp.o
nDPILight: CMakeFiles/nDPILight.dir/src/lib/pcap_reader.cpp.o
nDPILight: CMakeFiles/nDPILight.dir/src/lib/napatech_reader.cpp.o
nDPILight: CMakeFiles/nDPILight.dir/src/lib/reader_thread.cpp.o
nDPILight: CMakeFiles/nDPILight.dir/src/lib/flow_info.cpp.o
nDPILight: CMakeFiles/nDPILight.dir/build.make
nDPILight: CMakeFiles/nDPILight.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable nDPILight"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/nDPILight.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/nDPILight.dir/build: nDPILight

.PHONY : CMakeFiles/nDPILight.dir/build

CMakeFiles/nDPILight.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/nDPILight.dir/cmake_clean.cmake
.PHONY : CMakeFiles/nDPILight.dir/clean

CMakeFiles/nDPILight.dir/depend:
	cd /matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /matteo/tirocinio/Tirocinio/nDPILight /matteo/tirocinio/Tirocinio/nDPILight /matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug /matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug /matteo/tirocinio/Tirocinio/nDPILight/cmake-build-debug/CMakeFiles/nDPILight.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/nDPILight.dir/depend

