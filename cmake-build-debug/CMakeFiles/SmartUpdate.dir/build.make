# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

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
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/SmartUpdate.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/SmartUpdate.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/SmartUpdate.dir/flags.make

CMakeFiles/SmartUpdate.dir/code/hs.c.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/hs.c.o: ../code/hs.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/SmartUpdate.dir/code/hs.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/hs.c.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c

CMakeFiles/SmartUpdate.dir/code/hs.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/hs.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c > CMakeFiles/SmartUpdate.dir/code/hs.c.i

CMakeFiles/SmartUpdate.dir/code/hs.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/hs.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c -o CMakeFiles/SmartUpdate.dir/code/hs.c.s

CMakeFiles/SmartUpdate.dir/code/hs.c.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/hs.c.o.requires

CMakeFiles/SmartUpdate.dir/code/hs.c.o.provides: CMakeFiles/SmartUpdate.dir/code/hs.c.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/hs.c.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/hs.c.o.provides

CMakeFiles/SmartUpdate.dir/code/hs.c.o.provides.build: CMakeFiles/SmartUpdate.dir/code/hs.c.o


CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o: ../code/mem_sim.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c

CMakeFiles/SmartUpdate.dir/code/mem_sim.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/mem_sim.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c > CMakeFiles/SmartUpdate.dir/code/mem_sim.c.i

CMakeFiles/SmartUpdate.dir/code/mem_sim.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/mem_sim.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c -o CMakeFiles/SmartUpdate.dir/code/mem_sim.c.s

CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.requires

CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.provides: CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.provides

CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.provides.build: CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o


CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o: ../code/pc_eval.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c

CMakeFiles/SmartUpdate.dir/code/pc_eval.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/pc_eval.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c > CMakeFiles/SmartUpdate.dir/code/pc_eval.c.i

CMakeFiles/SmartUpdate.dir/code/pc_eval.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/pc_eval.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c -o CMakeFiles/SmartUpdate.dir/code/pc_eval.c.s

CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.requires

CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.provides: CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.provides

CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.provides.build: CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o


CMakeFiles/SmartUpdate.dir/code/tss.c.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/tss.c.o: ../code/tss.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/SmartUpdate.dir/code/tss.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/tss.c.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c

CMakeFiles/SmartUpdate.dir/code/tss.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/tss.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c > CMakeFiles/SmartUpdate.dir/code/tss.c.i

CMakeFiles/SmartUpdate.dir/code/tss.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/tss.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c -o CMakeFiles/SmartUpdate.dir/code/tss.c.s

CMakeFiles/SmartUpdate.dir/code/tss.c.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/tss.c.o.requires

CMakeFiles/SmartUpdate.dir/code/tss.c.o.provides: CMakeFiles/SmartUpdate.dir/code/tss.c.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/tss.c.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/tss.c.o.provides

CMakeFiles/SmartUpdate.dir/code/tss.c.o.provides.build: CMakeFiles/SmartUpdate.dir/code/tss.c.o


CMakeFiles/SmartUpdate.dir/code/utils.c.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/utils.c.o: ../code/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/SmartUpdate.dir/code/utils.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/utils.c.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c

CMakeFiles/SmartUpdate.dir/code/utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/utils.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c > CMakeFiles/SmartUpdate.dir/code/utils.c.i

CMakeFiles/SmartUpdate.dir/code/utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/utils.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c -o CMakeFiles/SmartUpdate.dir/code/utils.c.s

CMakeFiles/SmartUpdate.dir/code/utils.c.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/utils.c.o.requires

CMakeFiles/SmartUpdate.dir/code/utils.c.o.provides: CMakeFiles/SmartUpdate.dir/code/utils.c.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/utils.c.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/utils.c.o.provides

CMakeFiles/SmartUpdate.dir/code/utils.c.o.provides.build: CMakeFiles/SmartUpdate.dir/code/utils.c.o


# Object files for target SmartUpdate
SmartUpdate_OBJECTS = \
"CMakeFiles/SmartUpdate.dir/code/hs.c.o" \
"CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o" \
"CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o" \
"CMakeFiles/SmartUpdate.dir/code/tss.c.o" \
"CMakeFiles/SmartUpdate.dir/code/utils.c.o"

# External object files for target SmartUpdate
SmartUpdate_EXTERNAL_OBJECTS =

SmartUpdate: CMakeFiles/SmartUpdate.dir/code/hs.c.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/tss.c.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/utils.c.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/build.make
SmartUpdate: CMakeFiles/SmartUpdate.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable SmartUpdate"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/SmartUpdate.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/SmartUpdate.dir/build: SmartUpdate

.PHONY : CMakeFiles/SmartUpdate.dir/build

CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/hs.c.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/mem_sim.c.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/pc_eval.c.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/tss.c.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/utils.c.o.requires

.PHONY : CMakeFiles/SmartUpdate.dir/requires

CMakeFiles/SmartUpdate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/SmartUpdate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/SmartUpdate.dir/clean

CMakeFiles/SmartUpdate.dir/depend:
	cd /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/cmake-build-debug/CMakeFiles/SmartUpdate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/SmartUpdate.dir/depend
