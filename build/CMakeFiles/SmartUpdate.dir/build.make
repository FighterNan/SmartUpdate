# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

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
CMAKE_COMMAND = /Applications/CMake.app/Contents/bin/cmake

# The command to remove a file.
RM = /Applications/CMake.app/Contents/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build

# Include any dependencies generated for this target.
include CMakeFiles/SmartUpdate.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/SmartUpdate.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/SmartUpdate.dir/flags.make

CMakeFiles/SmartUpdate.dir/code/hs.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/hs.o: ../code/hs.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/SmartUpdate.dir/code/hs.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/hs.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c

CMakeFiles/SmartUpdate.dir/code/hs.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/hs.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c > CMakeFiles/SmartUpdate.dir/code/hs.i

CMakeFiles/SmartUpdate.dir/code/hs.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/hs.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/hs.c -o CMakeFiles/SmartUpdate.dir/code/hs.s

CMakeFiles/SmartUpdate.dir/code/hs.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/hs.o.requires

CMakeFiles/SmartUpdate.dir/code/hs.o.provides: CMakeFiles/SmartUpdate.dir/code/hs.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/hs.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/hs.o.provides

CMakeFiles/SmartUpdate.dir/code/hs.o.provides.build: CMakeFiles/SmartUpdate.dir/code/hs.o


CMakeFiles/SmartUpdate.dir/code/mem_sim.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/mem_sim.o: ../code/mem_sim.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/SmartUpdate.dir/code/mem_sim.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/mem_sim.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c

CMakeFiles/SmartUpdate.dir/code/mem_sim.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/mem_sim.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c > CMakeFiles/SmartUpdate.dir/code/mem_sim.i

CMakeFiles/SmartUpdate.dir/code/mem_sim.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/mem_sim.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/mem_sim.c -o CMakeFiles/SmartUpdate.dir/code/mem_sim.s

CMakeFiles/SmartUpdate.dir/code/mem_sim.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/mem_sim.o.requires

CMakeFiles/SmartUpdate.dir/code/mem_sim.o.provides: CMakeFiles/SmartUpdate.dir/code/mem_sim.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/mem_sim.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/mem_sim.o.provides

CMakeFiles/SmartUpdate.dir/code/mem_sim.o.provides.build: CMakeFiles/SmartUpdate.dir/code/mem_sim.o


CMakeFiles/SmartUpdate.dir/code/pc_eval.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/pc_eval.o: ../code/pc_eval.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/SmartUpdate.dir/code/pc_eval.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/pc_eval.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c

CMakeFiles/SmartUpdate.dir/code/pc_eval.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/pc_eval.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c > CMakeFiles/SmartUpdate.dir/code/pc_eval.i

CMakeFiles/SmartUpdate.dir/code/pc_eval.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/pc_eval.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/pc_eval.c -o CMakeFiles/SmartUpdate.dir/code/pc_eval.s

CMakeFiles/SmartUpdate.dir/code/pc_eval.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/pc_eval.o.requires

CMakeFiles/SmartUpdate.dir/code/pc_eval.o.provides: CMakeFiles/SmartUpdate.dir/code/pc_eval.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/pc_eval.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/pc_eval.o.provides

CMakeFiles/SmartUpdate.dir/code/pc_eval.o.provides.build: CMakeFiles/SmartUpdate.dir/code/pc_eval.o


CMakeFiles/SmartUpdate.dir/code/tss.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/tss.o: ../code/tss.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/SmartUpdate.dir/code/tss.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/tss.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c

CMakeFiles/SmartUpdate.dir/code/tss.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/tss.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c > CMakeFiles/SmartUpdate.dir/code/tss.i

CMakeFiles/SmartUpdate.dir/code/tss.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/tss.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/tss.c -o CMakeFiles/SmartUpdate.dir/code/tss.s

CMakeFiles/SmartUpdate.dir/code/tss.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/tss.o.requires

CMakeFiles/SmartUpdate.dir/code/tss.o.provides: CMakeFiles/SmartUpdate.dir/code/tss.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/tss.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/tss.o.provides

CMakeFiles/SmartUpdate.dir/code/tss.o.provides.build: CMakeFiles/SmartUpdate.dir/code/tss.o


CMakeFiles/SmartUpdate.dir/code/utils.o: CMakeFiles/SmartUpdate.dir/flags.make
CMakeFiles/SmartUpdate.dir/code/utils.o: ../code/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/SmartUpdate.dir/code/utils.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/SmartUpdate.dir/code/utils.o   -c /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c

CMakeFiles/SmartUpdate.dir/code/utils.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/SmartUpdate.dir/code/utils.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c > CMakeFiles/SmartUpdate.dir/code/utils.i

CMakeFiles/SmartUpdate.dir/code/utils.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/SmartUpdate.dir/code/utils.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/code/utils.c -o CMakeFiles/SmartUpdate.dir/code/utils.s

CMakeFiles/SmartUpdate.dir/code/utils.o.requires:

.PHONY : CMakeFiles/SmartUpdate.dir/code/utils.o.requires

CMakeFiles/SmartUpdate.dir/code/utils.o.provides: CMakeFiles/SmartUpdate.dir/code/utils.o.requires
	$(MAKE) -f CMakeFiles/SmartUpdate.dir/build.make CMakeFiles/SmartUpdate.dir/code/utils.o.provides.build
.PHONY : CMakeFiles/SmartUpdate.dir/code/utils.o.provides

CMakeFiles/SmartUpdate.dir/code/utils.o.provides.build: CMakeFiles/SmartUpdate.dir/code/utils.o


# Object files for target SmartUpdate
SmartUpdate_OBJECTS = \
"CMakeFiles/SmartUpdate.dir/code/hs.o" \
"CMakeFiles/SmartUpdate.dir/code/mem_sim.o" \
"CMakeFiles/SmartUpdate.dir/code/pc_eval.o" \
"CMakeFiles/SmartUpdate.dir/code/tss.o" \
"CMakeFiles/SmartUpdate.dir/code/utils.o"

# External object files for target SmartUpdate
SmartUpdate_EXTERNAL_OBJECTS =

SmartUpdate: CMakeFiles/SmartUpdate.dir/code/hs.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/mem_sim.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/pc_eval.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/tss.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/code/utils.o
SmartUpdate: CMakeFiles/SmartUpdate.dir/build.make
SmartUpdate: CMakeFiles/SmartUpdate.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable SmartUpdate"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/SmartUpdate.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/SmartUpdate.dir/build: SmartUpdate

.PHONY : CMakeFiles/SmartUpdate.dir/build

CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/hs.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/mem_sim.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/pc_eval.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/tss.o.requires
CMakeFiles/SmartUpdate.dir/requires: CMakeFiles/SmartUpdate.dir/code/utils.o.requires

.PHONY : CMakeFiles/SmartUpdate.dir/requires

CMakeFiles/SmartUpdate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/SmartUpdate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/SmartUpdate.dir/clean

CMakeFiles/SmartUpdate.dir/depend:
	cd /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build /Users/zhoun14/Desktop/GithubWorkshop/PC/SmartUpdate/build/CMakeFiles/SmartUpdate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/SmartUpdate.dir/depend

