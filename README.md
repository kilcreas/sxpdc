# sxpdc
Open Source C code for IETF Scalable-Group Tag eXchage Protocol (SXP)

This readme describes SXP daemon.

1. About
2. Basic compilation
3. Advanced compilation options
4. SXPD configuration file
5. Running SXPD
6. Running SXPD test suite
7. Modifying run-time configuration
8. SXPD GDBUS interface
9. Source directory content


                              1. ABOUT SXPD
================================================================================
SXP daemon (SXPD) is software implementation of source-group tag exchange
protocol (SXP). SXP is control protocol used to propagate IP address to
sourge group tag (SGT) binding information across network devices.

Detailed documentaion about sxp protocol can be found in rfc draft:
http://tools.ietf.org/html/draft-smith-kandula-sxp-06

                            2. BASIC COMPILATION
================================================================================
Build system CMake is used for SXPD compilation.

Building SXPD:
Simply create directory which will be used by cmake to generate make rules and
also used as destination for compiled binary files. Change to this newly created
directory and call cmake command with path to SXPD source directory as one of
of the parameters. Once cmake is finished, invoke make.

Command line compilation example (assuming the sxpd source code is in ~/sxpd and
building in ~/build):

   # create and change directory to build files directory
   mkdir ~/build && cd ~/build

   # use cmake to generate make rules used to build linux SXPD binary
   cmake -DTARGET_BUILD_PLATFORM=linux ~/sxpd

   # build linux SXPD binary
   make all

                       3. ADVANCED COMPILATION OPTIONS
================================================================================
Sxpd project has these cmake configuration options:

   (1) (mandatory) target operating system cmake option:
      -DTARGET_BUILD_PLATFORM=<linux>

   (2) (optional) option to build SXPD binary with or without debug symbols:
      -DCMAKE_BUILD_TYPE=<Debug|Release>

   (3) (optional) option to build SXPD binary with or without d-bus interface.
       By default, d-bus interface is disabled.
       To know more about d-bus interface see section "SXPD GDBUS INTERFACE":
      -DENABLE_GDBUS_INTERFACE=false to disable d-bus
      -DENABLE_GDBUS_INTERFACE=<any other value> to enable d-bus

   (4) (optional) option to print all logging information to console:
       By default, log printing is disabled.
      -DENABLE_LOG_PRINTING=false to disable log printing
      -DENABLE_LOG_PRINTING=<any other value> to enable log printing
      
   (5) (optional) option to strictly check binding configuration:
       By default, binding configuration strict checker is enabled.
       -DENABLE_STRICT_BINDING_CFG_CHECK=false to disable option
       -DENABLE_STRICT_BINDING_CFG_CHECK=<any other value> to enable option

Detailed documentaion about CMake build-system can be found at:
http://www.cmake.org/documentation/

                         4. SXPD configuration file
================================================================================
SXP daemon is using libconfig-like format configuration file, not all options,
which libconfig allows/supports are used/allowed though. See "default.cfg" file
in the root SXPD source directory, which contains a commented example with all
options explained.

                              5. Running SXPD
================================================================================
SXP daemon can be run from the command-line with the default or user specified
parameters.

Usage:
<sxpd_binary_path> [config_file_path] [log_level] [pid_file_path]

sxpd_binary_path: path to sxpd binary

config_file_path: path to configuration file used by this SXPD instance

log_level: default log-level used by the SXPD instance,
    must be one of the following:
        alert: critical messages which require user interaction
        error: run-time error messages
        debug: debugging messages
        trace: detailed debugging messages
    NOTE: the log-level can be overriden in the configuration file, in which
    case, the log-level specified on command-line is used only until
    config-file log-level is read and applied

pid_file_path: path to file where SXPD will store its process ID

the default parameters are:

config_file_path: /etc/sxpd.cfg
log_level: error
pid_file_path: /tmp/sxpd.pid

                          6. Running SXPD test suite
================================================================================
SXPD tests can be stared from the command-line from build directory.

Command to run unit/topology testing:
    ctest

Command to run specific test:
    ctest -R <testname>

Command to run memory check testing:
    ctest -T MemCheck

Command to run code coverage testing:
    make sxpd_coverage

Static analysis testing requires different build command:
    scan-build -V cmake <compilation options>
Command to run static analysis testing:
    scan-build -V make -j4

                      7. Modifying run-time configuration
================================================================================
Modifying run-time configuration is possible by changing the configuration file,
which SXPD instance uses and then sending the HANGUP signal to the SXPD.
A convenience shell script, called sxpd-reload.sh is provided in the source code
root directory. The script reads the PID from the SXPD pid-file and sendts the
appropriate signal to the SXPD instance.

Example:

1. SXPD run with default parameters:

$ ./sxpd-reload.sh
No parameter specified, use default pid file location /tmp/sxpd.pid?y
  PID TTY          TIME CMD
30155 pts/14   00:00:00 sxpd
Success: sent configuration reload trigger to process 30155

2. SXPD with custom pid-file path /tmp/my_sxpd.pid

$ ./sxpd-reload.sh /tmp/my_sxpd.pid
  PID TTY          TIME CMD
30155 pts/14   00:00:00 sxpd
Success: sent configuration reload trigger to process 30155


                          8. SXPD GDBUS INTERFACE
================================================================================
SXPD defautly has no IPC interface to export any informations to other 
processes. SXPD can be optionally built with d-bus gdbus interface. Gdbus 
interface exports basic sxpd informations, IPv4 and IPv6 binding lists and peer
list. Gdbus interface is using "d-bus system bus" which requires to update 
d-bus configuration before using SXPD.

Example of debian d-bus configuration, which allows users of group nobody to 
connect system bus and own d-bus name "com.cisxo.sxpd":
configuration file path:
   /etc/dbus-1/system.d/com.cisco.sxpd.conf

configuration file content:
   <busconfig>
        <policy at_console="true">
                <allow own="com.cisco.sxpd"/>
        </policy>

        <policy group="nobody">
                <allow own="com.cisco.sxpd"/>
        </policy>

        <policy group="nobody">
                <allow send_destination="com.cisco.sxpd"
                       send_interface="com.cisco.sxpd"/>
        </policy>

        <policy context="default">
                <allow send_destination="com.cisco.sxpd"
                       send_interface="org.freedesktop.DBus.Introspectable" />
                <allow send_destination="com.cisco.sxpd"
                       send_interface="org.freedesktop.DBus.Properties" />
        </policy>
   </busconfig>

Detailed documentation about d-bus configuration can be found at:
http://dbus.freedesktop.org/doc/dbus-daemon.1.html

                        9. SOURCE DIRECTORY CONTENT
================================================================================
   <SXPD source root>/README.txt - this readme file.
   <SXPD source root>/default.cfg - default configuration file with
                                     documentation
   <SXPD source root>/license - SXPD source code license
   <SXPD source root>/inc - header files directory
   <SXPD source root>/src - source files directory
   <SXPD source root>/test - test files directory
   <SXPD source root>/linux - linux specific source and test files directory
