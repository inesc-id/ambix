# Ambix
Dynamic page placement for Hybrid multi-tiered architectures.

Thesis Project on extending placement mechanisms in order to consider an architecture that integrates Intel Optane Persistent Memory.

Ambix works with any architecture where Optane is configured in App Direct Mode, as system ram, i.e., as a NUMA node.
It also leverages a modified version of PCM (https://github.com/opcm/pcm).

# Installation

## Kernel Configuration:
  1. Download any recent version of the kernel from https://www.kernel.org, and add the following line at the bottom of the ```linux-{version}/mm/pagewalk.c``` file:
  ```
  EXPORT_SYMBOL(walk_page_range)
  ```
  2. Build and install the kernel following the usual procedure

## Post Boot Setup:
  1. Run ```sudo modprobe msr```
  
  Optional, but recommended:
  
  2. Disable NUMA balancing
  3. Set swappinness to 0
  4. Disable THPs

## Ambix Configuration:
  1. Download and unzip latest Ambix release.
  2. Go to ```ambix/src/``` and edit ```ambix.h```, setting the ```DRAM_NODES[]``` and ```NVRAM_NODES[]``` constants to the respective DRAM and NVRAM nodes that should be monitored by Ambix.
  3. (optional) Edit the ```ambix_hyb-mod.c``` file, chaging the "5.8.5-patched" in the ```MODULE_INFO(vermagic, "5.8.5-patched SMP mod_unload modversions ")``` line to the name of the current kernel version. If not done, a version mismatch warning will be printed in the kernel log.
  4. Compile the ```src/``` directory contents with ```make```
  
  7. Go to ```src/pcm-mod/``` and compile its contents with ```make```
  8. Move ```pcm-memory.x``` to the ```src/``` directory.

# Using Ambix:

1. Start Ambix by running the following commands:
  ```
  
    sudo make insert
    sudo ./pcm-memory.x
    ./ambix-hyb-ctl.o

  ```

 In order to bind processes to Ambix, multiple options are provided:

  A. Preferred Method (C/C++/Fortran):
  
  1. Add a ```bind_uds([pid])``` and ```unbind_uds([pid])``` calls to the start and end of a target application's source code. If application is Fortran add          ```[un|]bind_uds_ft()``` instead. Alternatively the ```[un|]bind_uds_ft()``` call also work for C/C++ applications without specifying a PID.

  2. Compile target binary with ambix_client.c (e.g. ```gcc [...] -c ambix_client.c```).

  B. Alternative Method 1 (any binary):
  1. Use the compiled bind.o and unbind.o (e.g. ```[binary] | PID=$! & ./bind.o $PID; wait; ./unbind.o $PID```).
    
  C. Alternative Method 2 (any binary):
  1. In the ambix_hyb-ctl.o CLI use the bind and unbind commands followed by the target binary's PID.
