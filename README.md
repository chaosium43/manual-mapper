# manual-mapper
My implementation of a DLL manual map injector with explanation of how each step works.
## How to use
In injector.hpp, there are two important functions, "Inject", and "ManualMap". If you simply want to use the manual mapper to quickly inject a DLL, include injector.hpp in a file and call Inject. Pass in the process name to inject into, the absolute path of the DLL to be injected, and the injector configuration. If you have a HANDLE to a process instead of a process name, use ManualMap instead and pass the same parameters you would normally pass to Inject but pass the HANDLE where the process name would go. <br>
To customize how the injector will inject a DLL, consider looking at line 16 in injector.hpp to get a list of all parameters the injection configuration takes.<br>
Note that depending on what process you are injecting into, the dependencies for a DLL may be unable to be loaded. For example, if trying to inject into a Chromium based web browser or Electron app, using the C++ standard library in a DLL will cause the DLL to be unloadabe due to the Chromium sandbox blocking injection of most DLLs via LoadLibrary, which the injector shellcode relies on to load target DLL dependencies.

## How to build (CMake)
You must be on 64 bit Windows 10 or newer versions of Windows to build this repository. <br>
You will also need the following dependencies to build this library: CMake and ucrt64 <br>
You can download CMake via winget (run "winget install cmake"), and ucrt64 can be downloaded from the following website: https://www.msys2.org/ <br>
To build the project, create a folder called "build" in the repository, then run the following commands: <br>
```
cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```
If all goes well, there should be two files that created, "testdll.dll", and "injector.exe". To verify that the program works correctly, open Notepad.exe on your computer and run injector.exe.

## How to build (Ninja)
Same prerequisites as with the CMake method, but with the additional requirement of installing Ninja. To install Ninja, run "winget install Ninja-build.ninja" on your computer. Then, build the project by running the following commands: <br>
```
cmake -G Ninja .. -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc
ninja
```
Then, to run the project, open Notepad.exe and run injector.exe.
