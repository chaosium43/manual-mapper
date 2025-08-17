# Shellcode
This document explains the theory behind how shellcode is loaded and run by the injector.
## Loading Shellcode
In order for the shellcode to run properly, two things must be loaded with VirtualAllocEx. First, the parameters that the shellcode requires (like where the DLL was loaded and configuration for the injection process), and the shellcode itself. The shellcode <b>must</b> be marked as executable or DEP will crash the target process. Once these two items are loaded into the target process, a remote thread will be created to start running the Shellcode internally in the process.
## Note about RVA
Because the shellcode is a detached piece of code injected into a process, it does not have a proper IAT, and will not know where any relative function addresses live. All Windows functions that the shellcode uses <b>must</b> be passed directly via the shellcode parameters and called directly as a result.
## What the shellcode does
```
┌───────────────────────────────────────────────────────────────────────────────┐
│                            PE File Structure Analysis                         │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌───────────────────────┐        ┌───────────────────────┐                   │
│  │      DOS Header       │        │      PE Header        │                   │
│  │                       │        │                       │                   │
│  │  - e_magic: 'MZ'      │        │  - Signature: 'PE\0\0'│                   │
│  │  - e_lfanew: PE offset├───────►│  - Machine type       │                   │
│  └───────────────────────┘        │  - NumberOfSections   │                   │
│                                   └──────────┬────────────┘                   │
│                                              │                                │
│  ┌───────────────────────┐        ┌──────────▼────────────┐                   │
│  │   Section Headers     │        │   Optional Header     │                   │
│  │                       │        │                       │                   │
│  │  - .text              │        │  - Magic (PE32/PE32+) │                   │
│  │  - .rdata             │        │  - AddressOfEntryPoint│                   │
│  │  - .data              │        │  - ImageBase          │                   │
│  │  - .reloc             ├────────┤  - DataDirectories    │                   │
│  └───────────────────────┘        │    ├── Import Table   │                   │
│                                   │    └── Base Relocation Table              │
│                                   └───────────┬────────────┘                  │
│                                               │                               │
├───────────────────────────────────────┬───────┴───────────────────────────────┤
│        Relocation Addresses           │  Import Ordinals                      │
├───────────────────────────────────────┼───────────────────────────────────────┤
│                                       │              │                        │
│ 1. Locate .reloc section              │ 1. Locate Import Directory            │
│    or DataDirectory[5]                │                                       |
│                                       │    DataDirectory[1]                   |
│ 2. Parse relocation blocks:           │                                       │
│    ┌───────────────────────┐          │ 2. For each DLL in Import Directory:  │
│    │ IMAGE_BASE_RELOCATION │          │    ┌───────────────────────┐          │
│    ├───────────────────────┤          │    │IMAGE_IMPORT_DESCRIPTOR│          │
│    │  Page RVA             │          │    ├───────────────────────┤          │
│    │  Block Size           │          │    │  OriginalFirstThunk   │          │
│    ├───────────────────────┤          │    │  Name (DLL name)      │          │
│    │  Type+Offset entries  │          │    │  FirstThunk           │          │
│    └───────────────────────┘          │    └──────────┬────────────┘          │
│                                       │               │                       │
│ 3. For each entry:                    │ 3. Follow OriginalFirstThunk or       │
│    - Calculate RVA: Page RVA + Offset │    FirstThunk to IMAGE_THUNK_DATA:    │
│    - Type (usually IMAGE_REL_BASED_HIGHLOW)                                   │
│                                       │    ┌───────────────────────┐          │
│ 4. All addresses need relocation      │    │  IMAGE_THUNK_DATA     │          │
│    are collected                      │    ├───────────────────────┤          │
│                                       │    │  if Ordinal bit set:  │          │
│                                       │    │    Ordinal & 0xFFFF   │          │
│                                       │    │  else: Hint/Name RVA  │          │
│                                       │    └───────────────────────┘          │
└───────────────────────────────────────┴───────────────────────────────────────┘
```
### Fixing Imports
The shellcode grabs the address of the DLL Import Table and the Relocation table relative to the address the DLL was loaded at by reading optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress and optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress. Then, the shellcode will calculate the difference between the preferred base address of the DLL and the address the DLL is currently loaded at. If a difference exists, relocations must be fixed. The shellcode will fix relocations by parsing all relocation blocks in the relocation table (which starts at dllBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) until it finds the terminator entry (which has a VirtualAddress of 0). For each block, the shellcode gets the amount of entries in the block and the offset from the DLL base the entries start at. Then, every entry is iterated through and relocation is applied.
### Aside: Why relocatoins are necessary
Consider this snippet of code that is written for a DLL:
```cpp
int i = 0;
int *j = &i;
```
Suppose that the DLL preferred base is 0x100000, and that i is stored at an offset of 0x4 from the DLL's preferred base, then the compiler would initialize j's value to be 0x100004. If the DLL were to load at 0x200000, 0x100004 would point to some nonsense address not even within the DLL's address space. To fix this problem, 0x200000 - 0x100000 = 0x100000 could be added to j, so that it would point to i again. The relocation table simply stores the relative address of all value in a DLL that behaves like j, so that these addresses can be updated when a module is loaded into memory. Since the DLL injector is manually loading a module, each one of these relocations must also be fixed manually if necessary.
### Fixing imports
The injector then navigates to where the IAT for the DLL is located (dllBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) and imports all necessary dependencies. For each IMAGE_IMPORT_DESCRIPTOR entry in the IAT, the injector first goes to dllBase + entry.Name to get the name of the dependency, and calls LoadLibraryA to import the dependency. Then, the code will grab each thunk associated with the import (Usually, OriginalFirstThunk stores the import data related to a thunk and FirstThunk stores the address of the function the thunk should point to once the thunk is resolved but OriginalFirstThunk data sometimes get stored in FirstThunk initially which the shellcode accounts for). Each thunk is either import by ordinal (thunk->u1.Ordinal will have IMAGE_ORDINAL_FLAG set high if this is the case which you can check with thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG), or will be import by name. If a thunk is import by Ordinal, GetProcAddress can simply be called on the dependency with ordinal number specified. If it is import by name, the name to be imported is stored at dllBase + thunk->u1.AddressOfData->Name.
### Additional Steps
Once relocations and imports are fixed, DLLMain can be called safely. Depending on injection config, the shellcode may also do TLS callbacks and setup SEH for the DLL.
## Debugging Shellcode
Debugging shellcode presents a challenge as console I/O is unavailable. Therefore, a function called DebugMap has been created which does the same thing as ManualMap except it maps the target DLL into the injector process and directly calls the shellcode rather than injecting it. This means that printing can be used to debug issues with the shellcode. However, due to DEP, DllMain will not run properly as DebugMap does not mark injected DLL code as PAGE_EXECUTE_READWRITE by default.