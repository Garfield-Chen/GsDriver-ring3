# GsDriver-ring3

A feature-rich Windows kernel-mode driver for advanced system operations, process manipulation, and memory management. Designed for research/educational purposes.

## Features

### Process Operations
- Attach to processes by name
- Hide processes from system visibility
- Force terminate processes
- Process protection (anti-kill)
- Process base/module address retrieval

### Memory Management
- Read/Write physical/virtual memory
- Allocate/Free virtual memory
- Memory protection modification
- Memory region hiding
- Memory pattern scanning

### System Operations
- File force deletion
- Hardware ID spoofing
- Direct input simulation (mouse/keyboard)
- Window anti-screenshot protection
- Handle privilege escalation

### Injection Capabilities
- DLL/Shellcode injection
- Remote thread creation
- Protected process injection

## Requirements
- Windows 10/11 x64
- Administrative privileges
- Test signing enabled (for driver loading)
- Visual Studio 2019+ (for compilation)

## Installation
1. Clone repository
2. Build solution in Release mode
3. Load driver using included loader:
```cpp
Loader loader;
if (!loader.Load("driver.sys")) {
    // Handle error
}
