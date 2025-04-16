# IATPhantom 🕵
---
## Description 🌟

**IATPhantom** is a C++ library designed for stealth-based dynamic function invocation. It allows you to load DLLs and invoke functions dynamically without leaving any traces in the Import Address Table (IAT), making it harder for traditional security mechanisms to detect or analyze the application. This is particularly useful in low-level applications where security, privacy, and evasion are critical.

> **Disclaimer:**  
> This tool **does not hide string literals** (e.g., DLL names or function names) but specifically hides function calls from the IAT. It's designed for use cases where stealth is required in function resolution, but it’s important to understand that string literals remain exposed.

**IATPhantom** will attempt to load DLLs like `user32.dll` through the IAT by default. However, this DLL isnt preloaded (common in console apps), it will fall back to `CustomGetModuleHandleW` and `CustomGetProcAddress` to resolve and invoke the functions dynamically (LoadLibrary).

## Features ✨
- **Stealth Function Calls:** Functions are called without appearing in the IAT, making it harder to detect.
- **Dynamic DLL Loading:** Load DLLs dynamically at runtime, bypassing IAT references.
- **Encrypted Calls:** Functions are invoked in an encrypted manner to add another layer of protection.
- **Flexible Integration:** Seamlessly integrates into your project without modifying the core structure.
- **Error Handling:** If a DLL or function cannot be loaded or resolved, clear error messages will be displayed.

## Usage Example 💡

Here’s how to use **IATPhantom** to invoke functions from DLLs dynamically, even if the DLLs are not pre-loaded:

```cpp
#include <Windows.h>
#include <iostream>
#include "IATPhantom.hpp"

int main() {
    // Dynamically invoke MessageBoxA from user32.dll
    int result = CALL_ENCRYPTED(
        L"user32.dll",           // DLL name
        "MessageBoxA",           // Function name
        int,                     // Return type
        NULL,                    // First argument (HWND)
        "Hello from IATPhantom", // Message to display
        "Encrypted API-Test",    // Title of the message box
        MB_OK                    // MessageBox style
    );

    std::cout << "MessageBoxA returned: " << result << std::endl;

    // Dynamically invoke ExitProcess from kernel32.dll to exit the process
    CALL_ENCRYPTED(
        L"kernel32.dll",   // DLL name
        "ExitProcess",     // Function name
        void,              // Return type (void, since it doesn't return anything)
        999                // Exit code
    );

    return 0;
}
```

## How It Works 🛠️
1. **Custom DLL Handling:** If the DLL isn't already loaded, it will be loaded dynamically.
2. **No IAT Entries:** Functions are resolved and called dynamically at runtime without leaving any trace in the IAT, which makes it harder for traditional analysis tools to detect the calls.

> **Note:** If the specified DLL (e.g., `user32.dll`) is not already loaded, **IATPhantom** will attempt to load the DLL using `CustomGetProcAddress` or `CustomGetModuleHandleW`. This ensures that the program can still proceed without relying on the IAT.

---

## Setup 🚀

1. **Include the header in your project:**
   Add `IATPhantom.hpp` to your project's include path.

2. **Use `CALL_ENCRYPTED` to invoke functions:**
   Use the macro as shown in the example to dynamically invoke functions from any DLL.

---

## Requirements ⚙️
- **Windows OS**: This library works on Windows platforms only.
- **C++17 or later**: The code is designed for C++17 and may not work properly on earlier versions.
- **Visual Studio** or any compatible C++ compiler.

---

## License 📄
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

