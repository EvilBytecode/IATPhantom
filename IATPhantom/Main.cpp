#include <Windows.h>
#include <iostream>
#include "IATPhantom.hpp"

int main() {
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

    CALL_ENCRYPTED(
        L"kernel32.dll",   // DLL name
        "ExitProcess",     // Function name
        void,              // Return type (void, since it doesn't return anything)
        999                // Exit code
    );

    return 0;
}