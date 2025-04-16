#pragma once

#include <Windows.h>
#include <wchar.h>
#include <string>
#include <iostream>
#include <type_traits>
#include "PEB.h"

namespace HiddenCalls {
    HMODULE CustomGetModuleHandleW(LPCWSTR dllName);
    FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
    HMODULE LoadLibraryIndirect(LPCWSTR dllName);
    // definitions
}

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)((LPBYTE)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif

namespace HiddenCalls {
    static wchar_t* extractor(LPCWSTR str1) {
        static wchar_t dll_str[50];
        int len = wcslen(str1);
        int loop_from = 0;

        for (int i = len - 1; i >= 0; i--) {
            if (str1[i] == L'\\') {
                loop_from = i + 1;
                break;
            }
        }

        int incre = 0;
        for (int j = loop_from; j < len + 1; j++) {
            dll_str[incre++] = str1[j];
        }

        dll_str[incre] = L'\0';
        return dll_str;
    }

    static HMODULE CustomGetModuleHandleW(LPCWSTR dllName) {
        PPEB PEB_pointer = nullptr;
#ifdef _WIN64
        PEB_pointer = (PPEB)__readgsqword(0x60); // -> use obfusheader and put OBF() around it, that way this wont be triggered on WD by static analysis. (OBF(0X60))
#elif _WIN32
        PEB_pointer = (PPEB)__readfsdword(0x30);// // -> use obfusheader and put OBF() around it, that way this wont be triggered on WD by static analysis. (OBF(0X30))
#endif

        PPEB_LDR_DATA Ldr_pointer = PEB_pointer->LoaderData;
        PLIST_ENTRY head = &(Ldr_pointer->InMemoryOrderModuleList);
        PLIST_ENTRY current_Position = head->Flink;

        while (current_Position != head) {
            PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(current_Position, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (module->FullDllName.Length != 0) {
                if (_wcsicmp(extractor(module->FullDllName.Buffer), dllName) == 0) {
                    return (HMODULE)module->DllBase;
                }
            }
            current_Position = current_Position->Flink;
        }

        HMODULE hLoaded = LoadLibraryIndirect(dllName);
        if (!hLoaded) {
            std::wcerr << L"[!] Failed to load DLL from disk: " << dllName << std::endl; // you can comment this out
        }
        else {
            std::wcout << L"[+] Loaded DLL from disk: " << dllName << std::endl; // you can comment this out
        }
        return hLoaded;
    }

    static HMODULE LoadLibraryIndirect(LPCWSTR dllName) {
        HMODULE hKernel32 = CustomGetModuleHandleW(L"kernel32.dll");  
        if (!hKernel32) {
            std::wcerr << L"[!] Failed to get kernel32.dll module handle." << std::endl; // you can comment this out
            return nullptr;
        }
        FARPROC loadLibraryWProc = CustomGetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibraryWProc) {
            std::wcerr << L"[!] Failed to resolve LoadLibraryW address!" << std::endl; // you can comment this out
            return nullptr;
        }
        auto evasiveLoadLibraryW = reinterpret_cast<HMODULE(WINAPI*)(LPCWSTR)>(loadLibraryWProc);
        return evasiveLoadLibraryW(dllName); // not really evasive but just loading it sigma way
    }

    static FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
        if (!hModule || !lpProcName) return nullptr;

        DWORD_PTR base = reinterpret_cast<DWORD_PTR>(hModule);
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
        auto ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);
        auto functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            if (strcmp(lpProcName, reinterpret_cast<LPCSTR>(base + names[i])) == 0) {
                return reinterpret_cast<FARPROC>(base + functions[ordinals[i]]);
            }
        }
        return nullptr;
    }

    template<typename Ret, typename... Args>
    static Ret CallEncryptedWithArgs(LPCWSTR dllName, LPCSTR procName, Args... args) {
        HMODULE hModule = CustomGetModuleHandleW(dllName);
        if (!hModule) {
            std::wcerr << L"[!] DLL not found: " << dllName << std::endl;
            return Ret();
        }

        auto proc = reinterpret_cast<Ret(*)(Args...)>(CustomGetProcAddress(hModule, procName));
        if (!proc) {
            std::cerr << "[!] Function not found: " << procName << std::endl;
            return Ret();
        }

        return proc(args...);
    }

} 

#define CALL_ENCRYPTED(dll, func, rettype, ...) \
    HiddenCalls::CallEncryptedWithArgs<rettype>(dll, func, __VA_ARGS__)
