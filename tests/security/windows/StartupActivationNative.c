/* Fixed hosted activation-context observation; no CRT, target execution or input selector. */
#include "startup-activation-input.h"

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef int BOOL;
typedef struct {
    DWORD size, flags;
    const WORD *source;
    WORD architecture, language;
    const WORD *directory, *resource, *application;
    HANDLE module;
} FixedActCtx;

__declspec(dllimport) HANDLE __stdcall CreateActCtxW(FixedActCtx *context);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall ReleaseActCtx(HANDLE context);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD kind);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *data, DWORD bytes, DWORD *written, void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);

typedef char SizeCheck[sizeof(FixedActCtx) == 56 ? 1 : -1];
#define OFFSET(field) ((unsigned long long)&(((FixedActCtx *)0)->field))
typedef char OffsetCheck[(OFFSET(size) == 0 && OFFSET(flags) == 4 && OFFSET(source) == 8 &&
    OFFSET(architecture) == 16 && OFFSET(language) == 18 && OFFSET(directory) == 24 &&
    OFFSET(resource) == 32 && OFFSET(application) == 40 && OFFSET(module) == 48) ? 1 : -1];

void __stdcall StartupEntry(void)
{
    FixedActCtx context;
    HANDLE result, output;
    DWORD error, written = 0, index, length = 0;
    BOOL success;
    char line[256];
    const char *part;
    static const char hex[] = "0123456789ABCDEF";
    context.size = 56;
    context.flags = 0x2E;
    context.source = fixed_python;
    context.architecture = 0;
    context.language = fixed_language;
    context.directory = fixed_directory;
    context.resource = (const WORD *)1;
    context.application = fixed_python;
    context.module = 0;
    result = CreateActCtxW(&context);
    error = result == (HANDLE)-1 ? GetLastError() : 0;
    success = result != (HANDLE)-1 && result != 0;
    if (success) ReleaseActCtx(result);
    if (result == 0 || (!success && error == 0)) ExitProcess(120);
    part = "WINDOWS_CHILD_ACTIVATION created=";
    while (*part) line[length++] = *part++;
    part = success ? "True" : "False";
    while (*part) line[length++] = *part++;
    part = " win32_error=0x";
    while (*part) line[length++] = *part++;
    for (index = 0; index < 8; index++) line[length++] = hex[(error >> ((7 - index) * 4)) & 15];
    part = " cause_claimed=False child_equivalence_claimed=False\n";
    while (*part) line[length++] = *part++;
    output = GetStdHandle((DWORD)-11);
    if (output == 0 || output == (HANDLE)-1 ||
        !WriteFile(output, line, length, &written, 0) || written != length) ExitProcess(121);
    ExitProcess(0);
}
