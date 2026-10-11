/* Trusted CI startup differential only: no CRT, input, buffers or target code. */
__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
void __stdcall StartupEntry(void)
{
    ExitProcess(0);
}
