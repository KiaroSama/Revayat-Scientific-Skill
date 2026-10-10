using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Native security ABI is kept separate from process/fixture policy.
    internal static class Native
    {
        internal const uint ExtendedStartup = 0x00080000, Suspended = 4, NoWindow = 0x08000000;
        internal const uint UnicodeEnvironment = 0x400, TokenQuery = 8;
        internal static readonly IntPtr InvalidHandle = new IntPtr(-1);
        [StructLayout(LayoutKind.Sequential)] internal struct Startup
        {
            internal uint cb;
            internal IntPtr reserved, desktop, title;
            internal uint x, y, width, height, charsX, charsY, fill, flags;
            internal ushort show, reservedSize;
            internal IntPtr reservedBytes, input, output, error;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct StartupEx
        { internal Startup startup; internal IntPtr attributes; }
        [StructLayout(LayoutKind.Sequential)] internal struct ProcessInfo
        { internal IntPtr process, thread; internal uint pid, tid; }
        [StructLayout(LayoutKind.Sequential)] internal struct SecurityCapabilities
        { internal IntPtr sid, capabilities; internal uint count, reserved; }
        [StructLayout(LayoutKind.Sequential)] internal struct BasicLimits
        {
            internal long processTime, jobTime;
            internal uint flags;
            internal UIntPtr minWorkingSet, maxWorkingSet;
            internal uint processes;
            internal UIntPtr affinity;
            internal uint priority, scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct IoCounters
        { internal ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
        [StructLayout(LayoutKind.Sequential)] internal struct ExtendedLimits
        {
            internal BasicLimits basic;
            internal IoCounters io;
            internal UIntPtr processMemory, jobMemory, peakProcess, peakJob;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct CpuLimits
        { internal uint flags, rate; }
        [StructLayout(LayoutKind.Sequential)] internal struct Accounting
        {
            internal long userTime, kernelTime, periodUser, periodKernel;
            internal uint faults, totalProcesses, activeProcesses, terminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes
        { internal uint size; internal IntPtr descriptor; internal int inherit; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetInformationJobObject(IntPtr job, int kind, IntPtr value, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool QueryInformationJobObject(IntPtr job, int kind, IntPtr value, uint length, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr bytes);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
            IntPtr value, IntPtr bytes, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcessW(string application, StringBuilder command,
            IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags,
            IntPtr environment, string cwd, ref StartupEx startup, out ProcessInfo info);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr CreateFileW(string path, uint access, uint sharing,
            ref SecurityAttributes attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreatePipe(out IntPtr reader, out IntPtr writer, ref SecurityAttributes attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CancelIoEx(IntPtr handle, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadFile(IntPtr file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr value, uint size, out uint returned);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool SetTokenInformation(IntPtr token, int kind, IntPtr value, uint size);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
        [DllImport("advapi32.dll")] internal static extern IntPtr FreeSid(IntPtr sid);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFree(IntPtr address, UIntPtr size, uint kind);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputBytes,
            IntPtr output, uint outputBytes, out uint returned, IntPtr overlapped);
        internal static void Check(bool value, string operation)
        {
            if (!value) {
                int code = Marshal.GetLastWin32Error();
                throw new Win32Exception(code, operation + " win32=" + code + " system=" + new Win32Exception(code).Message);
            }
        }
        internal static IntPtr Structure<T>(T value)
        {
            IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            Marshal.StructureToPtr(value, memory, false);
            return memory;
        }
        internal static T QueryJob<T>(IntPtr job, int kind)
        {
            IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            try
            {
                Check(QueryInformationJobObject(job, kind, memory, (uint)Marshal.SizeOf(typeof(T)), IntPtr.Zero), "query job");
                return (T)Marshal.PtrToStructure(memory, typeof(T));
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        internal static void SetJob<T>(IntPtr job, int kind, T value)
        {
            IntPtr memory = Structure(value);
            try { Check(SetInformationJobObject(job, kind, memory, (uint)Marshal.SizeOf(typeof(T))), "set job limits"); }
            finally { Marshal.FreeHGlobal(memory); }
        }
    }
}
