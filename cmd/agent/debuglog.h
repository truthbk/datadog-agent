#include <Windows.h>

__attribute__((constructor)) void dostuff() {
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL || GetStdHandle(STD_ERROR_HANDLE) != NULL)
    {
        // std handles are already set, don't overwrite them
        return;
    }

    HANDLE hout = CreateFileW(L"C:\\ProgramData\\Datadog\\logs\\agent-stdout.log", GENERIC_WRITE, FILE_READ_ACCESS | FILE_WRITE_ACCESS, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE herr = CreateFileW(L"C:\\ProgramData\\Datadog\\logs\\agent-stderr.log", GENERIC_WRITE, FILE_READ_ACCESS | FILE_WRITE_ACCESS, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    SetStdHandle(STD_OUTPUT_HANDLE, hout);
    SetStdHandle(STD_ERROR_HANDLE, herr);
}
