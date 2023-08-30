#include <Windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

__attribute__((constructor)) void dostuff() {
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL || GetStdHandle(STD_ERROR_HANDLE) != NULL)
    {
        // std handles are already set, don't overwrite them
        return;
    }

    // open files
    HANDLE hout = CreateFileW(L"C:\\ProgramData\\Datadog\\logs\\agent-stdout.log", FILE_APPEND_DATA, FILE_READ_ACCESS | FILE_WRITE_ACCESS, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE herr = CreateFileW(L"C:\\ProgramData\\Datadog\\logs\\agent-stderr.log", FILE_APPEND_DATA, FILE_READ_ACCESS | FILE_WRITE_ACCESS, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // set handles picked up by golang
    if (INVALID_HANDLE_VALUE != hout)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, hout);
    }
    if (INVALID_HANDLE_VALUE != herr)
    {
        SetStdHandle(STD_ERROR_HANDLE, herr);
    }

    // log timestamp to differentiate runs
    if (INVALID_HANDLE_VALUE != herr)
    {
        int fd_err = _open_osfhandle((intptr_t)herr, _O_APPEND);
        if (-1 == fd_err)
        {
            goto msvcrt_err_end;
        }
        FILE *ferr = fdopen(fd_err, "a");
        if (NULL == ferr)
        {
            goto msvcrt_err_end;
        }
        SYSTEMTIME t;
        GetSystemTime(&t);
        fprintf(ferr, "%d-%02d-%02d %02d:%02d:%02d.%03d: agent starting\n",
            t.wYear,
            t.wMonth,
            t.wDay,
            t.wHour,
            t.wMinute,
            t.wSecond,
            t.wMilliseconds);
        fflush(ferr);
msvcrt_err_end: {}
    }

}
