#pragma once
#include <Windows.h>
#include <thread>
#include <string>
enum ExecutionMode;

namespace Communication {

    class NamedPipe {
    private:
        static constexpr const char* PIPE_NAME = "\\\\.\\pipe\\CloudyExecution";
        static constexpr DWORD BUFFER_SIZE = 65536;
        HANDLE hPipe;
        bool running;
        std::thread PipeThread;

    public:
        NamedPipe();
        ~NamedPipe();

        bool Start(ExecutionMode mode);
        void Stop();

    private:
        void HandleClient(ExecutionMode mode);

    public:
        static int InitializeNamePipe(ExecutionMode mode);
    };

}
