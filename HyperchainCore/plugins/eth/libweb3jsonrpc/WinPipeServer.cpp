// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2015-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include "WinPipeServer.h"

#include <libdevcore/FileSystem.h>
#include <libdevcore/Guards.h>

using namespace std;
using namespace jsonrpc;
using namespace dev;

static int constexpr c_bufferSize = 1024;

WindowsPipeServer::WindowsPipeServer(string const& _appId)
  : IpcServerBase("\\\\.\\pipe\\" + getIpcPath().string() + "\\" + _appId + ".ipc")
{
    m_hstop = CreateEvent(NULL, TRUE, FALSE, NULL);
}

void WindowsPipeServer::CloseConnection(HANDLE _socket)
{
    ::CloseHandle(_socket);
}

size_t WindowsPipeServer::Write(HANDLE _connection, std::string const& _data)
{
    DWORD written = 0;
    ::WriteFile(_connection, _data.data(), _data.size(), &written, nullptr);
    return written;
}

size_t WindowsPipeServer::Read(HANDLE _connection, void* _data, size_t _size)
{
    DWORD read;
    ::ReadFile(_connection, _data, _size, &read, nullptr);
    return read;
}

void WindowsPipeServer::Listen()
{
    //std::list<HANDLE> handlers;
    while (m_running)
    {
        HANDLE socket =
            CreateNamedPipe(m_path.c_str(), PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES, c_bufferSize, c_bufferSize, 0, nullptr);

        DEV_GUARDED(x_sockets)
        m_sockets.insert(socket);

        if (ConnectNamedPipe(socket, nullptr) != 0)
        {
            if (WaitForSingleObject(m_hstop, 0) == WAIT_OBJECT_0) {
                printf("\tWindowsPipeServer has stopped\n");
                //HC: 遗留问题 当外部客户端连接到Pipe不关闭时，HC依然无法退出,阻塞在CloseConnection里，除非客户端退出
                //HC: 用强制关闭线程方式依然不行
                //for (auto &t : handlers) {
                    //DisconnectNamedPipe(t);
                    //CloseHandle(t);
                    //TerminateThread(t, -1);
                //}
                break;
            }
            std::thread handler([this, socket]() { GenerateResponse(socket); });
            handler.detach();
            //handlers.push_back(handler.native_handle());
        }
        else
        {
            DEV_GUARDED(x_sockets)
            m_sockets.erase(socket);
        }
    }
}

//HC: Connect to pipe server and stop it
bool WindowsPipeServer::StopListening()
{
    SetEvent(m_hstop);
    HANDLE hPipe = CreateFile(m_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    return IpcServerBase<HANDLE>::StopListening();
}
