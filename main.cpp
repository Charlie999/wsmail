#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "websocketpp/config/asio_client.hpp"
#include "websocketpp/client.hpp"
#include "utils.h"
#include "base64.h"

#include <iostream>
#include <fstream>
#include <io.h>
#include <direct.h>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;
typedef std::shared_ptr<boost::asio::ssl::context> context_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 8192

websocketpp::connection_hdl HDL = std::weak_ptr<void>();
int fail = 0;
int ws_open = 0;

auto listen_sock = INVALID_SOCKET;
auto client_sock = INVALID_SOCKET;

int server(int, const char*, const char*);
int server(const char*, const char*, const char*);
DWORD WINAPI wsclient(LPVOID);

typedef struct {
    std::string url;
    std::string port;
    std::string ac;
} server_conf;

typedef struct {
    HANDLE stdout_rd;
    char* tname;
} child_info;

void on_open(client* c, websocketpp::connection_hdl hdl) {
    sync_printf("websocket connection opened\n");
    HDL = hdl;
    ws_open = 1;
}

void on_message(client* c, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::string toSend = base64_decode(msg->get_raw_payload());
    //sync_printf("[WS=>TCP] %u %s\n",toSend.size(),msg->get_raw_payload().c_str());
    int iSendResult = send(client_sock, toSend.data(), toSend.length(), 0 );
    if (iSendResult == SOCKET_ERROR) {
        sync_printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(client_sock);
        WSACleanup();
        c->close(hdl,websocketpp::close::status::normal,"I/O error");
    }
}

void on_close(client* c, websocketpp::connection_hdl hdl) {
    sync_printf("websocket connection closed\n");
    HDL = std::weak_ptr<void>();
    closesocket(client_sock);
}

void on_fail(client* c, websocketpp::connection_hdl hdl) {
    sync_printf("websocket connection failed, trying again.\n");
    fail=1;
}

static context_ptr on_tls_init() {
    sync_printf("begin TLS init\n");
    context_ptr ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
        ctx->set_verify_mode(SSL_VERIFY_NONE);
    } catch (std::exception &e) {
        std::cout << "Error in context pointer: " << e.what() << std::endl;
    }
    return ctx;
}

DWORD WINAPI child_io_rcv(LPVOID c) {
    DWORD dwRead;
    CHAR chBuf[1];
    BOOL bSuccess = FALSE;
    child_info* ci = (child_info*)c;
    HANDLE child_rd_out = ci->stdout_rd;

    std::string d;

    for (;;)
    {
        bSuccess = ReadFile(child_rd_out, chBuf, 1, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break;

        if (chBuf[0] == '\n') {
            /*bSuccess = WriteFile(hParentStdOut, d.c_str(),
                                 d.size(), &dwWritten, NULL);
            if (! bSuccess ) break;*/
            sync_printf("[%s] %s%c",ci->tname, d.c_str(), chBuf[0]);
            d = std::string();
        } else {
            d.push_back(chBuf[0]);
        }
    }

    sync_printf("[%s] child i/o thread dead\n",ci->tname);

    return 0;
}

HANDLE fork_(char* me, char* url, char* port, char* ac) {
    sync_printf("Forking..\n");
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;

    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0) ) {
        sync_printf("CreatePipe failed (%d).\n", GetLastError());
        return nullptr;
    }

    if (!SetHandleInformation(child_stdout_rd, HANDLE_FLAG_INHERIT, 0)) {
        sync_printf("SetHandleInformation failed (%d).\n", GetLastError());
        return nullptr;
    }

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    si.hStdError = child_stdout_wr;
    si.hStdOutput = child_stdout_wr;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory( &pi, sizeof(pi) );

    std::string cmd = std::string(me);
    cmd = cmd.append(" "); // wss://i-am.cool/gmail/smtp
    cmd = cmd.append(url);
    cmd = cmd.append(" "); // 5260
    cmd = cmd.append(port);
    cmd = cmd.append(" ");
    cmd = cmd.append(ac);

    sync_printf("starting with %s\n",cmd.c_str());

    DWORD dwThreadIdArray[1];
    child_info* ch_i = (child_info*)malloc(sizeof(child_info));
    ch_i->stdout_rd = child_stdout_rd;
    ch_i->tname = port;
    CreateThread(
            NULL,
            0,
            child_io_rcv,
            (void*)ch_i,
            0,
            &dwThreadIdArray[0]);

    if( !CreateProcess( NULL,   // No module name (use command line)
                        (char*)cmd.c_str(),        // Command line
                        NULL,           // Process handle not inheritable
                        NULL,           // Thread handle not inheritable
                        TRUE,          // Set handle inheritance to FALSE
                        0,              // No creation flags
                        NULL,           // Use parent's environment block
                        NULL,           // Use parent's starting directory
                        &si,            // Pointer to STARTUPINFO structure
                        &pi )           // Pointer to PROCESS_INFORMATION structure
            ){
        sync_printf( "CreateProcess failed (%d).\n", GetLastError());
        CloseHandle(child_stdout_rd);
        return nullptr;
    }

    return pi.hProcess;
}

int main(int argc, char** argv) {
    if (argc==1) {
        printf("reading configuration\n");
        std::ifstream ifs("config.txt"); // tab-delimted config file in format
        // URL  PORT    AUTHCODE
        std::string line;

        if (!ifs.good()) {
            char tmp[512];
            _getcwd(tmp, 512);
            printf("ERROR! config.txt does not exist in %s\n",tmp);
            return 1;
        }

        std::vector<server_conf> configs = std::vector<server_conf>();

        while(std::getline(ifs, line)) {
            std::string line2 = replace_all(line, std::string("\n"), std::string(""));
            std::vector<std::string> la = split(line2, '\t');
            if (la.size() == 3) {
                printf("[CONF] %s\n", line2.c_str());
                server_conf conf;
                conf.url = la.at(0);
                conf.port = la.at(1);
                conf.ac = la.at(2);
                configs.push_back(conf);
            }
        }

        printf("loaded %d configs\n",configs.size());

        HANDLE handles[configs.size()];

        for (int i=0;i<configs.size();i++) {
            //handles[i] = fork_(argv[0], (char *) "wss://i-am.cool/gmail/smtp", (char *) "5260",
            //                   (char *) "rUR83t2uFT9zNYCs");
            handles[i] = fork_(argv[0], (char *)configs.at(i).url.c_str(), (char *)configs.at(i).port.c_str(),
                              (char *)configs.at(i).ac.c_str());
        }

        for (int i=0;i<configs.size();i++) {
            WaitForSingleObject(handles[i], INFINITE);
        }
        return 0;
    }

    if (argc!=4) {
        fprintf(stderr, "Usage: ./%s [ws URL] [port] [authcode]", argv[0]);
        return 1;
    }
    sync_printf("starting with URL=%s PORT=%s\n",argv[1],argv[2]);
    while (true) {
        int r = server(argv[2], argv[1], argv[3]);
        sync_printf("server terminated: %d\n",r);
        if (r!=0)
            break;
    }
}

int server(int port, const char* url, const char* ac) {
    return server(std::to_string(port).c_str(), url, ac);
}

DWORD WINAPI wsclient(LPVOID c) {
    try {
        ((client *) c)->run();
    } catch (const std::exception & e) {
        std::cout << e.what() << std::endl;
        HDL = std::weak_ptr<void>();
    }

    return 0;
}

int server(const char* port, const char* url, const char* authcode)
{
    try {
        WSADATA wsaData;
        int res;

        std::string ws_uri = std::string(url);

        struct addrinfo *result = NULL;
        struct addrinfo hints;

        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;

        res = WSAStartup(0x0202, &wsaData);
        if (res != 0) {
            sync_printf("WSAStartup failed with error: %d\n", res);
            return 1;
        }

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        res = getaddrinfo(NULL, port, &hints, &result);
        if (res != 0 ) {
            sync_printf("getaddrinfo failed with error: %d\n", res);
            WSACleanup();
            return 1;
        }

        listen_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (listen_sock == INVALID_SOCKET) {
            sync_printf("socket failed with error: %ld\n", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();
            return 1;
        }

        res = bind(listen_sock, result->ai_addr, (int)result->ai_addrlen);
        if (res == SOCKET_ERROR) {
            sync_printf("bind failed with error: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            closesocket(listen_sock);
            WSACleanup();
            return 1;
        }

        freeaddrinfo(result);

        res = listen(listen_sock, SOMAXCONN);
        if (res == SOCKET_ERROR) {
            sync_printf("listen failed with error: %d\n", WSAGetLastError());
            closesocket(listen_sock);
            WSACleanup();
            return 1;
        }

        sync_printf("waiting for connection on %s\n", port);
        client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) {
            sync_printf("accept failed with error: %d\n", WSAGetLastError());
            closesocket(listen_sock);
            WSACleanup();
            return 1;
        }
        sync_printf("serving client on %s\n", port);

        closesocket(listen_sock);

        init_ws:

        client c;

        c.clear_access_channels(websocketpp::log::alevel::frame_header);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);

        sync_printf("connecting to websocket at %s\n",ws_uri.c_str());
        c.init_asio();

        c.set_tls_init_handler(bind(&on_tls_init));

        c.set_open_handler(bind(&on_open,&c,::_1));
        c.set_message_handler(bind(&on_message,&c,::_1,::_2));
        c.set_close_handler(bind(&on_close,&c,::_1));
        c.set_fail_handler(bind(&on_fail,&c,::_1));

        c.set_user_agent("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36");

        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(ws_uri, ec);
        if (ec) {
            std::cout << "could not create connection: " << ec.message() << std::endl;
            return 0;
        }

        DWORD   dwThreadIdArray[1];

        c.connect(con);
        CreateThread(
                NULL,
                0,
                wsclient,
                &c,
                0,
                &dwThreadIdArray[0]);

        sync_printf("waiting for ws connect, please wait.\n");
        while (is_uninitialized(HDL) && fail==0 && ws_open == 0) {
            //printf("%d %d %d\n",is_uninitialized(HDL),fail,ws_open);
            std::this_thread::yield();
        }
        if (fail>0) {
            //sync_printf("ws error, killing server thread.");
            //closesocket(client_sock);
            //WSACleanup();
            //fail = 0;
            //return 0;
            fail = 0;
            ws_open = 0;
            HDL = std::weak_ptr<void>();
            goto init_ws;
        }
        ws_open = 0;

        sync_printf("sending auth packet to ws\n");

        c.send(HDL,std::string(base64_encode(std::string(authcode))),websocketpp::frame::opcode::TEXT);

        sync_printf("connected to ws, continuing.\n");

        do {
            memset(recvbuf, 0, recvbuflen);
            res = recv(client_sock, recvbuf, recvbuflen, 0);
            if (is_uninitialized(HDL))
                break;
            if (res > 0 && !is_uninitialized(HDL)) {
                recvbuf[res] = 0;
                std::string toSend = replace_all(base64_encode(reinterpret_cast<const unsigned char *>(&recvbuf), res, false), std::string("."), std::string("="));
                if (is_uninitialized(HDL)) {
                    break;
                }
                //sync_printf("[TCP=>WS] %u %s\n",res, toSend.c_str());
                c.send(HDL,toSend,websocketpp::frame::opcode::TEXT);
            } else {
                wchar_t *s = NULL;
                FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, WSAGetLastError(),
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPWSTR)&s, 0, NULL);
                if (WSAGetLastError()!=0)
                    sync_printf("recv failed with error %i: %S", WSAGetLastError(), s);
                else
                    sync_printf("peer disconnected\n");
                LocalFree(s);
                c.close(HDL, websocketpp::close::status::normal, "");
                sync_printf("waiting for websocket connection to stop\n");
                while (!c.stopped()) {}
                closesocket(client_sock);
                WSACleanup();
                return 0;
            }

        } while (res > 0);

        res = shutdown(client_sock, SD_SEND);
        if (res == SOCKET_ERROR) {
            sync_printf("shutdown failed with error: %d\n", WSAGetLastError());
            c.close(HDL, websocketpp::close::status::normal, "");
            sync_printf("waiting for websocket connection to stop\n");
            while (!c.stopped()) {}
            closesocket(client_sock);
            WSACleanup();
            return 0;
        }

        // cleanup
        c.close(HDL, websocketpp::close::status::normal, "");
        sync_printf("waiting for websocket connection to stop\n");
        while (!c.stopped()) {}
        closesocket(client_sock);
        WSACleanup();

        return 0;
    } catch (const std::exception & e) {
        std::cout << e.what() << std::endl;
        HDL = std::weak_ptr<void>();
        return 0;
    }
}
