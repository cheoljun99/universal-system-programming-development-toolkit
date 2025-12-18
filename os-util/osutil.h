#pragma once

#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include "ip.h"
#include "mac.h"
#include "arphdr.h"
#include "ethhdr.h"
    #if defined(_WIN32) || defined(_WIN64)
        // Windows 헤더
        #include <winsock2.h>
        #pragma comment(lib, "ws2_32.lib")
    #elif defined(__linux__)
        // 리눅스 헤더
        #include <unistd.h>
        #include <linux/types.h>
        #include <linux/netfilter.h>
        #include <libnetfilter_queue/libnetfilter_queue.h>
        extern char **environ; // posix_spawnp에 필요한 환경 변수
    #endif
namespace OsUtil {
    #if defined(_WIN32) || defined(_WIN64)
        SOCKET get_tcp_socket(Ip source_ip, uint16_t source_port);
        SOCKET get_udp_socket(Ip source_ip, uint16_t source_port);
        int close_socket(SOCKET socket);
        int close_handle(HANDLE handle);
    #elif defined(__linux__)
        // Utility 명령어 사용 함수
        int exec_cmd_util(const std::vector<std::string>& args);
        // 오프로드 제어 함수
        bool set_offload(const char* source_nic, __u32 cmd, const char* name, bool enable);
        // 시그널 핸들러 등록 함수
        bool set_signal_handler(int signal, void (*handler_func)(int));
        // epoll fd 할당 함수
        int get_epoll_fd();
        // fd 리소스 해제 함수
        int close_fd(int fd);
        // epll fd 설정 함수
        int ctl_epoll_fd(int epoll_fd, int option, int target_fd, int flags);
        //ipv4 nfq 핸들 오픈 함수
        struct nfq_handle* open_nfq_ipv4_handle();
        //ipv4 nfq 큐 생성 함수
        struct nfq_q_handle* create_nfq_q_ipv4_handle(struct nfq_handle* nfq_ipv4_handle, uint16_t nfq_q_num, nfq_callback* nfq_callback_func, void* nfq_callback_arg);
        //nfq fd 할당 함수
        int get_nfq_fd(struct nfq_handle* _nfq_handle);
        // nfq 리소스 해제 함수
        int close_nfq(struct nfq_handle* _nfq_handle, nfq_q_handle* _nfq_q_handle);
        // l2 raw_socket 할당 함수
        int get_l2_raw_socket_fd(const char* source_nic);
        // bpf 필터 적용 함수
        int set_bpf_filter(int fd, const std::string& filter_str);
        // bpf 필터 제거 함수
        int del_bpf_filter(int fd);
        // fd 논블럭 설정 함수
        int set_nonblock_fd(int fd);
        // nic에서 ip를 가져오는 함수
        Ip get_source_ip(const char* source_nic);
        // nic에서 mac을 가져오는 함수
        Mac get_source_mac(const char* source_nic);
        // nic에서 mtu를 가져오는 함수
        int get_source_mtu(const char* source_nic);
        // target의 mac을 알아내는 함수
        Mac get_target_mac(const char* source_nic, Ip source_ip, Mac source_mac, Ip target_ip,uint64_t timeout);
        // tun fd 할당함수
        int get_tun_fd(const char* virtual_nic,int virtual_nic_mtu, Ip virtual_ip, Ip virtual_subnet);
        // tun fd 할당함수 오버로드
        int get_tun_fd(const char* virtual_nic);
        //서브넷 prefix 계산 함수
        int calc_subnet_prefix_len(Ip subnet);
        // tcp 소켓 fd 할당 함수
        int get_tcp_socket_fd(Ip source_ip, uint16_t source_port);
        // udp 소켓 fd 할당 함수
        int get_udp_socket_fd(Ip source_ip, uint16_t source_port);
        // l4 프로토콜 port 가져오는 함수
        int get_port_from_l4_socket_fd(int l4_socket_fd);
        // can 소켓 fd 할당 함수
        int get_can_socket_fd(const char* source_nic);

    #endif

}

