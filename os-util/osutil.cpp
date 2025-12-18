#include "osutil.h"
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <csignal>

#define MAX_BUFFER_SIZE 65535

#if defined(_WIN32) || defined(_WIN64)
    // Windows 헤더
#elif defined(__linux__)
    // Linux 헤더
    #include <unistd.h>
    #include <spawn.h>
    #include <sys/ioctl.h>
    #include <sys/wait.h>
    #include <sys/socket.h>
    #include <linux/can.h>
    #include <linux/can/raw.h>
    #include <sys/epoll.h>
    #include <net/if.h>
    #include <linux/sockios.h>
    #include <linux/ethtool.h>
    #include <linux/if_packet.h> 
    #include <linux/filter.h>
    #include <arpa/inet.h>
    #include <pcap.h>
    #include <fcntl.h>
    #include <linux/if_tun.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    //Windows 함수
    SOCKET OsUtil::get_tcp_socket(Ip source_ip, uint16_t source_port) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            std::cout << "[ERROR] Socket creation failed : " << WSAGetLastError()<<" "<<"\n";
            return INVALID_SOCKET;
        }
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = htonl(source_ip);
        serverAddr.sin_port = htons(source_port);
        if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << "[ERROR] Bind failed : " << WSAGetLastError() << " " << "\n";
            closesocket(sock);
            return INVALID_SOCKET;
        }
        return sock;
    }
    SOCKET OsUtil::get_udp_socket(Ip source_ip, uint16_t source_port) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) {
            std::cout << "[ERROR] Socket creation failed : " << WSAGetLastError() << " " << "\n";
            return INVALID_SOCKET;
        }
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = htonl(source_ip);
        serverAddr.sin_port = htons(source_port);
        if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << "[ERROR] Bind failed : " << WSAGetLastError() << " " << "\n";
            closesocket(sock);
            return INVALID_SOCKET;
        }
        return sock;
    }
    int OsUtil::close_socket(SOCKET socket) {
        if (socket != INVALID_SOCKET) {
            if (closesocket(socket) == SOCKET_ERROR) {
                std::cerr << "[ERROR] socket(" << socket << ") fail to closesocket: " << WSAGetLastError() <<" " << '\n';
                return -1;
            }
        }
        return 0;
    }
    int OsUtil::close_handle(HANDLE handle) {
        if (handle != INVALID_HANDLE_VALUE && handle != NULL) {
            if (CloseHandle(handle) == FALSE) {
                std::cerr << "[ERROR] handle(" << handle << ") fail to CloseHandle: " << GetLastError() << " " << '\n';
                return -1;
            }
        }
        return 0;
    }

#elif defined(__linux__)
    //Linux 함수
    int OsUtil::exec_cmd_util(const std::vector<std::string>& args) {
        pid_t pid;
        std::vector<char*> argv;
        for (const std::string& arg : args)
            argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);

        int status = posix_spawnp(&pid, argv[0], nullptr, nullptr, argv.data(), environ);
        if (status != 0) { perror("[ERROR] syscall posix_spawnp"); return -1; }
        if (waitpid(pid, &status, 0) == -1) { perror("[ERROR] syscall waitpid"); return -1; }
        if (WIFEXITED(status)) return WEXITSTATUS(status);

        fprintf(stderr, "[ERROR] Abnormal termination of child process\n");
        return -1;
    }

    bool OsUtil::set_offload(const char* source_nic, __u32 cmd, const char* name, bool enable) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("[ERROR] socket"); return false; }

        struct ethtool_value eval = {};
        struct ifreq ifr = {};
        std::strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        eval.cmd = cmd;
        eval.data = enable ? 1 : 0;
        ifr.ifr_data = (caddr_t)&eval;

        if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
            printf("Failed to %s %s on %s: %s\n", enable ? "enable" : "disable", name, source_nic, strerror(errno));
        else
            printf("%s %s on %s\n", enable ? "Enabled" : "Disabled", name, source_nic);

        close(fd);
        return true;
    }

    bool OsUtil::set_signal_handler(int signal, void (*handler_func)(int)) {
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler_func;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(signal, &sa, nullptr) == -1) {
            perror("[ERROR] sigaction");
            return false;
        }
        return true;
    }

    int OsUtil::get_epoll_fd(){
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            std::cerr<<"[ERROR] epoll_create1 : "<<strerror(errno)<<" "<< '\n';
            return -1;
        }
        return epoll_fd;
    }

    int OsUtil::close_fd(int fd) {
        if (fd != -1) {
            if (close(fd) == -1) {
                std::cerr << "[ERROR] fd(" << fd << ") fail to close: " << std::strerror(errno) << '\n';
                return -1;
            }
        } 
        return 0;
    }

    int OsUtil::ctl_epoll_fd(int epoll_fd, int option, int target_fd, int flags){
        struct epoll_event evt{};
        evt.events  = flags;
        evt.data.fd = target_fd;
        int ret;
        if (option == EPOLL_CTL_DEL) {
            ret = epoll_ctl(epoll_fd, option, target_fd, NULL);
        } else {
            ret = epoll_ctl(epoll_fd, option, target_fd, &evt);
        }
        if (ret == -1) {
            std::cerr << "[ERROR] epoll_ctl : " << strerror(errno) <<" "<<"\n";
        }
        return ret;
    }
    struct nfq_handle* OsUtil::open_nfq_ipv4_handle(){
        struct nfq_handle* nfq_ipv4_handle = nullptr;
        nfq_ipv4_handle = nfq_open();
        if (!nfq_ipv4_handle) {
            std::cerr<<"[ERROR] nfq_open : "<<strerror(errno)<<" "<< '\n';
            return nullptr;
        }
         // IPv4 unbind & bind
        if (nfq_unbind_pf(nfq_ipv4_handle, AF_INET) < 0) {
            std::cerr<<"[ERROR] nfq_unbind_pf : "<<strerror(errno)<<" "<< '\n';
            nfq_close(nfq_ipv4_handle);
            return nullptr;
        }
        if (nfq_bind_pf(nfq_ipv4_handle, AF_INET) < 0) {
            std::cerr<<"[ERROR] nfq_bind_pf : "<<strerror(errno)<<" "<< '\n';
            nfq_close(nfq_ipv4_handle);
            return nullptr;
        }
        return nfq_ipv4_handle;
    }

    struct nfq_q_handle* OsUtil::create_nfq_q_ipv4_handle(struct nfq_handle* nfq_ipv4_handle, uint16_t nfq_q_num, nfq_callback* nfq_callback_func, void* nfq_callback_arg){
        struct nfq_q_handle* nfq_q_ipv4_handle = nullptr;
        nfq_q_ipv4_handle = nfq_create_queue(nfq_ipv4_handle, nfq_q_num, nfq_callback_func, nfq_callback_arg);
        if (!nfq_q_ipv4_handle) {
            std::cerr<<"[ERROR] nfq_create_queue : "<<strerror(errno)<<" " << '\n';
            return nullptr;
        }
        // 패킷 복사 모드
        if (nfq_set_mode(nfq_q_ipv4_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
            std::cerr<<"[ERROR] nfq_set_mode : "<<strerror(errno)<<" " << '\n';
            nfq_destroy_queue(nfq_q_ipv4_handle);
            return nullptr;
        }
        return nfq_q_ipv4_handle;
    }

    int OsUtil::get_nfq_fd(struct nfq_handle* _nfq_handle){
        int _nfq_fd = nfq_fd(_nfq_handle);
        if (_nfq_fd == -1) {
            std::cerr<<"[ERROR] nfq_fd : "<<strerror(errno)<<" " << '\n';
            return -1;
        }
        return _nfq_fd;
    }

    int OsUtil::close_nfq(struct nfq_handle* _nfq_handle, nfq_q_handle* _nfq_q_handle){
        int chk=0;
        if (_nfq_q_handle != nullptr) {
            if (nfq_destroy_queue(_nfq_q_handle) == -1) {
                std::cerr << "[ERROR] nfq_destroy_queue failed " << '\n';
                chk++;
            }
        }
        if (_nfq_handle != nullptr) {
            if(nfq_close(_nfq_handle)==-1){
                std::cerr << "[ERROR] nfq_close failed "<< '\n';
                chk++;
            }
        }
        if(chk>0) return -1;
        else return 0;
    }
    int OsUtil::get_l2_raw_socket_fd(const char* source_nic){
        struct ifreq ifr;
        struct sockaddr_ll saddrll;
        int raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));// RAW 소켓 생성
        if (raw_socket_fd == -1) {
            std::cerr << "[ERROR] SOCK_RAW socket syscall : " << std::strerror(errno)<< '\n';
            return -1;
        }
        // 인터페이스 인덱스 가져오기
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(raw_socket_fd, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "[ERROR] SOCK_RAW ioctl SIOCGIFINDEX : " << std::strerror(errno)<< '\n';
            close(raw_socket_fd);
            return -1;
        }
        // 소켓 바인딩
        std::memset(&saddrll, 0, sizeof(saddrll));
        saddrll.sll_family = AF_PACKET;
        saddrll.sll_ifindex = ifr.ifr_ifindex;
        saddrll.sll_protocol = htons(ETH_P_ALL);
        if (bind(raw_socket_fd, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0) {
            std::cerr << "[ERROR] SOCK_RAW bind : " << std::strerror(errno) << '\n';
            close(raw_socket_fd);
            return -1;
        }
        return raw_socket_fd;
    }

    int OsUtil::set_bpf_filter(int fd, const std::string& filter_str){
        pcap_t* dummy_handle = pcap_open_dead(DLT_EN10MB, MAX_BUFFER_SIZE);
        if (!dummy_handle) {
			std::cerr << "[ERROR] Failed to open dummy pcap handle "<< '\n';
            return -1;
        }
        struct bpf_program fp;
        if (pcap_compile(dummy_handle, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
			std::cerr << "[ERROR] Failed to compile filter : " << pcap_geterr(dummy_handle) << '\n';
            pcap_close(dummy_handle);
            return -1;
        }
		// sock_fprog 구조체로 변환
		struct sock_fprog fprog;
		fprog.len = fp.bf_len;
		fprog.filter = (struct sock_filter*)fp.bf_insns;
        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
			std::cerr << "[ERROR] setsockopt SO_ATTACH_FILTER : " << std::strerror(errno) << '\n';
            pcap_freecode(&fp);
            pcap_close(dummy_handle);
            return -1;
        }
        pcap_freecode(&fp);
        pcap_close(dummy_handle);
        return 0;
    }

    int OsUtil::del_bpf_filter(int fd) {
        if (setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, nullptr, 0) ==-1) {
            std::cerr << "[ERROR] setsockopt SO_DETACH_FILTER : "  << std::strerror(errno) << '\n';
            return -1;
        }
        return 0;
    }

    int OsUtil::set_nonblock_fd(int fd){
        int flags = fcntl(fd, F_GETFL);
        if(flags == -1){
            std::cerr << "[ERROR] fcntl F_GETFL : "  << std::strerror(errno) << '\n';
            return -1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1) {
            std::cerr << "[ERROR] fcntl O_NONBLOCK : " << std::strerror(errno)<< '\n';
            return -1;
        }
        return 0;
    }

    Ip OsUtil::get_source_ip(const char* source_nic){
        struct ifreq ifr;
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd ==-1) {
            std::cerr << "[ERROR] socket : " << std::strerror(errno) << '\n';
            return Ip(0);
        }
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {// IP
            std::cerr << "[ERROR] ioctl SIOCGIFADDR : " << std::strerror(errno)<< '\n';
            close(fd);
            return Ip(0);
        }
        struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
        close(fd);
        return Ip(ntohl(ipaddr->sin_addr.s_addr));  
    }
    
    Mac OsUtil::get_source_mac(const char* source_nic){
        struct ifreq ifr;
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd ==-1) {
            std::cerr << "[ERROR] socket : " << std::strerror(errno) << '\n';
            return Mac::nullMac();
        }
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {// IP
            std::cerr << "[ERROR] ioctl SIOCGIFHWADDR : " << std::strerror(errno)<< '\n';
            close(fd);
            return Mac::nullMac();
        }
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        close(fd);
        return Mac(mac);
    }

    int OsUtil::get_source_mtu(const char* source_nic){
        struct ifreq ifr;
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd ==-1) {
            std::cerr << "[ERROR] socket : " << std::strerror(errno) << '\n';
            return -1;
        }
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {// IP
            std::cerr << "[ERROR] ioctl SIOCGIFMTU : " << std::strerror(errno)<< '\n';
            close(fd);
            return -1;
        }
        return ifr.ifr_mtu;
    }

    Mac OsUtil::get_target_mac(const char* source_nic, Ip source_ip, Mac source_mac, Ip target_ip, uint64_t timeout){
        int raw_socket_fd = get_l2_raw_socket_fd(source_nic);
        if(raw_socket_fd == -1) {
            std::cerr << "[ERROR] get_l2_raw_socket_fd " << '\n';
            return Mac::nullMac();
        }
        if(set_nonblock_fd(raw_socket_fd)== -1){
            std::cerr << "[ERROR] set_nonblock_fd " << '\n';
            return Mac::nullMac();
        }
        if(set_bpf_filter(raw_socket_fd,"arp")==-1){
            std::cerr << "[ERROR] set_bpf_filter " << '\n';
            close_fd(raw_socket_fd);
            return Mac::nullMac();
        }
        int new_eth_len = sizeof(EthHdr)+sizeof(ArpHdr);
        uint8_t new_eth[MAX_BUFFER_SIZE];
        EthHdr* new_ethhdr = (EthHdr*)new_eth;
        new_ethhdr->dmac_ = Mac::broadcastMac();
        new_ethhdr->smac_ = source_mac;
        new_ethhdr->type_ = htons(EthHdr::Arp);
        ArpHdr* new_arphdr = (ArpHdr*)(new_eth + sizeof(EthHdr));
        new_arphdr->hrd_ = htons(ArpHdr::ETHER);
        new_arphdr->pro_ = htons(EthHdr::Ip4);
        new_arphdr->hln_ = Mac::SIZE;
        new_arphdr->pln_ = Ip::SIZE;
        new_arphdr->op_ = htons(ArpHdr::Request);
        new_arphdr->smac_ =source_mac;
        new_arphdr->sip_ = htonl(source_ip);
        new_arphdr->tmac_ = Mac::nullMac();
        new_arphdr->tip_ = htonl(target_ip);
        std::chrono::time_point<std::chrono::steady_clock> send_start_time = std::chrono::steady_clock::now();
        while(1){
            std::chrono::time_point<std::chrono::steady_clock> now = std::chrono::steady_clock::now();
		    uint64_t elapsed = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - send_start_time).count());
            if(elapsed > timeout){
                // 패킷은 수신을 못하여 타임아웃을 발생했을 때
                std::cerr<<"[ERROR] Timeout while waiting for ARP reply. "<< '\n';
                close_fd(raw_socket_fd);
                return Mac::nullMac();
            }
            int send_res;
            do{send_res = send(raw_socket_fd, new_eth, new_eth_len, 0);}
            while (send_res == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK|| errno == ENOBUFS));
            if(send_res == -1){
                std::cerr<<"[ERROR] send raw_socket_fd : " <<strerror(errno)<< '\n';
                close_fd(raw_socket_fd);
                return Mac::nullMac();
            }
            else{
                uint8_t recv_buffer[MAX_BUFFER_SIZE];
                while(true){
                    int recv_res = recv(raw_socket_fd, recv_buffer, sizeof(recv_buffer), 0);
                    if (recv_res == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) { // No more data to receive
                            break;
                        } else if (errno == EINTR) {// Signal interrupt 
                            continue;
                        }else if (errno == ENOBUFS) {// Kernel buffer overflow in NFQUEUE
                            continue;
                        }else {
                            std::cerr<<"[ERROR] send raw_socket_fd : " <<strerror(errno)<< '\n';
                            close_fd(raw_socket_fd);
                            return Mac::nullMac();
                        }
                    }
                    else{
                        EthHdr* ethhdr = (EthHdr*)recv_buffer;
                        ArpHdr* arphdr = (ArpHdr*)(recv_buffer + sizeof(EthHdr));
                        if (ethhdr->type() == EthHdr::Arp && arphdr->op() == ArpHdr::Reply && arphdr->sip() == target_ip){
                            close_fd(raw_socket_fd);
                            return arphdr->smac();
                        }
                    }
                }
            }
        }
    }

    int OsUtil::get_tun_fd(const char* virtual_nic, int virtual_nic_mtu,Ip virtual_ip, Ip virtual_subnet){
        int subnet_prefix_len = calc_subnet_prefix_len(virtual_subnet);
        if(subnet_prefix_len<0){
            std::cerr<<"[ERROR] calc_subnet_prefix_len "<< '\n';
            return -1;
        }
        struct ifreq ifr;
        int tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            std::cerr<<"[ERROR] open /dev/net/tun : "<<strerror(errno)<<" " << '\n';
            return -1;
        }
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
        std::strncpy(ifr.ifr_name, virtual_nic, IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
            std::cerr<<"[ERROR] ioctl TUNSETIFF : "<<strerror(errno)<<" " << '\n';
            close(tun_fd);
            return -1;
        }
        int result=0;
        if(exec_cmd_util({"sysctl", "-w", std::string("net.ipv6.conf.") + virtual_nic + ".disable_ipv6=1"})==0){result++;}
        if(exec_cmd_util({"ip", "link", "set", "dev", virtual_nic, "mtu", std::to_string(virtual_nic_mtu)})==0) {result++;}
        if(exec_cmd_util({"ip", "addr", "add", std::string(virtual_ip) + "/" + std::to_string(subnet_prefix_len), "dev", virtual_nic})==0){result++;}
        if(exec_cmd_util({"ip", "link", "set", virtual_nic, "up"})==0) {result++;}
        if(result!=4){
            std::cerr<<"[ERROR] exec_cmd_util_lnx "<< '\n';
            close(tun_fd);
            return -1;
        }
        return tun_fd;
    }

    int OsUtil::get_tun_fd(const char* virtual_nic){
        struct ifreq ifr;
        int tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            std::cerr<<"[ERROR] open /dev/net/tun : "<<strerror(errno)<<" " << '\n';
            return -1;
        }
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
        std::strncpy(ifr.ifr_name, virtual_nic, IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
            std::cerr<<"[ERROR] ioctl TUNSETIFF : "<<strerror(errno)<<" " << '\n';
            close(tun_fd);
            return -1;
        }
        return tun_fd;
    }
    
    int OsUtil::calc_subnet_prefix_len(Ip subnet) {
        uint32_t mask = static_cast<uint32_t>(subnet);
        uint32_t inv = ~mask;
        if ((inv & (inv + 1)) != 0) {
            std::cerr<<"[ERROR] Wrong Subnet Mask: not continuous " << '\n';
            return -1;
        }
        int len = 0;
        while (mask & 0x80000000) {
            len++;
            mask <<= 1;
        }
        return len;
    }

    int OsUtil::get_tcp_socket_fd(Ip source_ip, uint16_t source_port){
        int tcp_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_socket_fd == -1) {
            std::cerr<<"[ERROR] socket SOCK_STREAM : "<<strerror(errno)<<" " << '\n';
            return -1;
        }
        int optval = 1;
        if (setsockopt(tcp_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
            std::cerr<<"[ERROR] syscall setsockopt SO_REUSEADDR : "<<strerror(errno)<<" " << '\n';
            close(tcp_socket_fd);
            return -1;
        }
        struct sockaddr_in tcp_addr;
        memset(&tcp_addr, 0, sizeof(tcp_addr));
        tcp_addr.sin_family = AF_INET;
        tcp_addr.sin_addr.s_addr = htonl(source_ip);
        tcp_addr.sin_port = htons(source_port);
        if (bind(tcp_socket_fd, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) == -1) {
            std::cerr<<"[ERROR] syscall bind : "<<strerror(errno)<<" "<< '\n';
            close(tcp_socket_fd);
            return -1;
        }
        return tcp_socket_fd;
    }

    int OsUtil::get_udp_socket_fd(Ip source_ip, uint16_t source_port){
        int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket_fd == -1) {
            std::cerr << "[ERROR] socket SOCK_DGRAM : " << strerror(errno) << "\n";
            return -1;
        }
        int optval = 1;
        if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
            std::cerr << "[ERROR] setsockopt SO_REUSEADDR : " << strerror(errno) << "\n";
            close(udp_socket_fd);
            return -1;
        }
        struct sockaddr_in udp_addr;
        memset(&udp_addr, 0, sizeof(udp_addr));
        udp_addr.sin_family = AF_INET;
        udp_addr.sin_addr.s_addr = htonl(source_ip);
        udp_addr.sin_port = htons(source_port);
        if (bind(udp_socket_fd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == -1) {
            std::cerr << "[ERROR] bind : " << strerror(errno) << "\n";
            close(udp_socket_fd);
            return -1;
        }
        return udp_socket_fd;
    }

    int OsUtil::get_port_from_l4_socket_fd(int l4_socket_fd) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        if (getsockname(l4_socket_fd, (struct sockaddr *)&addr, &len) == -1) {
            std::cerr << "[ERROR] getsockname: " << strerror(errno) << "\n";
            return -1; 
        }
        return ntohs(addr.sin_port);
    }

    int OsUtil::get_can_socket_fd(const char* source_nic) {
        int can_socket_fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
        if (can_socket_fd < 0) {
            std::cerr << "[ERROR] socket(AF_CAN, SOCK_RAW, CAN_RAW): " << strerror(errno) << "\n";
            return -1;
        }
        int enable_canfd = 1;
        setsockopt(can_socket_fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_canfd, sizeof(enable_canfd));
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, source_nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(can_socket_fd, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "[ERROR] ioctl(SIOCGIFINDEX): " << strerror(errno) << "\n";
            close(can_socket_fd);
            return -1;
        }
        struct sockaddr_can addr;
        memset(&addr, 0, sizeof(addr));
        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;
        if (bind(can_socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[ERROR] bind CAN socket: " << strerror(errno) << "\n";
            close(can_socket_fd);
            return -1;
        }
        return can_socket_fd;
    }

    
#endif