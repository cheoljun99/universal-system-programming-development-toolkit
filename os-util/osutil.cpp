#include "osutil.h"
#include <string>
#include <vector>
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
    // Windows 헤더
#elif defined(__linux__)
    // Linux 헤더
    #include <unistd.h>
    #include <spawn.h>
    #include <sys/ioctl.h>
    #include <sys/wait.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include <linux/sockios.h>
    #include <linux/ethtool.h>
    #include <arpa/inet.h>
    #include <cerrno>
    #include <cstring>
    #include <csignal>
    extern char **environ;
#endif

#if defined(_WIN32) || defined(_WIN64)
    //Windows 함수
#elif defined(__linux__)
    //Linux 함수
    int  osutil::exec_cmd_util(const std::vector<std::string>& args) {
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

    bool  osutil::set_ofld(const char* iface, __u32 cmd, const char* name, bool enable) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("[ERROR] socket"); return false; }

        struct ethtool_value eval = {};
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        eval.cmd = cmd;
        eval.data = enable ? 1 : 0;
        ifr.ifr_data = (caddr_t)&eval;

        if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
            printf("Failed to %s %s on %s: %s\n", enable ? "enable" : "disable", name, iface, strerror(errno));
        else
            printf("%s %s on %s\n", enable ? "Enabled" : "Disabled", name, iface);

        close(fd);
        return true;
    }

    bool  osutil::reg_sig_hdl(int sig, void (*hdl_func)(int)) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = hdl_func;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction(sig, &sa, nullptr) == -1) {
            perror("[ERROR] sigaction");
            return false;
        }
        return true;
    }

    uint32_t  osutil::get_nic_ip(char * nic) {
        struct ifreq ifr;
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) { perror("[ERROR] socket"); return 0; }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, nic, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
            struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
            close(fd);
            return ntohl(ipaddr->sin_addr.s_addr);
        } else {
            perror("[ERROR] ioctl SIOCGIFADDR");
            close(fd);
            return 0;
        }
    }
#endif