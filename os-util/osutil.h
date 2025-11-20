#pragma once

#include <string>
#include <vector>
#include <cstdint>
namespace osutil {
    #if defined(_WIN32) || defined(_WIN64)
        // Windows 헤더
    #elif defined(__linux__)
        // 리눅스 헤더
        #include <unistd.h>
        #include <linux/types.h>
        extern char **environ; // posix_spawnp에 필요한 환경 변수
    #endif

    #if defined(_WIN32) || defined(_WIN64)

    #elif defined(__linux__)
        // Utility 명령어 사용 함수
        int exec_cmd_util(const std::vector<std::string>& args);

        // 오프로드 제어 함수
        bool set_ofld(const char* iface, uint32_t cmd, const char* name, bool enable);

        // 시그널 핸들러 등록 함수
        bool reg_sig_hdl(int sig, void (*hdl_func)(int));

        // NIC IP 가져오는 함수
        uint32_t get_nic_ip(char * nic);
    #endif

}

