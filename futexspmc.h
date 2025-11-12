/*
 * FutexSPMC: Futex 기반 Single Producer Multiple Consumer Queue Wrapper
 *
 * 본 구현은 SPMC 환경에서 Linux futex 시스템 콜을 사용하여
 * 컨슈머 스레드가 대기(wait) 및 깨움(wake)을 효율적으로 처리하는 래퍼 클래스이다.
 *
 * 핵심 원칙:
 *  - 외부에서 dequeue_wait 메서드 호출할 때 **while 루프로 반복 호출**해야 하며,
 *    이를 통해 스피리어스 웨이크업이나 간헐적 데이터 도착 상황에서도
 *    항상 안전하게 데이터를 처리할 수 있음을 보장한다.
 *
 * 추가 보장 사항:
 *  - 큐에 데이터가 존재하는 동안 항상 최소 하나 이상의 스레드가 dequeue 시도 가능 상태가 보장됨
 *  - wait 전에 wake업이 수행되었더라도 wait 조건이 메모리 값 확인 기반이므로 건너뜀
 *  - 컨슈머 하나가 flag를 1에서 0으로 바꾸더라도 wait하지 않고 return → 해당 컨슈머는 wait되지 않음
 *  - 컨슈머는 데이터를 읽기 위해 dequeue_wait 수행 가능 (데이터 없으면 wait, 데이터 있으면 deque 후 return)
 *
 * 특징:
 *  - 내부 SPMCBuf 원형 버퍼 사용, 단일 프로듀서 enqueue 지원
 *  - atomic flag + futex wake/wait 로 lost wakeup 방지
 *  - lock-free 구조로 여러 컨슈머 경쟁 가능
 *
 * 동작:
 *  - enqueue_wake(): 데이터 enqueue + flag 설정 + futex wake
 *  - wake_all(): 모든 대기 컨슈머 wake
 *  - dequeue_wait(): 데이터 있으면 즉시 반환, 없으면 CAS 후 futex wait
 *
 * 안정성:
 *  - 데이터 폭주, 간헐적 도착 모두 처리 가능
 *  - lost wakeup 없음, 최소 커널 진입으로 성능 최적화
 *  - 스레드 안전성과 반응성 모두 보장
 */

 
#pragma once
#include <stdatomic.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <unistd.h>
#include <cstdint>
#include <climits>
#include "SPMCBuf.h"

class FutexSPMC {
    SPMCBuf spmc_buf_;
    alignas(4) atomic_int flag_;

public:
    FutexSPMC(size_t size) : spmc_buf_(size), flag_(0) {}

    int32_t enqueue_wake(const uint8_t* data, size_t len) {
        int32_t n = spmc_buf_.enqueue(data, len);
        if (n >=0) {
            atomic_store_explicit(&flag_, 1, memory_order_relaxed);
            syscall(SYS_futex, &flag_, FUTEX_WAKE, 1, nullptr, nullptr, 0);
        }
        else{
            std::cout << "spmc_buf_ is pull " << '\n';
            atomic_store_explicit(&flag_, 1, memory_order_relaxed);
            syscall(SYS_futex, &flag_, FUTEX_WAKE, 1, nullptr, nullptr, 0);
        }
        return n; // -1: full
    }

    void wake_all() {
        atomic_store_explicit(&flag_, 1, memory_order_relaxed);
        syscall(SYS_futex, &flag_, FUTEX_WAKE, INT_MAX, nullptr, nullptr, 0);
    }

    int32_t dequeue_wait(uint8_t* out, size_t len) {
        int32_t n = spmc_buf_.dequeue(out, len);
        if (n >= 0) return n;
        int expected = 1;
        if (!atomic_compare_exchange_strong(&flag_, &expected, 0, memory_order_relaxed, memory_order_relaxed)) {
            // flag가 1이면 0으로 바꾸고 true 반환하고 이것이 반전됨 syscall 건너뜀
            // flag가 0이면 0으로 유지하고 false 반환하고 이것이 반전됨 syscall 들어감 
            syscall(SYS_futex, &flag_, FUTEX_WAIT, 0, nullptr, nullptr, 0);
        }
        return -1;
    }
};
