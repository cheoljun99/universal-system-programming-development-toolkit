/*
 * SpinLock: Simple and High-Performance Exclusive Spin Lock
 *
 * 구현 개요:
 *  - std::atomic_flag 기반의 단일 비트 락 상태 관리
 *  - test_and_set()으로 lock 획득, clear()로 해제
 *  - CPU 아키텍처별 pause/yield 명령을 이용한 backoff 지원
 *  - 64바이트 캐시 라인 정렬로 false sharing 최소화
 *
 * 동작 특성:
 *  - 커널 블로킹 없음, 완전한 busy-wait 스핀락
 *  - 짧은 임계 구역에서 최고의 성능
 *  - 장시간 경합 시 CPU 점유율 급증 가능
 *
 * 메모리 오더링:
 *  - lock(): memory_order_acquire
 *  - unlock(): memory_order_release
 *  - try_lock(): non-blocking 즉시 시도
 *
 * 사용 예시:
 *  SpinLock lock;
 *  lock.lock();
 *  // critical section
 *  lock.unlock();
 */

#pragma once
#include <atomic>
#if defined(_MSC_VER)
#include <immintrin.h>
#endif

class alignas(64) SpinLock {
private:
    std::atomic_flag flag_;  // 락 상태 플래그 (true = locked)

public:
    // 생성자에서 초기화
    SpinLock() : flag_(ATOMIC_FLAG_INIT) {}

    // 락 획득 (blocking)
    inline void lock() {
        while (flag_.test_and_set(std::memory_order_acquire)) {
            backoff();
        }
    }

    // 락 해제
    inline void unlock() {
        flag_.clear(std::memory_order_release);
    }

    // 비차단 try-lock (즉시 시도 후 실패 시 false)
    inline bool try_lock() {
        return !flag_.test_and_set(std::memory_order_acquire);
    }

private:
    // CPU별 pause/yield 백오프
    static inline void backoff() {
    #if defined(_MSC_VER)
        _mm_pause();
    #elif defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
    #elif defined(__aarch64__) || defined(__arm__)
        __asm__ __volatile__("yield");
    #elif defined(__riscv)
        __asm__ __volatile__("pause");
    #endif
    }
};
