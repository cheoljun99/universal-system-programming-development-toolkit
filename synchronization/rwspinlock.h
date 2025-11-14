/*
 * RWSpinLock: High-Performance Reader-Writer Spin Lock
 *
 * 구현 개요:
 *  - 단일 32비트 원자 변수(state_) 기반으로 읽기/쓰기 상태 관리
 *      * 최상위 비트: 쓰기(lock) 플래그
 *      * 나머지 31비트: 읽기(reader) 카운터 (최대 2,147,483,647명 동시 리더 지원)
 *  - lock_shared()/unlock_shared(): reader 획득 및 해제
 *  - lock()/unlock(): writer 획득 및 해제
 *  - compare_exchange_weak 기반 CAS 반복으로 lock 획득
 *  - 64바이트 캐시 라인 정렬으로 false sharing 최소화
 *
 * 동작 특성:
 *  - 순수 스핀락 기반, 커널 블록킹 없음
 *  - 짧은 임계 구간에서 높은 성능 제공
 *  - starvation 방지 로직 없음(읽기 지속 시 writer 대기 가능)
 *  - backoff()에서 아키텍처별 CPU pause 명령 사용
 *      * Windows: _mm_pause()
 *      * x86/x64 GCC/Clang: __builtin_ia32_pause()
 *      * ARM/ARM64: yield
 *      * RISC-V: pause
 *
 * 메모리 오더링:
 *  - lock_shared()/lock(): memory_order_acquire
 *  - unlock_shared()/unlock(): memory_order_release
 *  - CAS 실패 시 relaxed로 재시도
 *
 * 사용 주의:
 *  - 락 구간이 길거나 스레드 수가 매우 많을 경우 CPU 점유 과다 가능
 *  - modern x86/ARM 환경에서는 std::this_thread::yield() fallback 없음
 *  - 장시간 경합이나 우선순위 보장이 필요한 경우 별도 설계 필요
 *  - 경합이 적고 짧은 임계 구간 환경에서 Folly SharedMutex 대비 빠른 성능 가능
 * 
 */

#pragma once
#include <atomic>
#if defined(_MSC_VER)
#include <immintrin.h>
#endif

#define WRITER_BIT (1u << 31)
#define READER_INC 1u

class alignas(64) RWSpinLock {
private:
    std::atomic<uint32_t> state_;
public:
    RWSpinLock():state_(0){};
    // Acquire shared (reader) lock
    inline void lock_shared() {
        uint32_t  old;
        while (true) {
            old = state_.load(std::memory_order_relaxed);
            // writer active?
            if (old & WRITER_BIT) {
                backoff();
                continue;
            }
            // try to increment reader count
            if (state_.compare_exchange_weak(old, old + READER_INC,std::memory_order_acquire, std::memory_order_relaxed)) {
                return;
            }
            backoff();
        }
    }

    // Release shared (reader) lock
    inline void unlock_shared() {
        state_.fetch_sub(READER_INC, std::memory_order_release);
    }

    // Acquire exclusive (writer) lock
    inline void lock() {
        // try to acquire writer bit when no one holds the lock
        while (true) {
            uint32_t  expected = 0;
            if (state_.compare_exchange_weak(expected, WRITER_BIT, std::memory_order_acquire, std::memory_order_relaxed)) {
                break;
            }
            backoff();
        }
        // wait until all readers have exited
        while (state_.load(std::memory_order_acquire) != WRITER_BIT) {
            backoff();
        }
    }

    // Release exclusive (writer) lock
    inline void unlock() {
        state_.store(0, std::memory_order_release);
    }

public:
    // Adaptive backoff: fast pause first, yield if contention persists
    static inline void backoff() {
        #if defined(_MSC_VER)
            // MSVC (Windows)
            _mm_pause();
        #elif defined(__x86_64__) || defined(__i386__)
            // GCC/Clang on x86/x86-64
            __builtin_ia32_pause();
        #elif defined(__aarch64__) || defined(__arm__)
            // ARM / ARM64
            __asm__ __volatile__("yield");
        #elif defined(__riscv)
            // RISC-V
            __asm__ __volatile__("pause");
        #endif
    }
};
