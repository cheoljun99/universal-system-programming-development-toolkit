/*
 * AtomicSignalBuf: C++20 atomic wait/notify 기반  Producer Consumer Queue Wrapper
 *
 * 본 구현은 Producer Consumer 환경에서 C++20 std::atomic::wait / notify_one/notify_all을 사용하여
 * 컨슈머 스레드가 대기(wait) 및 깨움(notify)을 효율적으로 처리하는 래퍼 클래스이다.
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
 *  - 내부 SPMCBuf 원형 버퍼 사용, 단일 다중 프로듀서 enqueue 지원
 *  - atomic flag + wait/notify 로 lost wakeup 방지
 *  - lock-free 구조로 여러 컨슈머 경쟁 가능
 *
 * 동작:
 *  - enqueue_wake(): 데이터 enqueue + flag store + notify_one
 *  - wake_all(): 모든 대기 컨슈머 notify
 *  - dequeue_wait(): 데이터 있으면 즉시 반환, 없으면 CAS 후 atomic wait
 *
 * 안정성:
 *  - 데이터 폭주, 간헐적 도착 모두 처리 가능
 *  - lost wakeup 없음, 커널 진입 최소화로 고속 처리 가능
 *  - 스레드 안전성과 반응성 모두 보장
 */


#pragma once
#include <iostream>
#include <atomic>
#include <cstdint>
#include "SignalBuf.h"

class AtomicSignalBuf : public SignalBuf {
    std::atomic<int> flag_;

public:
    AtomicSignalBuf(std::unique_ptr<SharedBuf> shared_buf) : SignalBuf(std::move(shared_buf)), flag_(0) {}

    int32_t enqueue_wake(const uint8_t* data, size_t len) override {
        int32_t n = shared_buf_->enqueue(data, len);
        if (n >=0) {
            flag_.store(1, std::memory_order_relaxed);
            flag_.notify_one();  
        }
        else{
            std::cout << "shared_buf_ is pull " << '\n';
            flag_.store(1, std::memory_order_relaxed);
            flag_.notify_one();
        }
        return n; // -1: full
    }

    void wake_all() override {
        flag_.store(1, std::memory_order_relaxed);
        flag_.notify_all();
    }

    int32_t dequeue_wait(uint8_t* out, size_t len) override {
        int32_t n = shared_buf_->dequeue(out, len);
        if (n >= 0) return n;
        int expected = 1;
        if (!flag_.compare_exchange_strong(expected, 0, std::memory_order_relaxed, std::memory_order_relaxed)) {
            // flag가 1이면 0으로 바꾸고 true 반환하고 이것이 반전됨 wait 건너뜀
            // flag가 0이면 0으로 유지하고 false 반환하고 이것이 반전됨 wait 들어감 
            flag_.wait(0);
        }
        return -1;
    }
};
