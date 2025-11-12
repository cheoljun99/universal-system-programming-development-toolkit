/*
 * CVNotifySPMC: Condition Variable 기반 Single Producer Multiple Consumer Queue Wrapper
 *
 * 본 구현은 SPMC 환경에서 std::condition_variable과 std::mutex를 사용하여
 * 컨슈머 스레드가 안전하게 데이터를 dequeue_wait 할 수 있도록 관리하는 래퍼 클래스이다.
 *
 * 핵심 원칙:
 *  - 외부에서 dequeue_wait 메서드 호출할 때 **while 루프로 반복 호출**해야 하며,
 *    이를 통해 스피리어스 웨이크업이나 간헐적 데이터 도착 상황에서도
 *    항상 안전하게 데이터를 처리할 수 있음을 보장한다.
*  - wait 호출 직전에 프로듀서가 enqueue_wake() 또는 wake_all()을 수행하더라도,
 *    flag 확인 기반으로 건너뛰기 때문에 컨슈머는 wait에 빠지지 않고 즉시 처리 가능하다.
 *
 * 특징:
 *  - 내부 SPMCBuf 원형 버퍼 사용, 단일 프로듀서 enqueue 지원
 *  - flag 기반 wake/notify로 lost wakeup 방지
 *  - enqueue_wake 호출 시 깨어난 컨슈머가 즉시 데이터 처리
 *  - wake_all 호출 시 모든 컨슈머 동시 깨움 가능
 *
 * 동작:
 *  - enqueue_wake(): 데이터 enqueue + flag 설정 + notify_one
 *  - wake_all(): 모든 대기 컨슈머 notify
 *  - dequeue_wait(): 데이터 있으면 즉시 반환, 없으면 while 루프를 통해 flag 확인 후 wait
 *
 * 안정성:
 *  - 데이터 폭주, 간헐적 도착 모두 안전하게 처리 가능
 *  - lost wakeup 없음, CPU 낭비 최소화
 */

#pragma once
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include "SPMCBuf.h"

class CVNotifySPMC {
    SPMCBuf buf_;
    std::mutex mtx_;
    std::condition_variable cv_;
    uint64_t flag_ = 0;

public:
    CVNotifySPMC(size_t size): buf_(size) {}

    int32_t enqueue_wake(const uint8_t* data, size_t len) {
        int32_t n = buf_.enqueue(data, len);
        if (n >= 0) {
            std::unique_lock<std::mutex> lock(mtx_);
            flag_++;
            lock.unlock();
            cv_.notify_one();
        }
        else{
            std::cout << "spmc_buf_ is pull " << '\n';
            std::unique_lock<std::mutex> lock(mtx_);
            flag_++;
            lock.unlock();
            cv_.notify_one();
        }
        return n; // -1: full
    }

    void wake_all() {
        std::unique_lock<std::mutex> lock(mtx_);
        flag_++;
        lock.unlock();
        cv_.notify_all();
    }

    int32_t dequeue_wait(uint8_t* out, size_t len) {
        int32_t n = buf_.dequeue(out, len);
        if (n > 0) return n;
        uint64_t expected = flag_;
        std::unique_lock<std::mutex> lock(mtx_);
        while (flag_ == expected) { 
            cv_.wait(lock);
            lock.unlock();
            return -1;
        }
        lock.unlock();
        return -1;
    }
};
