/*
 * C++11 Thread Management Wrapper (Thread Class)
 *
 * 본 구현은 C++11 표준의 std::thread를 안전하게 관리하기 위한 RAII 기반 래퍼 클래스이다.
 * 스레드의 생성, 종료, 예외 처리, 자원 정리를 일관된 방식으로 수행하며,
 * start_thread()와 stop_thread() 호출을 통해 스레드 생명주기를 관리한다.
 *
 * 특징:
 *  - C++11 이상의 표준 스레드(std::thread) 기반으로 POSIX 및 Windows 모두에서 동작 가능
 *  - 내부적으로 std::atomic<bool>을 사용하여 종료 신호를 안전하게 전달
 *  - 스레드 실행 중 예외 발생 시 안전하게 종료 처리하고 로그 출력
 *  - thread_loop()는 사용자 정의 함수로, 스레드 내에서 수행할 주 작업 루프를
 *    애플리케이션 목적에 맞게 직접 구현해야 함
 *  - 사용자는 thread_term_ 플래그를 주기적으로 확인하여 루프 종료 조건을 스스로 정의해야 함
 *  - RAII 원칙에 따라 객체 소멸 시 stop_thread()가 자동 호출됨
 *
 * setup() / cleanup() 설계 지침:
 *  - setup()은 start_thread() 내부에서 호출되며,
 *    스레드 실행에 필요한 하드웨어 또는 시스템 리소스를 확보해야 함
 *  - cleanup()은 stop_thread() 또는 setup() 실패 시 호출되며,
 *    여러 번 실행되어도 예외나 오류 없이 안전하게 동작해야 함
 *  - cleanup()은 리소스 해제 순서가 보장되어야 하며,
 *    이미 해제된 리소스에 대해 중복 해제를 시도해서는 안 됨
 *
 * stop_thread() 동작:
 *  - stop_thread()는 여러 번 호출되어도 안전하게 동작하도록 설계되어 있음
 *  - 스레드가 이미 종료된 상태에서는 추가 join을 수행하지 않음
 *  - stop_thread() 호출 시 thread_term_을 true로 설정하여
 *    thread_loop()가 자연스럽게 종료될 수 있도록 함
 *
 * 주의:
 *  - start_thread()는 이미 실행 중인 스레드가 있을 경우 재호출할 수 없음
 *  - thread_loop()는 사용자 정의 함수이며, 반드시 thread_term_을 참조하여
 *    적절한 시점에 루프를 종료하도록 작성해야 함
 *  - cleanup()은 반복 호출되어도 안전하게 작동해야 하며,
 *    리소스 해제 로직은 idempotent하게 작성되어야 함
 *  - thread_func() 내부에서 발생한 예외는 잡아 처리되며, 시스템 오류로 확산되지 않음
 *
 * 본 클래스는 표준 C++ std::thread를 기반으로 한 독립적 관리 객체이며,
 * 시스템 수준의 스레드 관리 및 자원 해제를 안전하게 수행하기 위한 참조 구현이다.
 */

#pragma once
#include <thread>
#include <atomic>
#include <exception>
#include <iostream>
#include <cstring>

class Thread {
private:
    std::thread thread_;
    std::atomic<bool> thread_term_;
public:
    Thread() : thread_term_(false) {}
    ~Thread() { stop_thread(); }
    bool start_thread() {
        if (thread_.joinable()) {
            std::cerr << "[ERROR] already started thread "
                << "(Thread::start_thread) "
                << "thread(ID : " << std::this_thread::get_id() << ")\n";
            return false;
        }
        if (!setup()) {
            cleanup();
            return false;
        }
        thread_ = std::thread(&Thread::thread_func, this);
        return true;
    }
    void stop_thread() {
        if (thread_.joinable()) {
            if (!thread_term_.load()) {
                thread_term_.store(true);
            }
            thread_.join();
        }
        cleanup();
    }
    bool get_thread_term() { return thread_term_.load();}
private:
    bool setup();
    void cleanup();
    static void thread_func(Thread* self) {
        std::cout << "thread(ID : " << std::this_thread::get_id()<< ") start...\n";
        try { self->thread_loop(); }
        catch (const std::exception& e) {
            std::cerr << "[EXCEPT] thread exception: " << e.what() << '\n';
            self->thread_term_.store(true);
        }
        std::cout << "thread(ID : " << std::this_thread::get_id()<< ") stop!!!\n";
    }
    void thread_loop();
};