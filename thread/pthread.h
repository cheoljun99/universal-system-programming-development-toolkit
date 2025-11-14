/*
 * POSIX Thread Management Wrapper (Pthread Class)
 *
 * 본 구현은 POSIX 스레드(pthread)를 안전하고 일관되게 관리하기 위한 RAII 기반 래퍼 클래스이다.
 * 스레드의 생성, 종료, 예외 처리, 자원 정리를 통합적으로 수행하며,
 * start_thread()와 stop_thread()를 통해 스레드 생명주기를 관리한다.
 *
 * 특징:
 *  - POSIX 환경 전용으로 설계되어 있으며, 다른 플랫폼(예: Windows)에서는 사용할 수 없다.
 *  - 내부적으로 pthread_t를 관리하고, std::atomic<bool>을 사용해 종료 신호를 전달한다.
 *  - 스레드 실행 중 예외 발생 시 안전하게 종료 처리하고 예외 내용을 로그로 출력한다.
 *  - thread_loop()는 사용자 정의 함수로, 스레드 내부에서 수행할 주 작업 루프를
 *    애플리케이션 목적에 맞게 직접 구현해야 한다.
 *  - 사용자는 thread_term_ 플래그를 주기적으로 확인하여 루프 종료 조건을 직접 제어해야 한다.
 *  - RAII 원칙에 따라 객체 소멸 시 stop_thread()가 자동 호출되어 리소스를 안전하게 해제한다.
 *
 * setup() / cleanup() 설계 지침:
 *  - setup()은 start_thread() 내부에서 호출되며,
 *    스레드 실행에 필요한 하드웨어 또는 시스템 리소스를 확보해야 한다.
 *  - cleanup()은 stop_thread() 또는 setup() 실패 시 호출되며,
 *    여러 번 호출되어도 예외나 오류 없이 안전하게 동작해야 한다.
 *  - cleanup()은 이미 해제된 리소스에 대해 중복 해제를 시도하지 않도록 설계되어야 한다.
 *
 * stop_thread() 동작:
 *  - stop_thread()는 여러 번 호출되어도 안전하게 동작하도록 설계되어 있다.
 *  - 스레드가 이미 종료된 상태에서는 추가 join을 수행하지 않는다.
 *  - stop_thread() 호출 시 thread_term_을 true로 설정하여
 *    thread_loop() 내 루프가 자연스럽게 종료될 수 있도록 한다.
 *
 * 주의:
 *  - start_thread()는 이미 실행 중인 스레드가 있을 경우 재호출할 수 없다.
 *  - thread_loop()는 사용자 정의 함수이며, 반드시 thread_term_을 참조하여
 *    적절한 시점에 루프를 종료하도록 작성해야 한다.
 *  - cleanup()은 반복 호출되어도 안전해야 하며,
 *    리소스 해제 로직은 항상 idempotent(중복 호출 시 동일한 결과를 유지)해야 한다.
 *  - thread_func() 내부에서 발생한 예외는 잡아 처리되며, 시스템 오류로 확산되지 않는다.
 *
 * 본 클래스는 POSIX 표준 pthread API를 기반으로 한 독립적 관리 객체이며,
 * 시스템 수준의 스레드 관리 및 자원 해제를 안전하고 예측 가능하게 수행하기 위한 참조 구현이다.
 */

#pragma once

#include <pthread.h>
#include <atomic>
#include <exception>
#include <iostream>
#include <cstring>
#include <unistd.h>

class Pthread {
private:
	pthread_t thread_id_ = 0;
	std::atomic<bool> thread_term_;
public:
	Pthread() : thread_term_(false) {}
	~Pthread() { stop_thread(); }
	bool start_thread() {
		if (thread_id_ != 0) {
			std::cerr << "[ERROR] already start thread "
				<< "(Pthread::start_thread) " << '\n';
			return false;
		}
		if (setup() == false) {
			cleanup();
			return false;
		}
		if (pthread_create(&thread_id_, nullptr, thread_func, this) != 0) {
			std::cerr << "[ERROR] pthread_create Pthread : "
				<< strerror(errno)
				<< "(Pthread::start_thread) " << '\n';
			cleanup();
			return false;
		}
		return true;
	}
	void stop_thread() {
		if (thread_id_ != 0) {
			if (!thread_term_.load()) { thread_term_.store(true); }
			if (pthread_join(thread_id_, nullptr) != 0) {
				std::cerr << "[ERROR] pthread_join : " << strerror(errno) << " "
					<< "(Pthread::start_thread) " << '\n';
			}
			thread_id_ = 0;
		}
		cleanup();
	}
	bool get_thread_term() { return thread_term_.load();}
private:
	bool setup();
	void cleanup();
	static void* thread_func(void* arg) {
		Pthread* self = static_cast<Pthread*>(arg);
		std::cout << "thread(PID :" << getpid() << ", TID :" << gettid() << ") start..." << '\n';
		try { self->thread_loop(); }
		catch (const std::exception& e) {
			std::cerr << "[EXCEPT] pthread exception: " << e.what() << '\n';
			self->thread_term_.store(true);
		}
		std::cout << "VPN server thread(PID :" << getpid() << ", TID :" << gettid() << ") stop!!!" << '\n';
		return nullptr;
	}
	void thread_loop();
};
