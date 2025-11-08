#pragma once

#include <pthread.h>
#include <atomic>
#include <exception>
#include <iostream>
#include <string.h>
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
