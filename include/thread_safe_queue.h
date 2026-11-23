#pragma once
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>

// Bounded blocking queue. A full queue makes producers wait (backpressure).
template <typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t maxSize = 10000) : maxSize_(maxSize) {}

    // False if the queue was closed.
    bool push(T item) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            notFull_.wait(lock, [&] { return queue_.size() < maxSize_ || closed_; });
            if (closed_) return false;
            queue_.push(std::move(item));
        }
        notEmpty_.notify_one();
        return true;
    }

    // Waits for an item. nullopt only when closed AND fully drained,
    // so nothing already queued is ever lost.
    std::optional<T> pop() {
        std::optional<T> item;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            notEmpty_.wait(lock, [&] { return !queue_.empty() || closed_; });
            if (queue_.empty()) return std::nullopt;
            item = std::move(queue_.front());
            queue_.pop();
        }
        notFull_.notify_one();
        return item;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable notEmpty_, notFull_;
    std::queue<T> queue_;
    size_t maxSize_;
    bool closed_ = false;
};
