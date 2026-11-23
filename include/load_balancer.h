#pragma once
#include <vector>
#include "fast_path.h"

// Distributes packets to its own group of workers.
class LoadBalancer {
public:
    LoadBalancer(std::vector<FastPath*> workers, size_t lbCount)
        : workers_(std::move(workers)), lbCount_(lbCount) {}

    void start() { thread_ = std::thread(&LoadBalancer::run, this); }
    void push(JobBatch batch) { input_.push(std::move(batch)); }
    void finish();

private:
    void run();

    std::vector<FastPath*> workers_;
    size_t lbCount_;
    ThreadSafeQueue<JobBatch> input_{QUEUE_BATCHES};
    std::thread thread_;
};
