#include "load_balancer.h"

void LoadBalancer::run() {
    while (auto batch = input_.pop()) {
        std::vector<JobBatch> out(workers_.size());
        for (PacketJob& job : *batch) {
            // The LB was chosen with hash % lbCount. Dividing first uses the rest
            // of the hash; reusing hash % n would leave some workers idle.
            out[(job.hash / lbCount_) % workers_.size()].push_back(std::move(job));
        }
        for (size_t i = 0; i < out.size(); i++)
            if (!out[i].empty()) workers_[i]->push(std::move(out[i]));
    }
}

void LoadBalancer::finish() {
    input_.close();
    thread_.join();
}
