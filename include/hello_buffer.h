#pragma once
#include <cstdint>
#include <map>
#include <vector>

// Joins the first TCP segments a client sends, so a TLS Client Hello that was
// split over several packets can still be read. Handles out-of-order and
// repeated segments. Memory per connection is limited.
class HelloBuffer {
public:
    explicit HelloBuffer(uint32_t firstSeq) : next_(firstSeq) {}

    void add(uint32_t seq, const uint8_t* data, size_t length);
    const std::vector<uint8_t>& data() const { return data_; }
    bool finished() const;     // complete, too large, or not TLS at all

private:
    bool append(uint32_t seq, const uint8_t* data, size_t length);

    uint32_t next_;            // sequence number expected next
    std::vector<uint8_t> data_;
    std::map<uint32_t, std::vector<uint8_t>> later_;
};
