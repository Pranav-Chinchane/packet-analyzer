#include "hello_buffer.h"
#include "byte_order.h"

namespace {
constexpr size_t MAX_BYTES = 5 + 16384;          // one full TLS record
constexpr size_t MAX_LATER = 16;                 // out-of-order segments kept
}

// Sequence numbers wrap around at 2^32, so compare the signed difference.
bool HelloBuffer::append(uint32_t seq, const uint8_t* data, size_t length) {
    const int32_t ahead = static_cast<int32_t>(seq - next_);
    if (ahead > 0) return false;                 // a gap: not yet
    const size_t known = static_cast<size_t>(-static_cast<int64_t>(ahead));
    if (known < length && data_.size() < MAX_BYTES) {
        data_.insert(data_.end(), data + known, data + length);
        next_ += static_cast<uint32_t>(length - known);
    }
    return true;
}

void HelloBuffer::add(uint32_t seq, const uint8_t* data, size_t length) {
    if (!append(seq, data, length)) {
        if (later_.size() < MAX_LATER) later_.emplace(seq, std::vector<uint8_t>(data, data + length));
        return;
    }
    for (auto it = later_.begin(); it != later_.end();) {
        if (append(it->first, it->second.data(), it->second.size())) {
            later_.erase(it);
            it = later_.begin();
        } else {
            ++it;
        }
    }
}

bool HelloBuffer::finished() const {
    if (data_.empty()) return false;
    if (data_[0] != 0x16 || data_.size() >= MAX_BYTES) return true;
    return data_.size() >= 5 && data_.size() >= 5 + size_t(readBE16(&data_[3]));
}
