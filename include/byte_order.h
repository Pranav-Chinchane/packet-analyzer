#pragma once
// Network fields are big-endian. Building values byte by byte works on any CPU
// and avoids misaligned pointer casts.
#include <cstdint>

inline uint16_t readBE16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

inline uint32_t swap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0xFF00u) | ((v << 8) & 0xFF0000u) | (v << 24);
}

inline uint16_t swap16(uint16_t v) {
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}
