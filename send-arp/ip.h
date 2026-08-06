#pragma once

#include <cstdint>
#include <string>
#include <netinet/in.h>

struct Ip final {
	static const int Size = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

	std::string toString() const {
		const uint32_t a = (ip_ >> 24) & 0xFF;
		const uint32_t b = (ip_ >> 16) & 0xFF;
		const uint32_t c = (ip_ >> 8) & 0xFF;
		const uint32_t d = ip_ & 0xFF;

		return std::to_string(a) + "." 
				+ std::to_string(b) + "."
				+ std::to_string(c) + "."
				+ std::to_string(d);
	}

protected:
	uint32_t ip_;
};
