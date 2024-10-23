#ifndef XADAMC09_ISA_IGNORE_PACKET_EXCEPTION
#define XADAMC09_ISA_IGNORE_PACKET_EXCEPTION

#include <iostream>

class IgnorePacket : public std::exception {};
class IgnoreRecord : public std::exception {};

#endif