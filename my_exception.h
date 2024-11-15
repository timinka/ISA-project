/***
 * ISA PROJECT
 * @file my_exception.h
 * @author Tímea Adamčíková (xadamc09)
 */

#ifndef XADAMC09_ISA_IGNORE_PACKET_EXCEPTION
#define XADAMC09_ISA_IGNORE_PACKET_EXCEPTION

#include <iostream>

class IgnorePacket : public std::exception {};
class IgnoreRecord : public std::exception {};
class HandleSetUpErr : public std::exception {};
class ArgParserError : public std::exception {};

#endif