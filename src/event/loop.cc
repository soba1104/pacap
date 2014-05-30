#include <iostream>
#include <unordered_map>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mpcap/pcap.h>
#include <mpcap/protocol.h>
#include <mpcap/stream.h>

#include <pacap.h>

using namespace mpcap::protocol;
typedef mpcap::protocol::stack<ethernet, ipv4, tcp> protocol_stack_t;
typedef mpcap::protocol::stack<ipv4, tcp>::packet tcp_ipv4_packet_t;
typedef mpcap::protocol::stack<ipv4, tcp>::address tcp_ipv4_address_t;

namespace {

class mpcap_event_observer : public mpcap::stream::event::observer::iface<tcp_ipv4_address_t> {
  public:
    mpcap_event_observer(pacap::event::observer::iface *pacap_event_observer)
                       : m_pacap_event_observer(pacap_event_observer) {}
    ~mpcap_event_observer(void) {
      for (auto it = m_reassembler_map.begin();
           it != m_reassembler_map.end();
           it++) {
        delete it->second;
      }
    }

    void notify(mpcap::stream::event::type type,
                const tcp_ipv4_address_t &src,
                const tcp_ipv4_address_t &dst,
                const void *data,
                const struct ::timeval &time);

  private:
    void process(const tcp_ipv4_address_t &src,
                 const tcp_ipv4_address_t &dst,
                 const tcp::packet *p,
                 const struct ::timeval &time);

    pacap::event::observer::iface *m_pacap_event_observer;

    std::unordered_map<mpcap::stream::key<tcp_ipv4_address_t>,
                       tcp::reassembler*,
                       mpcap::stream::key<tcp_ipv4_address_t>::hasher> m_reassembler_map;
};

void mpcap_event_observer::notify(mpcap::stream::event::type type,
                                  const tcp_ipv4_address_t &src,
                                  const tcp_ipv4_address_t &dst,
                                  const void *data,
                                  const struct ::timeval &time) {
  const tcp_ipv4_packet_t *p0 = static_cast<const tcp_ipv4_packet_t*>(data);
  const tcp::packet &p1 = p0->at<1>();
  mpcap::stream::key<tcp_ipv4_address_t> k(src, dst);
  mpcap::protocol::tcp::reassembler *r = nullptr;
  if (m_reassembler_map.find(k) != m_reassembler_map.end()) {
    r = m_reassembler_map[k];
  } else {
    r = new mpcap::protocol::tcp::reassembler;
    m_reassembler_map[k] = r;
  }

  bool pass = r->pass(p1);
  if (pass) {
    process(src, dst, &p1, time);
  } else {
    r->put(p1);
  }
  while (const tcp::packet *pptr = r->take()) {
    process(src, dst, pptr, time);
  }
}

void mpcap_event_observer::process(const tcp_ipv4_address_t &src,
                                   const tcp_ipv4_address_t &dst,
                                   const tcp::packet *p,
                                   const struct ::timeval &time) {
  const std::string srcip(inet_ntoa({ src.at<0>().value() }));
  const std::string dstip(inet_ntoa({ dst.at<0>().value() }));
  const int srcport(ntohs(src.at<1>().value()));
  const int dstport(ntohs(dst.at<1>().value()));
  m_pacap_event_observer->notify(srcip,
                                 srcport,
                                 dstip,
                                 dstport,
                                 p->dataptr(),
                                 p->datasize(),
                                 time);
}

void run(const std::string &iface,
         mpcap::stream::event::subject::iface<tcp_ipv4_address_t> *mpcap_subject,
         pacap::event::observer::iface *pacap_event_observer) {
  mpcap_event_observer mpcap_observer(pacap_event_observer);
  mpcap_subject->attach(&mpcap_observer);
  mpcap::pcap::reader reader(iface, "");
  reader.open();

  const void *data;
  struct ::timeval time;
  int32_t size;
  while ((size = reader.read(&data, &time)) > 0) {
    protocol_stack_t::packet p0;
    if (p0.apply(data, size)) {
      const tcp_ipv4_packet_t &p1 = p0.template slice<1>();
      mpcap_subject->notify(p1.src(), p1.dst(), &p1, time);
    }
  }

  reader.close();
}

} // namespace

namespace pacap {

namespace event {

void loop::start(const std::string &iface,
                 const std::string ip,
                 const int port,
                 observer::iface *observer) {
  tcp_ipv4_address_t addr(ip, std::to_string(port));
  mpcap::stream::event::subject::server<tcp_ipv4_address_t> mpcap_subject(addr);
  run(iface, &mpcap_subject, observer);
}

void loop::start(const std::string &iface,
                 const std::string sip, const int sport,
                 const std::string dip, const int dport,
                 observer::iface *observer) {
  tcp_ipv4_address_t saddr(sip, std::to_string(sport));
  tcp_ipv4_address_t daddr(dip, std::to_string(dport));
  mpcap::stream::event::subject::client<tcp_ipv4_address_t> mpcap_subject(saddr, daddr);
  run(iface, &mpcap_subject, observer);
}

} // namespace event

} // namespace pacap
