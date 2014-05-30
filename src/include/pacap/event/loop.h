#ifndef SRC_INCLUDE_PACAP_EVENT_LOOP_H_
#define SRC_INCLUDE_PACAP_EVENT_LOOP_H_

#include <pacap/event/loop.h>

namespace pacap {

namespace event {

class loop {
  public:
    loop(void) {}
    ~loop(void) {}

    void start(const std::string &iface,
               const std::string ip,
               const int port,
               observer::iface *observer);

    void start(const std::string &iface,
               const std::string sip, const int sport,
               const std::string dip, const int dport,
               observer::iface *observer);
};

} // namespace event

} // namespace pacap

#endif // SRC_INCLUDE_PACAP_EVENT_LOOP_H_
