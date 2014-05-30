#ifndef SRC_INCLUDE_PACAP_EVENT_OBSERVER_IFACE_H_
#define SRC_INCLUDE_PACAP_EVENT_OBSERVER_IFACE_H_

namespace pacap {

namespace event {

namespace observer {

class iface {
  public:
    virtual void notify(const std::string &srcip,
                        const int srcport,
                        const std::string &dstip,
                        const int dstport,
                        const void *data,
                        int32_t size, 
                        const struct ::timeval &time) = 0;
};

} // namespace observer

} // namespace event

} // namespace pacap

#endif // SRC_INCLUDE_PACAP_EVENT_OBSERVER_IFACE_H_
