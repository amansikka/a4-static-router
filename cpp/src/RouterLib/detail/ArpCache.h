#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <chrono>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>

#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"

struct QueuedPacket { //so this just has a packet
    Packet packet;
    std::string iface;
};

struct ArpEntry {
    std::chrono::steady_clock::time_point timeAdded; //when was this ARP entry added so we can easily get timeouts
    mac_addr mac; //this is the mac addr resolved 
    std::vector<QueuedPacket> queuedPackets; //this is a vector of packets so we can send the packets once we get the mac addr back because there will be a time delay 
    int numTries = 0;  //end it after 7
    
};

class ArpCache {
public:
    ArpCache(
        std::chrono::milliseconds entryTimeout,
        std::chrono::milliseconds tickInterval,
        std::chrono::milliseconds resendInterval,
        std::shared_ptr<IPacketSender> packetSender, 
        std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache();

    void tick();

    Packet constructArpRequest(uint32_t targetIp, const std::string& iface, std::shared_ptr<IRoutingTable> routingTable);
    //this is a helper function I created with some gpt help 
    //ik it looks interesting, but ArpRequests are actual objects that need to be classified as packets
    //so I made a constructor function to easily make and then send these packets when the When a host must find the MAC address of the destination


    void addEntry(uint32_t ip, const mac_addr& mac); //this function gets called after you receive the ARP reply

    std::optional<mac_addr> getEntry(uint32_t ip); //optional because this value MAY be contained 

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface);

    bool isUnresolved(const mac_addr& mac);

private:
    void loop();

    std::chrono::milliseconds entryTimeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;

    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::mutex mutex;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
};



#endif //ARPCACHE_H
