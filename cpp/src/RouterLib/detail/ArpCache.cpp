#include "ArpCache.h"
#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>
#include <arpa/inet.h> // for htons from host to network 
#include "protocol.h"
#include "utils.h"

//we are implementing a mechanism in order to cache the mappings in a temp data structure 

//this way we can easily resolve the link layer mechanics MAC for a given IP address without having to constantly send ARP requests everytime a packet needs to be forwarded

//this class uses two threads 

//Main thread	Handles incoming packets, ARP replies, forwarding logic
//Background thread (loop())	Maintains ARP state: retry ARP, delete expired entries

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, //basically sets how long it is valid
    std::chrono::milliseconds tickInterval,  //how often to do "maintenance" so during each tick the cache checks for expired entries and other perioic operations 
    std::chrono::milliseconds resendInterval, //this defines the time interval between successive ARP requests end after 7
    std::shared_ptr<IPacketSender> packetSender, //this data strucure is a smart pointer shared, so it auto deallocates when it is no longer needed so we don't have to manually clean it up
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this); //this makes a thread thhat does maintences tasks like cleaning up expired entries and handling queued packets
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) { //this makes the thread finish working before we end the object preventing invalid memory
        thread->join(); //block
    }
    //the object is destroyed
}

constexpr mac_addr UNRESOLVED_MAC = { {0, 0, 0, 0, 0, 0} };

bool isUnresolved(const mac_addr& mac) {
    return std::memcmp(mac.data, UNRESOLVED_MAC.data, sizeof(UNRESOLVED_MAC.data)) == 0;
} //checks if the mac is not resolved yet 

void ArpCache::loop() {
    while (!shutdown) { //as long as we are active
        tick(); //continue time to maintain the background states
        std::this_thread::sleep_for(tickInterval); //then we sleep that thread to process the actual connection
    }
} //helper function that switches between thread to handle background and then new thread to process connections 

Packet constructArpRequest(uint32_t targetIp, const std::string& iface, std::shared_ptr<IRoutingTable> routingTable) {
    //function first gets a routing interface
    RoutingInterface intf = routingTable->getRoutingInterface(iface);
    //this is a struct that holds the iface, which is like a port and the IP address and MAC address 

    // Step 2: Calculate total packet size: Ethernet + ARP header
    size_t packetSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    //so this has the ethernet header + ARP header AS IN 
    Packet packet(packetSize, 0); // Initializes all bytes to zero
    //this basically clears packet content for us 

    // Step 3: Fill in the Ethernet header
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    //this casts the data into the eth_hdr struct format that we defined in protocol.h 

    std::memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Destination = broadcast
    //this sets the ARP request in the code to a ff-ff-ff-ff-ff-ff MAC address for broadcastting the MAC 

    std::memcpy(eth_hdr->ether_shost, intf.mac.data, ETHER_ADDR_LEN); // Source = interface MAC
    //this just sets the Source = interface MAC

    eth_hdr->ether_type = htons(ethertype_arp); // ARP EtherType = 0x0806
    //turns to ethertype_arp defined in protocol.h into a network defined byte object so the receiving MAC addr knows that is an ARP request 

    //THESE ARE CONTROL BITS 
    // Step 4: Fill in the ARP header
    sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    //this allocates a pointer in memory JUST AFTER the Ethernet header and allocates that memory as the ARP header 

    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);  
    // sets the Hardware type to Ethernet for the packet 
    
    arp_hdr->ar_pro = htons(ethertype_ip);       // Protocol type = IPv4
    arp_hdr->ar_hln = ETHER_ADDR_LEN;            // Hardware size = 6 (MAC)
    arp_hdr->ar_pln = 4;                          // Protocol size = 4 (IPv4)
    arp_hdr->ar_op  = htons(arp_op_request);     // Operation = ARP request

    //THESE ARE DATA BITS
    std::memcpy(arp_hdr->ar_sha, intf.mac.data, ETHER_ADDR_LEN); // we are simply copying Sender MAC into this field 
    arp_hdr->ar_sip = intf.ip;                                     // Sender IP (network byte order)

    std::memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);              // Target MAC = 0 because we dont know it 
    arp_hdr->ar_tip = htonl(targetIp);                                   // ASSUMING Target IP was in  host byte order

    return packet;
} //when you call this function targetIP needs to be in host order or else it won't work 


//std::unordered_map<ip_addr, ArpEntry> entries; we have this data structure to hold entries 
void ArpCache::tick() { //maintain backgruond states by cleaning up expired packets
    std::unique_lock lock(mutex); //this ensures only on thread can access this resource we are going to use since they are shared ptrs
    auto now = std::chrono::steady_clock::now(); //get time 

    //the only function of this for loop is to clear entries whose MAC we cant resolve 
    for (auto& entryPair : entries) { //so we go through each of the entries 
        ArpEntry &entry = entryPair.second; //we get the Arp Entry which is an IP -> MAC 

        if (!entry.queuedPackets.empty() && isUnresolved(entry.mac)) { 
            //so if stuff is queued and not resolved meaning there is data to send from our router 
            if (now - entry.timeAdded >= resendInterval) {
                //we check for a timeout, if so now we resend 
                if (entry.numTries < 7) {
                    //so now we make sure we haven't sent it too many times 
                    std::string iface = entry.queuedPackets.front().iface;
                    //we take interface or port that the ARPentry in the front is going to be sent from 

                    // Rebuild and send an ARP request
                    Packet arpReq = constructArpRequest(entryPair.first, iface, routingTable);
                    //construct a ARP request from that packet 
                    packetSender->sendPacket(arpReq, iface); //send packet given that hardware interface 

                    // Log and update metadata
                    spdlog::info("Resent ARP request for IP {} on iface {} [Try {}]", 
                                 ipToString(entryPair.first), iface, entry.numTries + 1);

                    entry.timeAdded = now; //mark the time 
                    entry.numTries++; //increment 
                } else {
                    // Give up after 7 tries and drop queued packets
                    spdlog::warn("ARP resolution failed for IP {} after 7 tries. Sending ICMP host unreachable.",
                                 ipToString(entryPair.first));

                    for (const auto& qp : entry.queuedPackets) {
                        // TODO (optional): Generate and send ICMP Destination Host Unreachable.
                        // e.g., packetSender->sendPacket(icmpErrorPacket, qp.iface);
                        spdlog::warn("Dropped packet queued for IP {} on iface {}", 
                                     ipToString(entryPair.first), qp.iface);
                    }
                    //sum gpt logging lol

                    // Clear the queue so we don't retry anymore
                    entry.queuedPackets.clear();
                    //it clears it after FAILING 7 times to get the MAC
                }
            }
        }
    } 

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    //this function assumes RESOLVED MAC addresses
    std::unique_lock lock(mutex);

     // TODO: Your code here
     ArpEntry& entry = entries[ip]; //so we implement the entry into the data structure 
     entry.timeAdded = std::chrono::steady_clock::now(); //we get the time
     entry.mac = mac; //get the mac
     entry.numTries = 0; // Reset tries
     //so we are going to process 
     spdlog::info("ARP entry added for IP: {} with MAC: {}", ip, toString(mac));

     for (const auto& qp : entry.queuedPackets) {
        Packet packet = qp.packet;
        //grabs the packet from the queue

        //so makes a ethernet header pointer with the packet data
        sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
        std::memcpy(eth_hdr->ether_dhost, mac.data, ETHER_ADDR_LEN);
        //this copys the destination host addr data wit the mac data 
        RoutingInterface intf = routingTable->getRoutingInterface(qp.iface);
        std::memcpy(eth_hdr->ether_shost, intf.mac.data, ETHER_ADDR_LEN);

        //Send the completed packet now that you have a mac address, I lowk feel you should just call it in 
        //here because we know the entry 
        packetSender->sendPacket(packet, qp.iface);

        spdlog::info("Flushed queued packet for IP {} via iface {}", ipToString(ip), qp.iface);
        //log clearing that packet 

    }

    entry.queuedPackets.clear(); //actually clear it 
     //needs an ARP factory in order to work 
    
    // TODO: Your code below

}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex); //locks the current thread when getting that entry to prevent race conditions on that memory 
    //implemented in unordered map of ip_addr->ArpEntry
    //If the entry exists and the MAC is resolved: It returns the MAC address otherwise it returns a nullopt 
    auto it = entries.find(ip); //get an iterator 
    if (it != entries.end() && !isUnresolved(it->second.mac)) { //check if exists and is resolved
        return it->second.mac; //return mac addr 
    } 
    // TODO: Your code below
    return std::nullopt; // Placeholder
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    //iface is where the IP addr gets filled in 
    //iface tells you:Which MAC/IP to fill in as the sender
    //Which physical port to send it out from
    //we know the ip addr 


    auto it = entries.find(ip); //iterator for the ip address 

    if (it == entries.end()) { //check for no exist
        // If no entry exists for this IP, create one with an unresolved MAC.
        ArpEntry newEntry; //make a new object for ARPentry 
        newEntry.timeAdded = std::chrono::steady_clock::now(); //get the current clock
        newEntry.mac = UNRESOLVED_MAC; // Unresolved: all zeros.
        newEntry.queuedPackets.push_back({packet, iface}); //so you push_back an ARPentry with the packet and interface of the ethernet
        entries[ip] = newEntry;
    } else {
        // Otherwise, just add the packet to the queue.
        it->second.queuedPackets.push_back({packet, iface});
    }

    spdlog::info("Packet queued on interface {} for IP: {}", iface, ip);
}



    // TODO: Your code below


