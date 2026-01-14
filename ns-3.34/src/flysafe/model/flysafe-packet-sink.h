#include "ns3/address-utils.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet-socket-address.h"
#include "ns3/string.h"
#include "ns3/mobility-module.h"

//#include "flysafe-tag.h"
#include "ns3/utils.h"
#include "ns3/flysafe-tag.h"

using namespace std;

namespace ns3 {

/* ========================================================================
 * FlySafePacketSink class
 *
 * Inherited from Application class
 *
 * Receive and analyze packets
 *
 * ========================================================================
 */

class FlySafePacketSink : public Application
{

public:
  static TypeId GetTypeId(void);
  FlySafePacketSink();
  virtual ~FlySafePacketSink();
  void Setup(Address addressTo, uint32_t protocolId, double maliciousTime);

  /**
  * @brief Struct to store infos from a neighbor node
  * @date 25022023
  */
  struct NeighInfos {
        Ipv4Address ip;
        double x;
        double y;
        double z;
        uint8_t hop;
        uint8_t state;
  };   

private:
  // inherited from Application base class.
  void StartApplication();
  void StopApplication();
  void PacketReceived(Ptr<Socket> socket);
  void ManipulateRead(Ptr<Socket> socket);
  void ManipulatePeerClose(Ptr<Socket> socket);
  void ManipulatePeerError(Ptr<Socket> socket);
  void ManipulateAccept(Ptr<Socket> s, const Address &from);
  void SendMessage(Address addressTo, string message, uint8_t tagy, 
                   u_int32_t nNeigbors, Vector nodePosition,
                   std::vector<ns3::MyTag::NeighInfos> nodeInfos);
  
  /**
   * \brief Get node nodes actual position
   */
  Vector GetNodeActualPosition();


  // added by me
  Address GetNodeIpAddress();


  /**
   * @brief Print my neighbor list
   * @date Feb 27, 2023
   * @param neighborList Node IPv4 neighbor list
   */
  void PrintMyNeighborList(); 
 
  /**
   * @brief Print a node suspicious list
   * @date Nov 02, 2023
   */

  void PrintMySupiciousList();

  /**
   * @brief Update a node NL from a received neighbor node NL 
   * @date Feb 25, 2023
   * 
   * @param neighInfos Vector of structs with neighbor nodes information
   */
  void UpdateMyNeighborList(std::vector<ns3::MyTag::NeighInfos> neighInfos); 


  /**
   * @brief Check neighbor node attitude (0 - keep, 1 - inbound, 2 - outbound)
   * @date Feb 27, 2023
   * 
   * @param newDistance Actual new distance from neighbor node
   * @param oldDistance Previous saved distance
   * @return uint8_t Neighbor node attitude
   */
  uint8_t CheckNeighAttitude(double newDistance, double oldDistance);


  /**
   * @brief Create a vector from node neighbor list
   * 
   */
  std::vector<NeighInfos> GetNeighborListVector();


  /**
   * @brief Puts neighbors information in a string
   * @date Mar 28, 2023
   * 
   * @return ostringstream neighbor nodes information string
   */
  ostringstream neighListToString();

  /**
   * @brief Get the Neighbor Ip List Full object
   * @date Apr 7, 2023
   * 
   * @return vector<ns3::MyTag::NeighborFull> 
   */
  vector<ns3::MyTag::NeighborFull> GetNeighborIpListFull();

  /**
   * @brief Get malicious neighbor list from the node
   * @date Nov 27, 2023
   * 
   * @return vector<ns3::MyTag::MaliciousNode> 
   */
  vector<ns3::MyTag::MaliciousNode> GetMaliciousNeighborList();

  /**
   * @brief Notify neighbor nodes (one hop away and non malicious) about a malicious node
   * 
   * @param maliciousIP - malicious node IP address
   * @param state - 0 (suspect) or 1 (blocked)
   * @param tagValue - Message tag
   */
  void NotifyNeighbors(Ipv4Address maliciousIP, Vector position, uint8_t state, uint8_t tagValue);

//}

  // inherited from Application base class.
  Address m_local;                //!< Local address to bind to
  uint64_t m_totalRx;             //!< Total bytes received
  TypeId m_tid;                   //!< Protocol TypeId
  Ptr<Socket> m_socket;           //!< Listening socket
  list<Ptr<Socket>> m_socketList; //!< the accepted sockets
  EventId m_sendEvent;            //!< Event id of pending "send packet" event

  // added by me
  string m_myId;                  //!< store competence + interests
  Address m_node;                 //!< Application node address
  Ipv4Address m_nodeIP;           //!< Node's IPv4 Address
  double m_maliciousTime;         //!< Store the time a node becomes malicious (default: 9999.99)

  TracedCallback<Ptr<const Packet>, const Address &>
      m_rxTrace;              //!< Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &, const Address &>
      m_rxTraceWithAddresses; //!< Traced Callback: received packets, source and
                              //!< destination address.
  TracedCallback<double, Vector, Ipv4Address, Ipv4Address, int, string, std::vector<ns3::MyTag::NeighborFull>, 
      double> m_sinkTrace;   //!< Traced Callback: received messages 
      //double, std::vector<ns3::MyTag::MaliciousNode>> m_sinkTrace;   //!< Traced Callback: received messages 
  TracedCallback <double, Ipv4Address, Ipv4Address, int, string, Vector,std::vector<ns3::MyTag::NeighborFull>> 
      m_txTrace;              //!< Traced value to sent messages
  TracedCallback<double, Ipv4Address, std::vector<ns3::MyTag::MaliciousNode>> 
      m_sinkMaliciousTrace;   //!< Traced Callback: received messages 
  bool m_maliciousRegister;                         //!< Register wether a node becomes malicious
};

} // namespace ns3