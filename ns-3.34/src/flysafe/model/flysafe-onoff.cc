/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
//
// Copyright (c) 2006 Georgia Tech Research Corporation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: George F. Riley<riley@ece.gatech.edu>
//

// ns3 - On/Off Data Source Application class
// George F. Riley, Georgia Tech, Spring 2007
// Adapted from ApplicationOnOff in GTNetS.

#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/packet-socket-address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/data-rate.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/boolean.h"
#include "ns3/ipv4.h"
#include "ns3/mobility-module.h"
#include "ns3/vector.h"

#include "ns3/flysafe-onoff.h"
#include "ns3/flysafe-tag.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("FlySafeOnOff");

NS_OBJECT_ENSURE_REGISTERED (FlySafeOnOff);

TypeId
FlySafeOnOff::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::FlySafeOnOff")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<FlySafeOnOff> ()
    .AddAttribute ("DataRate", "The data rate in on state.",
                   DataRateValue (DataRate ("500kb/s")),
                   MakeDataRateAccessor (&FlySafeOnOff::m_cbrRate),
                   MakeDataRateChecker ())
    .AddAttribute ("PacketSize", "The size of packets sent in on state",
                   UintegerValue (512),
                   MakeUintegerAccessor (&FlySafeOnOff::m_pktSize),
                   MakeUintegerChecker<uint32_t> (1))
    .AddAttribute ("Remote", "The address of the destination",
                   AddressValue (),
                   MakeAddressAccessor (&FlySafeOnOff::m_peer),
                   MakeAddressChecker ())
    .AddAttribute ("Local",
                   "The Address on which to bind the socket. If not set, it is generated automatically.",
                   AddressValue (),
                   MakeAddressAccessor (&FlySafeOnOff::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("OnTime", "A RandomVariableStream used to pick the duration of the 'On' state.",
                   StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"),
                   MakePointerAccessor (&FlySafeOnOff::m_onTime),
                   MakePointerChecker <RandomVariableStream>())
    .AddAttribute ("OffTime", "A RandomVariableStream used to pick the duration of the 'Off' state.",
                   StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"),
                   MakePointerAccessor (&FlySafeOnOff::m_offTime),
                   MakePointerChecker <RandomVariableStream>())
    .AddAttribute ("MaxBytes", 
                   "The total number of bytes to send. Once these bytes are sent, "
                   "no packet is sent again, even in on state. The value zero means "
                   "that there is no limit.",
                   UintegerValue (0),
                   MakeUintegerAccessor (&FlySafeOnOff::m_maxBytes),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("Protocol", "The type of protocol to use. This should be "
                   "a subclass of ns3::SocketFactory",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&FlySafeOnOff::m_tid),
                   // This should check for SocketFactory as a parent
                   MakeTypeIdChecker ())
    .AddAttribute ("EnableSeqTsSizeHeader",
                   "Enable use of SeqTsSizeHeader for sequence number and timestamp",
                   BooleanValue (false),
                   MakeBooleanAccessor (&FlySafeOnOff::m_enableSeqTsSizeHeader),
                   MakeBooleanChecker ())
    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_txTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("TxWithAddresses", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_txTraceWithAddresses),
                     "ns3::Packet::TwoAddressTracedCallback")
    .AddTraceSource ("TxWithSeqTsSize", "A new packet is created with SeqTsSizeHeader",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_txTraceWithSeqTsSize),
                     "ns3::PacketSink::SeqTsSizeCallback")
    .AddTraceSource ("TxTraces", "A new message is created and is sent - Monitoring neighborhood",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_txTraceMessage),
                     "ns3::FlySafeOnOff::TracedCallback")
    .AddTraceSource ("TxMaliciousTraces", "A new message is created and is sent - Monitoring malicious neighborhood",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_txMaliciousTraces),
                     "ns3::FlySafeOnOff::TracedCallback")
    .AddTraceSource ("StopTraces", "Monitor nodes while stopped",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_stopTraces),
                     "ns3::FlySafeOnOff::TracedCallback")
    .AddTraceSource ("EmptyNLTraces", "Monitor nodes with empty NL",
                     MakeTraceSourceAccessor (&FlySafeOnOff::m_emptyNLTraces),
                     "ns3::FlySafeOnOff::TracedCallback")
  ;
  return tid;
}



FlySafeOnOff::FlySafeOnOff ()
  : m_socket (0),
    m_connected (false),
    m_residualBits (0),
    m_lastStartTime (Seconds (0)),
    m_totBytes (0),
    m_unsentPacket (0)
{
  NS_LOG_FUNCTION (this);
}

FlySafeOnOff::~FlySafeOnOff()
{
  NS_LOG_FUNCTION (this);
}


/**
 * @brief Configure application settings
 * 
 * @param destiny IP address 
 * @param protocolId - UDP (1) or TCP (2)
 */
void FlySafeOnOff::Setup(Address address, uint32_t protocolId, double maliciousTime) {
  NS_LOG_FUNCTION(this);
  m_peer = address;
  m_node = GetNodeIpAddress();
  m_nodeIP = InetSocketAddress::ConvertFrom(m_node).GetIpv4();
  
  m_searchNeighbors = true;

  // Choose protocol
  if (protocolId == 1) // 1 Udp
    m_tid = ns3::UdpSocketFactory::GetTypeId();
  else // 2 tcp
    m_tid = ns3::TcpSocketFactory::GetTypeId();

  m_maliciousTime = maliciousTime;
  m_maliciousRegister = false;
}


/**
 * @brief Set max bytes
 * 
 * @param maxBytes 
 */
void 
FlySafeOnOff::SetMaxBytes (uint64_t maxBytes)
{
  NS_LOG_FUNCTION (this << maxBytes);
  m_maxBytes = maxBytes;
}


/**
 * @brief Get socket
 * 
 * @return Ptr<Socket> 
 */
Ptr<Socket>
FlySafeOnOff::GetSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}


int64_t 
FlySafeOnOff::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_onTime->SetStream (stream);
  m_offTime->SetStream (stream + 1);
  return 2;
}

void
FlySafeOnOff::DoDispose (void)
{
  NS_LOG_FUNCTION (this);

  CancelEvents ();
  m_socket = 0;
  m_unsentPacket = 0;
  // chain up
  Application::DoDispose ();
}


/**
 * @brief Start application. Called at time specified at Start time
 * 
 */
void FlySafeOnOff::StartApplication ()
{
  NS_LOG_FUNCTION (this);

  // 26Sep2022 
  // As node is created and set on coordinates (0,0,0),
  // we update its position with the information from the mobility model
  Vector position = GetNodeActualPosition();
  Ptr<Node> ThisNode = this->GetNode();
  ThisNode->SetPosition(position);
  // ----------------------
  // ThisNode->RegisterNeighbor(m_peer,position); //Setup one neighbor in the list

  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = Socket::CreateSocket (GetNode (), m_tid);
      int ret = -1;

      if (! m_local.IsInvalid())
        {
          NS_ABORT_MSG_IF ((Inet6SocketAddress::IsMatchingType (m_peer) && InetSocketAddress::IsMatchingType (m_local)) ||
                           (InetSocketAddress::IsMatchingType (m_peer) && Inet6SocketAddress::IsMatchingType (m_local)),
                           "Incompatible peer and local address IP version");
          ret = m_socket->Bind (m_local);
        }
      else
        {
          if (Inet6SocketAddress::IsMatchingType (m_peer))
            {
              ret = m_socket->Bind6 ();
            }
          else if (InetSocketAddress::IsMatchingType (m_peer) ||
                   PacketSocketAddress::IsMatchingType (m_peer))
            {
              ret = m_socket->Bind ();
            }
        }

      if (ret == -1)
        {
          NS_FATAL_ERROR ("Failed to bind socket");
        }

      m_socket->Connect (m_peer);
      m_socket->SetAllowBroadcast (true);
      m_socket->ShutdownRecv ();

      m_socket->SetConnectCallback (
        MakeCallback (&FlySafeOnOff::ConnectionSucceeded, this),
        MakeCallback (&FlySafeOnOff::ConnectionFailed, this));
    }
  m_cbrRateFailSafe = m_cbrRate;

  // Insure no pending event
  CancelEvents ();
  // If we are not yet connected, there is nothing to do here
  // The ConnectionComplete upcall will start timers at that time
  //if (!m_connected) return;
  ScheduleStartEvent ();
}


/**
 * @brief Stop application
 * 
 */
void FlySafeOnOff::StopApplication () // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);

  CancelEvents ();
  if(m_socket != 0)
    {
      m_socket->Close ();
    }
  else
    {
      NS_LOG_WARN ("FlySafeOnOff found null socket to close in StopApplication");
    }
}


/**
 * @brief Cancel pending events
 * 
 */
void FlySafeOnOff::CancelEvents ()
{
  NS_LOG_FUNCTION (this);

  if (m_sendEvent.IsRunning () && m_cbrRateFailSafe == m_cbrRate )
    { // Cancel the pending send packet event
      // Calculate residual bits since last packet sent
      Time delta (Simulator::Now () - m_lastStartTime);
      int64x64_t bits = delta.To (Time::S) * m_cbrRate.GetBitRate ();
      m_residualBits += bits.GetHigh ();
    }
  m_cbrRateFailSafe = m_cbrRate;
  Simulator::Cancel (m_sendEvent);
  Simulator::Cancel (m_startStopEvent);
  // Canceling events may cause discontinuity in sequence number if the
  // SeqTsSizeHeader is header, and m_unsentPacket is true
  if (m_unsentPacket)
    {
      NS_LOG_DEBUG ("Discarding cached packet upon CancelEvents ()");
    }
  m_unsentPacket = 0;
}

// Event handlers
void FlySafeOnOff::StartSending ()
{
  NS_LOG_FUNCTION (this);
  m_lastStartTime = Simulator::Now ();
  ScheduleNextTx ();  // Schedule the send packet event
  ScheduleStopEvent ();
}


/**
 * @brief Stop sending messages
 * 
 */
void FlySafeOnOff::StopSending ()
{
  NS_LOG_FUNCTION (this);
  CancelEvents ();

  ScheduleStartEvent ();
}


/**
 * @brief Schedule next tx
 * 
 * Function modified to schedule Tx events at 1s, like the mobility model
 * Check sendpacket modifications to verify nodes position before transmission'
 * 
 * @date Sep 26, 2022
 */
void FlySafeOnOff::ScheduleNextTx ()
{
  NS_LOG_FUNCTION (this);

  if (m_maxBytes == 0 || m_totBytes < m_maxBytes)
    {
      //NS_ABORT_MSG_IF (m_residualBits > m_pktSize * 8, "Calculation to compute next send time will overflow");
      uint32_t bits = m_pktSize * 8 - m_residualBits;
      NS_LOG_LOGIC ("bits = " << bits);

      // Original - Don't remove these comments
      // Time nextTime (Seconds (bits /
      //                        static_cast<double>(m_cbrRate.GetBitRate ()))); //
      //                        Time till next packet

      // 080918 - Modified to send just one packet in onTime interval, since
      // m_OnTime = 1
      Time nextTime(Seconds(0.5));                              
      NS_LOG_LOGIC ("nextTime = " << nextTime.As (Time::S));
      m_sendEvent = Simulator::Schedule (nextTime, &FlySafeOnOff::SendPacket, this);
    }
  else
    { // All done, cancel any pending events
      StopApplication ();
    }
}


/**
 * @brief Schedule start event
 * 
 * Changed method to offInterval of 1s. Send a packet at 2s interval
 * 
 * @date Sep 26, 2022
 * 
 */
void FlySafeOnOff::ScheduleStartEvent ()
{  // Schedules the event to start sending data (switch to the "On" state)
  NS_LOG_FUNCTION (this);

  // Update 04012024
  Time offInterval = Seconds (m_offTime->GetValue ());
  // Time offInterval = Seconds (0.5);
  NS_LOG_LOGIC ("start at " << offInterval.As (Time::S));
  
  //std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() << " - Start at " << offInterval.As (Time::S) << std::endl;
  
  m_startStopEvent = Simulator::Schedule (offInterval, &FlySafeOnOff::StartSending, this);
}

/**
 * @brief Schedule stop event
 * 
 */
void FlySafeOnOff::ScheduleStopEvent ()
{  // Schedules the event to stop sending data (switch to "Off" state)
  NS_LOG_FUNCTION (this);

  Time onInterval = Seconds (m_onTime->GetValue ());
  NS_LOG_LOGIC ("stop at " << onInterval.As (Time::S));
  //std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() << " - Stop at " << onInterval.As (Time::S) << std::endl;

  m_startStopEvent = Simulator::Schedule (onInterval, &FlySafeOnOff::StopSending, this);
}


/**
 * @brief Send message to neighbor nodes (broadcast and traps)
 * 
 */
void FlySafeOnOff::SendPacket ()
{
  NS_LOG_FUNCTION (this);

  NS_ASSERT (m_sendEvent.IsExpired ());

  std::vector<NeighInfos> neighListVector;
  // Variables to recover node NL
  std::vector<ns3::MyTag::NeighInfos> nodeInfosVectorTag; 
  ns3::MyTag::NeighInfos nodeInfo;
  std::vector<ns3::MyTag::MaliciousNode> maliciousList;

  double timeNow;
  //Vector nodePosition;
  std::vector<ns3::MyTag::NeighborFull> neighListFull;

  Ptr<Node> ThisNode = this->GetNode();
  
  // Tag value 0: Broadcast - Search neighbors (Hello message)
  // 		       1: Unicast - Identification (Location message)
  //		       2: Unicast - Update location (Trap message)
  //           3: Unicast - Special identification (Location 
  //                        message to neighbors beyond 1 hop 
  //                        and up to 80 meters away)
  //           4: Unicast - Suspect neighbor (FDI)
  //           5: Unicast - Blocked node
  //           6: Unicast - Suspicious reduction

  Vector position = GetNodeActualPosition();
  timeNow = Simulator::Now().GetSeconds();

  if (ThisNode->IsMoving(position)){
     ThisNode->SetPosition(position); // Save for future comparaison
     if(ThisNode->IsThereAnyNeighbor() && !m_searchNeighbors) {
        DecreaseNeighborsQuality();
        CleanNeighborsList();         // Remove nodes with quality 0 from NL  

        if((int)ThisNode->GetState() == 1){ // Node will be malcious?
          if (timeNow >= m_maliciousTime){ // Time to becom malicious
              if (!m_maliciousRegister){
              cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Turn to malicious operation!" << endl;
              m_maliciousRegister = true;
              }
              cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Real position is " 
                  << position.x << ", " << position.y << ", " << position.z << endl;
              position = GenerateFalseLocation(); // Generate a false location to disseminate
              cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - False position is " 
                  << position.x << ", " << position.y << ", " << position.z << endl;
          }
        }

        if (ThisNode->IsThereAnyNeighbor(1)) {
          notifyNewPosition(position);  // Update neighbors with new position
          PrintMyNeighborList();
        }
        else{
          m_searchNeighbors = true;
          timeNow = Simulator::Now().GetSeconds();
          neighListFull = GetNeighborIpListFull();
          m_emptyNLTraces(timeNow, position, m_nodeIP, neighListFull);
          maliciousList = GetMaliciousNeighborList();
          m_txMaliciousTraces(timeNow, m_nodeIP, maliciousList);
        }
     }
     else{
        m_searchNeighbors = true;
        timeNow = Simulator::Now().GetSeconds();
        neighListFull = GetNeighborIpListFull();
        m_emptyNLTraces(timeNow, position, m_nodeIP, neighListFull);
        maliciousList = GetMaliciousNeighborList();
        m_txMaliciousTraces(timeNow, m_nodeIP, maliciousList);
     }
     //else
     
     
     if((int)ThisNode->GetState() == 1){ // Node will be malcious?
       if (timeNow >= m_maliciousTime){ // Time to becom malicious
          if (!m_maliciousRegister){
          cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Turn to malicious operation!" << endl;
          m_maliciousRegister = true;
          }
          cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Real position is " 
               << position.x << ", " << position.y << ", " << position.z << endl;
          position = GenerateFalseLocation(); // Generate a false location to disseminate
          cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - False position is " 
               << position.x << ", " << position.y << ", " << position.z << endl;
       }
     }

     if(m_searchNeighbors) {  // Search neighbors sending a broadcast message
        if (!ThisNode->IsThereAnyNeighbor(1) && ThisNode->IsThereAnyNeighbor()){ // If no 1 hop neighbor(s) in NL, clean up NL
          ThisNode->ClearNeighborList();
          std::cout << m_nodeIP << " : " << timeNow 
                    << " FlySafeOnOff - Cleaned up my Neighbor List!"
                    << std::endl; 
        }
        m_searchNeighbors = false;
        Ptr<Packet> packet = Create<Packet>(reinterpret_cast<const uint8_t *>("Hello!"), 6);  // Create a packet
        MyTag broadcastTag;                 // Create a tag

        std::cout << "\n" << m_nodeIP << " : " << timeNow 
                  << " FlySafeOnOff - Search neighbors from position x: "
                  << position.x << " y: " << position.y << " z: " << position.z 
                  << "\n" << std::endl; 

        broadcastTag.SetSimpleValue(0);     // Add value to tag
        broadcastTag.SetNNeighbors(ThisNode->GetNNeighbors());      // Broadcast only with NL = 0       
        broadcastTag.SetPosition(position); // Add nodes positin to tag
        broadcastTag.SetMessageTime(timeNow);

        if (ThisNode->GetNNeighbors() != 0){ // Get NL and add to tag
          neighListVector = GetNeighborListVector();

          for(auto n :neighListVector){ // Copy NL to a MyTag::NeighInfos vector type
            nodeInfo.ip = n.ip;
            nodeInfo.x = n.x;
            nodeInfo.y = n.y;
            nodeInfo.z = n.z; 
            nodeInfo.hop = n.hop;
            nodeInfo.state = n.state;
            nodeInfosVectorTag.push_back(nodeInfo);
          }
        }  
        broadcastTag.SetNeighInfosVector(nodeInfosVectorTag);
        
        packet->AddPacketTag(broadcastTag); // Add tag to the packet
        
        m_txTrace(packet);
        m_socket->Send(packet);
        m_totBytes += m_pktSize;

        InetSocketAddress receiverAddress = InetSocketAddress::ConvertFrom(m_peer); // Receiver address

        Address localAddress;
        m_socket->GetSockName(localAddress);
        if (InetSocketAddress::IsMatchingType(m_peer)) {
          if (receiverAddress.GetIpv4().IsBroadcast()) // Broadcast message
          {
            //NS_LOG_INFO (m_nodeIP << ":" << Simulator::Now().GetSeconds ()
            //                  << ":Sent message to search neighbors!");
            //std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds ()
            //          << " FlySafeOnOff - Sent message to search neighbors!" << std::endl;
          } else {
            NS_LOG_INFO(m_nodeIP << ":" << Simulator::Now().GetSeconds()
                                << ": Sent message to "
                                << receiverAddress.GetIpv4() << " - Tag "
                                << (int)broadcastTag.GetSimpleValue());
          }
          m_txTraceWithAddresses(packet, localAddress, receiverAddress);
        }
        neighListFull = GetNeighborIpListFull();
        m_txTraceMessage(timeNow, m_nodeIP, m_nodeIP.GetBroadcast(), 0, "Hello", position, neighListFull); // Callback to trace messages sent
        maliciousList = GetMaliciousNeighborList();
        m_txMaliciousTraces(timeNow, m_nodeIP, maliciousList);
     }   
  }
  else{
    // Register nodes infos when stopped
    timeNow = Simulator::Now().GetSeconds();
    neighListFull = GetNeighborIpListFull();
    cout << m_nodeIP << " : " << timeNow << " - Node stopped!" << endl; 
    m_stopTraces(timeNow, position, m_nodeIP, m_nodeIP, 4, 
                      "Stopped", neighListFull, timeNow);
    maliciousList = GetMaliciousNeighborList();
    m_txMaliciousTraces(timeNow, m_nodeIP, maliciousList);
  }      

  m_residualBits = 0;
  m_lastStartTime = Simulator::Now ();
  ScheduleNextTx ();
}


void FlySafeOnOff::ConnectionSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  m_connected = true;
}

void FlySafeOnOff::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_FATAL_ERROR ("Can't connect");
}

/*
 * -------------------------------------------------------
 * The following methods extends class on-off to meet UAV
 * needs
 * -------------------------------------------------------
 */


/**
 * @brief Get node IP address (IP:port)
 * @date 22Sep2022
 * 
 * @param NIL
 * @return Node IP Address (IP:port)
 */
Address FlySafeOnOff::GetNodeIpAddress() {
  Ptr<Node> PtrNode = this->GetNode();
  Ptr<Ipv4> ipv4 = PtrNode->GetObject<Ipv4>();
  Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1, 0);
  Ipv4Address ipAddr = iaddr.GetLocal();
  return (InetSocketAddress(ipAddr, 9));
}


/**
 * @brief Get node actual position
 * @date 26Sep2022
 * 
 * @param NIL
 * @return Vector (x,y,z) with node actual position
 */
Vector FlySafeOnOff::GetNodeActualPosition()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_sendEvent.IsExpired ());

  Ptr<Node> ThisNode = this->GetNode();
  Ptr<MobilityModel> position = ThisNode->GetObject<MobilityModel> (); // Check node current position - 26Sep2022
  NS_ASSERT (position != 0);

  return(position->GetPosition ());
}


/**
 * @brief Update neighbors nodes with nodes new position (trap message)
 * @date 29Sep2022
 * 
 * @param position - Vector with nodes position (x, y, z)
 * @returns NIL
 */
void FlySafeOnOff::notifyNewPosition(Vector position){
  
  vector<Ipv4Address> neighborList;
  std::vector<NeighInfos> neighInfosVector;
  Address neighIPPort;
  double timeNow;
  //ostringstream trapString;

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList(); // get node neighbors list
  neighInfosVector = GetNeighborListVector();

  MyTag tag;
  std::vector<ns3::MyTag::NeighInfos> neighInfosVectorTag; 
  std::vector<ns3::MyTag::NeighborFull> neighListFull;

  ns3::MyTag::NeighInfos nodeInfo;

	for(auto n :neighInfosVector){ // Copy NL to a MyTag::NeighInfos vector type
		nodeInfo.ip = n.ip;
		nodeInfo.x = n.x;
		nodeInfo.y = n.y;
		nodeInfo.z = n.z; 
    nodeInfo.hop = n.hop;
    nodeInfo.state = n.state;
    neighInfosVectorTag.push_back(nodeInfo);
	}

  tag.SetSimpleValue(2); // Tag value 2: Unicast - Update location (Trap message)
  tag.SetNNeighbors((uint32_t)ThisNode->GetNNeighbors()); // Add the number of neighbor nodes to tag
  tag.SetPosition(position); // Add nodes positin to tag
  tag.SetNeighInfosVector(neighInfosVectorTag);

  timeNow = Simulator::Now().GetSeconds();
  neighListFull = GetNeighborIpListFull();

  tag.SetMessageTime(timeNow);

  // if((int)ThisNode->GetState() == 1){ // Node will be malcious?
  //   if (timeNow >= m_maliciousTime){ // Time to becom malicious
  //     cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Turn to malicious operation!" << endl;
  //     cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - Real position is " 
  //           << position.x << ", " << position.y << ", " << position.z << endl;
  //     position = GenerateFalseLocation(); // Generate a false location to disseminate
  //     cout << m_nodeIP << " : " << timeNow << " FlySafeOnOff - False position is " 
  //           << position.x << ", " << position.y << ", " << position.z << endl;
  //   }
  // }


  for (uint8_t i = 0; i < neighborList.size(); i++) {  // Check all neighbors nodes at 1 hop and send message
    
    // trapString.str("");

    // Send a special identification no neighbor nodes 1 hop away, but closer than 86 m
    if((int)ThisNode->GetNeighborHop(neighborList[i]) > 1 && ThisNode->GetNeighborDistance(neighborList[i]) < 86){
      // 86m is the range to 802.11n
      
      cout << m_nodeIP << " : " << timeNow 
           << " FlySafeOnOff - Sent special identification message from new position x: "
           << position.x << " y: " << position.y << " z: " 
           << position.z << " to " << neighborList[i] << ". It is " 
           << (int)ThisNode->GetNeighborHop(neighborList[i]) << " hop(s) away at "
           << (int)ThisNode->GetNeighborDistance(neighborList[i]) << " meters" << std::endl; 

      neighIPPort = InetSocketAddress(neighborList[i], 9); // Register address with port = 9

      SendMessage(neighIPPort,"Special identification",3, (uint32_t) ThisNode->GetNNeighbors(), position, neighInfosVectorTag);

      // Callback to trace messages sent
      m_txTraceMessage(timeNow, m_nodeIP, neighborList[i], 3, "Special identification", position, neighListFull);
    }

    // Send trap messages to one hop neighbors only
    if((int)ThisNode->GetNeighborHop(neighborList[i]) == 1 && ThisNode->GetNeighborDistance(neighborList[i]) < 85){ 
      
      cout << m_nodeIP << " : " << timeNow 
           << " FlySafeOnOff - Sent trap message from new position x: "
           << position.x << " y: " << position.y << " z: " 
           << position.z << " to " << neighborList[i] << " - I have " 
           << (uint32_t)ThisNode->GetNNeighbors() << " neighbors" << std::endl; 

      cout << m_nodeIP << " : " << timeNow 
          << " FlySafeOnOff - NL sent within trap message:" << std::endl;
    
      PrintNeighborList(neighInfosVectorTag);

      Address DestinyAddress(InetSocketAddress(neighborList[i], 9));
      Ptr<Socket> socket = Socket::CreateSocket(GetNode(), m_tid);

      if (socket->Bind() == -1) {
        NS_FATAL_ERROR("Failed to bind socket");
      }

      socket->Connect(DestinyAddress);
      Ptr<Packet> packet;
      packet = Create<Packet>(reinterpret_cast<const uint8_t *>("Trap!"),5); // Create a packet to send the message 
      packet->AddPacketTag(tag); // add the tag to packet
      socket->Send(packet); // Send packet
      socket->Close();  // Close socket

      m_txTraceMessage(timeNow, m_nodeIP, neighborList[i], 2, "Trap", position, neighListFull); // Callback to messages sent
      
      if((int)ThisNode->GetNeighborQuality(neighborList[i]) == 1){ // No answer form neigh node in last round
        //register node data as empty list
        m_emptyNLTraces(timeNow, position, m_nodeIP, neighListFull);
      }
    }
  } 
}


/**
 * @brief Print node neighbors list
 * @date 29Sep2022
 * 
 * @returns NIL
 */

void FlySafeOnOff::PrintMyNeighborList() {
  vector<Ipv4Address> neighborList;
  Vector position;

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();
  
  cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
       << " FlySafeOnOff - My neighbors are: "
       << ThisNode->GetNNeighbors() << endl;
       
  for (uint8_t i = 0; i < neighborList.size(); i++) {
    position = ThisNode->GetNeighborPosition(neighborList[i]);
    cout << neighborList[i] << " : Position x: " 
         << position.x << " y: " << position.y << " z: " << position.z 
         << " Distance: " << ThisNode->GetNeighborDistance(neighborList[i]) 
         << "m Attitude: " << (int)ThisNode->GetNeighborAttitude(neighborList[i])
         << " Quality: " << (int)ThisNode->GetNeighborQuality(neighborList[i])
         << " Hop: " << (int)ThisNode->GetNeighborHop(neighborList[i])
         << " State: " << (int)ThisNode->GetNeighborNodeState(neighborList[i]) << endl;
  }
  cout << "\n" << endl;
}

/**
 * @brief Decrease the quality of each node neighbors in the NL
 * @date Jan 2, 2023
 * 
 * @returns NIL
 */

void FlySafeOnOff::DecreaseNeighborsQuality() {
  vector<Ipv4Address> neighborList;
  u_int8_t quality;

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();
  
  for (uint8_t i = 0; i < neighborList.size(); i++) {
    quality = ThisNode->GetNeighborQuality(neighborList[i]);
    if (quality > 0){
      ThisNode->SetNeighborQuality(neighborList[i], --quality);
    }
  }
}


/**
 * @brief Remove nodes with quality 0 from NL
 * @date Jan 3, 2023
 * 
 * @returns NIL
 */

void FlySafeOnOff::CleanNeighborsList() {
  vector<Ipv4Address> neighborList;

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();
  uint8_t i = 0;

  for (i = 0; i < neighborList.size(); i++) {
    if ((int)ThisNode->GetNeighborQuality(neighborList[i]) == 0 and 
        (int)ThisNode->GetNeighborNodeState(neighborList[i]) == 0) { // Not remove suspicious nodes - Nov 9, 23
      cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
           << " FlySafeOnOff - Removing neighbor node "
           << neighborList[i] << " with quality " << (int)ThisNode->GetNeighborQuality(neighborList[i]) 
           << " hop " << (int)ThisNode->GetNeighborHop(neighborList[i]) 
           << " and state " << (int)ThisNode->GetNeighborNodeState(neighborList[i]) 
           << " from my NL" << std::endl;   
      ThisNode->UnregisterNeighbor(neighborList[i]);
    }
  }
  if ((int)ThisNode->GetNNeighbors() == 0){
    cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
          << " FlySafeOnOff - My neighbor list is empty! \n" << std::endl; 
  }
}

/**
 * @brief Create a vector from node neigbor list
 * @date Feb 22, 2023
 * 
 * @param neighborList Vector with neighbor list Ipv4 Adress
 */

std::vector<FlySafeOnOff::NeighInfos> FlySafeOnOff::GetNeighborListVector(){
  vector<Ipv4Address> neighborList;
  std::vector<FlySafeOnOff::NeighInfos> neighborListVector;
  Vector position;
  FlySafeOnOff::NeighInfos node;

  neighborListVector.clear();
  
  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();
  
  for (uint8_t i = 0; i < neighborList.size(); i++) {
    position = ThisNode->GetNeighborPosition(neighborList[i]);
		node.ip = neighborList[i];
		node.x = position.x;
		node.y = position.y;
		node.z = position.z;
    node.hop = ThisNode->GetNeighborHop(neighborList[i]);
    node.state = ThisNode->GetNeighborNodeState(neighborList[i]);
		neighborListVector.push_back(node);
  }  
  return neighborListVector;
}


/**
 * @brief Send a message to a neighbor node
 * @date Mar 08, 2023
 * 
 * @param addressTo Neighbor node address (IPv4 + port)
 * @param message Message (string)
 * @param tagValue Tag value (0, 1, 2 or 3)
 * @param nNeigbors Number of neighbor nodes from the source node
 * @param nodePosition Source node position
 */
void FlySafeOnOff::SendMessage(Address addressTo, string message,
                               uint8_t tagValue, u_int32_t nNeigbors, Vector nodePosition,
                               std::vector<ns3::MyTag::NeighInfos> nodeInfos) {

  double timeNow;

  Address destinyAddress(InetSocketAddress(
      Ipv4Address(InetSocketAddress::ConvertFrom(addressTo).GetIpv4()), 9));  // Add port 9 to destiny address
  Ptr<Socket> socket = Socket::CreateSocket(GetNode(), m_tid);

  if (socket->Bind() == -1) {
    NS_FATAL_ERROR("Failed to bind socket");
  }

  socket->Connect(destinyAddress);
  Ptr<Packet> packet;

  packet = Create<Packet>(reinterpret_cast<const uint8_t *>(message.c_str()),
                          message.size());
  MyTag tagToSend;
  tagToSend.SetSimpleValue(tagValue);         // Add tag value
  tagToSend.SetNNeighbors(nNeigbors);         // Add the number of neighbor nodes to tag
  tagToSend.SetPosition(nodePosition);        // Add nodes positin to tag
  tagToSend.SetNeighInfosVector(nodeInfos);   // Add nodes NL to tag
  
  timeNow = Simulator::Now().GetSeconds();
  tagToSend.SetMessageTime(timeNow);

  packet->AddPacketTag(tagToSend);
  socket->Send(packet);
  socket->Close();
}

/**
 * @brief Get the Neighbor Ip List Full object
 * @date Apr 7, 2023
 * 
 * @return vector<ns3::MyTag::NeighborFull> 
 */
vector<ns3::MyTag::NeighborFull> FlySafeOnOff::GetNeighborIpListFull() { 
  vector<Ipv4Address> neighborList;
  vector<ns3::MyTag::NeighborFull> neighListFull;
  ns3::MyTag::NeighborFull NeighInfo;
  Vector position;
  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();

  for (uint8_t i = 0; i < neighborList.size(); i++) {
    NeighInfo.ip = neighborList[i];
    NeighInfo.position = ThisNode->GetNeighborPosition(neighborList[i]);
    NeighInfo.distance = ThisNode->GetNeighborDistance(neighborList[i]);
    NeighInfo.hop = ThisNode->GetNeighborHop(neighborList[i]);
    NeighInfo.state = ThisNode->GetNeighborNodeState(neighborList[i]);
    NeighInfo.attitude = ThisNode->GetNeighborAttitude(neighborList[i]);
    NeighInfo.quality = ThisNode->GetNeighborQuality(neighborList[i]);
    neighListFull.push_back(NeighInfo);
  }
  return neighListFull;
}

/**
 * @brief Get malicious neighbor list from the node
 * @date Nov 27, 2023
 * 
 * @return vector<ns3::MyTag::MaliciousNode> 
 */
vector<ns3::MyTag::MaliciousNode> FlySafeOnOff::GetMaliciousNeighborList() { 
  vector<Ipv4Address> maliciousIPList;
  vector<ns3::MyTag::MaliciousNode> maliciousListFull;
  ns3::MyTag::MaliciousNode maliciousInfo;
  Vector position;

  Ptr<Node> ThisNode = this->GetNode();
  maliciousIPList = ThisNode->GetMaliciousNodeIpList();

  for (uint8_t i = 0; i < maliciousIPList.size(); i++) {
    maliciousInfo.ip = maliciousIPList[i];
    maliciousInfo.state = ThisNode->GetMaliciousNodeState(maliciousIPList[i]);
    maliciousInfo.recurrence = ThisNode->GetMaliciousNodeRecurrence(maliciousIPList[i]);
    maliciousInfo.notifyIP = ThisNode->GetMaliciousNodesIPNotifiers(maliciousIPList[i]);
    maliciousListFull.push_back(maliciousInfo);
  }
  return maliciousListFull;
}

} // Namespace ns3
