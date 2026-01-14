#include "flysafe-packet-sink.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("FlySafePacketSink");


TypeId FlySafePacketSink::GetTypeId(void) {
  static TypeId tid =
      TypeId("ns3::FlySafePacketSink")
          .SetParent<Application>()
          .SetGroupName("Applications")
          .AddConstructor<FlySafePacketSink>()
          .AddAttribute("Local", "The Address on which to Bind the rx socket.",
                        AddressValue(),
                        MakeAddressAccessor(&FlySafePacketSink::m_local),
                        MakeAddressChecker())
          .AddAttribute("Protocol",
                        "The type id of the protocol to use for the rx socket.",
                        TypeIdValue(UdpSocketFactory::GetTypeId()),
                        MakeTypeIdAccessor(&FlySafePacketSink::m_tid),
                        MakeTypeIdChecker())
          .AddTraceSource("Rx", "A packet has been received",
                          MakeTraceSourceAccessor(&FlySafePacketSink::m_rxTrace),
                          "ns3::Packet::AddressTracedCallback")
          .AddTraceSource("RxWithAddresses", "A packet has been received",
                          MakeTraceSourceAccessor(&FlySafePacketSink::m_rxTraceWithAddresses),
                          "ns3::Packet::TwoAddressTracedCallback")
          .AddTraceSource("SinkTraces", "A message has been received",
                          MakeTraceSourceAccessor(&FlySafePacketSink::m_sinkTrace),
                          "ns3::FlySafePacketSink::TracedCallback")
          .AddTraceSource("SinkMaliciousTraces", "A message has been received",
                          MakeTraceSourceAccessor(&FlySafePacketSink::m_sinkMaliciousTrace),
                          "ns3::FlySafePacketSink::TracedCallback")
          .AddTraceSource("TxTraces", "A new message is created and is sent",
                          MakeTraceSourceAccessor (&FlySafePacketSink::m_txTrace),
                          "ns3::FlySafePacketSink::TracedCallback");
  return tid;
}

FlySafePacketSink::FlySafePacketSink() {
  NS_LOG_FUNCTION(this);
  m_socket = 0;
  m_totalRx = 0;
}

FlySafePacketSink::~FlySafePacketSink() { 
  NS_LOG_FUNCTION(this); 
}


/**
 * @brief Setup FlySafePacketSink application at startup
 * 
 * @param toAddress IPv4 address to bind to
 * @param protocolId Type of protocol to be used to (1 - UDP, 2 - TCP)
 */
void FlySafePacketSink::Setup(Address toAddress, uint32_t protocolId, double maliciousTime) {

  NS_LOG_FUNCTION(this);
  m_node = GetNodeIpAddress();
  m_nodeIP = InetSocketAddress::ConvertFrom(m_node).GetIpv4();
  m_local = toAddress;
  m_socket = 0;
  m_totalRx = 0;

  Ptr<Node> ThisNode = this->GetNode();

  if (protocolId == 1) // 1 Udp
    m_tid = ns3::UdpSocketFactory::GetTypeId();
  else // 2 tcp
    m_tid = ns3::TcpSocketFactory::GetTypeId();  

  m_maliciousTime = maliciousTime;
  m_maliciousRegister = false;
}

/**
 * @brief Stop FlySafePacketSink application
 */
void FlySafePacketSink::StopApplication() {
  NS_LOG_FUNCTION(this);
  while (!m_socketList.empty()) // these are accepted sockets, close them
  {
    Ptr<Socket> acceptedSocket = m_socketList.front();
    m_socketList.pop_front();
    acceptedSocket->Close();
  }
  if (m_socket) {
    m_socket->Close();
    m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
  }
}


/**
 * @brief Start FlySafePacketSink application
 */
void FlySafePacketSink::StartApplication() {
  NS_LOG_FUNCTION(this);
 
  if (!m_socket) { // Create the socket if not already
    m_socket = Socket::CreateSocket(GetNode(), m_tid);
    m_socket->SetAllowBroadcast(true);
    if (m_socket->Bind(m_local) == -1) {
      NS_FATAL_ERROR("Failed to bind socket");
    }
    m_socket->Listen();
    m_socket->ShutdownSend();
    if (addressUtils::IsMulticast(m_local)) {
      Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket>(m_socket);
      if (udpSocket) {        
        udpSocket->MulticastJoinGroup(0, m_local); // equivalent to setsockopt (MCAST_JOIN_GROUP)
      } else {
        NS_FATAL_ERROR("Error: joining multicast on a non-UDP socket");
      }
    }
  }

  m_socket->SetRecvCallback(
      MakeCallback(&FlySafePacketSink::PacketReceived, this));
  m_socket->SetAcceptCallback(
      MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&FlySafePacketSink::ManipulateAccept, this));
  m_socket->SetCloseCallbacks(
      MakeCallback(&FlySafePacketSink::ManipulatePeerClose, this),
      MakeCallback(&FlySafePacketSink::ManipulatePeerError, this));

  //cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() << " FlySafePacketSink - Starting application!" << endl; // To be commented!
}


/**
 * @brief Handle a packet received from a neighbor node
 * 
 * @param socket Socket received
 */
void FlySafePacketSink::PacketReceived(Ptr<Socket> socket) {

  Ptr<Packet> packet;
  Address neighAdd;
  Address neighIPPort;
  Address localAddress;
  Ipv4Address neighIP;    // Store neighbor node IPv4 to display
  string newBuffer;
  string oldBuffer;
  double distance, value;
  double oldDistance;     // Store the old neighbor node distance
  uint8_t neighAttitude;  // Store the new neighbor node attitude
  Vector nodePosition;    // Store node position
  vector<Ipv4Address> neighborList; // Store node neighbors list 
  std::vector<FlySafePacketSink::NeighInfos> neighborListVector; // Store node NL
  double timeNow;
  int nNeigh; // Store number of neigbhors in the node neighbors list
  //uint8_t nState; // neighbor operation state (0 ordinary, 1 suspect)

  bool suspiciousRegistered = false;

  // Tag value 0: Broadcast - Search neighbors (Hello message)
  // 		       1: Unicast - Identification (Location message)
  //		       2: Unicast - Update location (Trap message)
  //           3: Unicast - Special identification (Location message to neighbors beyond 1 hop and up to 80 meters away)
  //           4: Unicast - Suspect neighbor (FDI)
  //           5: Unicast - Blocked node
  //           6: Unicast - Suspicious recurrence reduction

  MyTag receivedTag; // Create a tag

  // Variables to store information from received tag
  std::vector<ns3::MyTag::NeighInfos> neighInfosVectorTag;  // Store received NL
  uint32_t numberNNeighbors;                                // Store the number of neighbors in the neighbor node NL
  Vector position;                                          // Store neighbor node position (x, y, z)

  Ptr<Node> ThisNode = this->GetNode();  
  nodePosition = GetNodeActualPosition();
  neighborList = ThisNode->GetNeighborIpList();

  // Variables to recover node NL
  std::vector<NeighInfos> nodeInfosVector;
  std::vector<ns3::MyTag::NeighInfos> nodeInfosVectorTag; 
  ns3::MyTag::NeighInfos nodeInfo;
  std::vector<ns3::MyTag::NeighborFull> neighListFull; 
  std::vector<ns3::MyTag::MaliciousNode> maliciousList;

  while ((packet = socket->RecvFrom(neighAdd))) {
    neighIP = InetSocketAddress::ConvertFrom(neighAdd).GetIpv4();
    neighIPPort = InetSocketAddress(neighIP, 9); // Register all address with port = 9

    if (packet->GetSize() == 0) { // EOF
      break;
    }
    m_totalRx += packet->GetSize();

    if (InetSocketAddress::IsMatchingType(neighAdd)) {
      newBuffer = "";
      newBuffer.clear();
      uint8_t *buffer = new uint8_t[packet->GetSize()];
      packet->CopyData(buffer, packet->GetSize());
      newBuffer = (char *)buffer;

      nNeigh = ThisNode->GetNNeighbors();

      if(nNeigh != 0){ // Recover node NL only if node NL != 0. So, create a vector with NL
        nodeInfosVector = GetNeighborListVector();

        for(auto n :nodeInfosVector){ // Copy NL to a MyTag::NeighInfos vector type
          nodeInfo.ip = n.ip;
          nodeInfo.x = n.x;
          nodeInfo.y = n.y;
          nodeInfo.z = n.z; 
          nodeInfo.hop = n.hop;
          nodeInfo.state = n.state;
          nodeInfosVectorTag.push_back(nodeInfo);
        }
      }  

      // Recover tag from packet and the information inside it
      packet->PeekPacketTag(receivedTag);
      position = receivedTag.GetPosition();
      numberNNeighbors = receivedTag.GetNNeighbors();
      neighInfosVectorTag = receivedTag.GetNeighInfosVector(); // Get the NL from the received tag
      
      std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
                            << " FlySafePacketSink - NL recovered from received packet from "
                            << neighIP << ", tag " <<  (int)receivedTag.GetSimpleValue()
                            << " and with " << (int)numberNNeighbors 
                            << " neighbors:" << std::endl;
      PrintNeighborList(neighInfosVectorTag);

      value = CalculateNodesDistance(nodePosition, position); // Calculate distance between nodes
      distance = std::ceil(value * 100.0) / 100.0; // 2 decimal cases
      
      oldDistance = ThisNode->GetNeighborDistance (neighIP); // Get the old neighbor node distance from this node 
      neighAttitude = CheckNeighAttitude(distance, oldDistance);      
      
      timeNow = Simulator::Now().GetSeconds();

      // Included malicious nodes analysis 
      // Fault data injection
      // 30/10/2023
      cout << m_nodeIP << " : " << timeNow 
           << " FlySafePacketSink - Message received from " << neighIP << " at " << distance << " meters!" << endl;
      if (ThisNode->IsAMaliciousNode(neighIP)){ // The neighbor is already malicious?
          cout << m_nodeIP << " : " << timeNow 
               << " FlySafePacketSink - Message received from suspicious node " << neighIP << " - Starting analysis!" << endl;
          PrintMyNeighborList();
          PrintMySupiciousList();
          
          if (ThisNode->IsABlockedNode(neighIP)){ // The malicious neighbor is blocked?
            cout << m_nodeIP << " : " << timeNow 
                 << " FlySafePacketSink - Message received from blocked node " << neighIP << " - Ignored!" << endl;
            maliciousList = GetMaliciousNeighborList();
            m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
            goto ignore_blocked_node; // Escape analysis of blocked node messages
            } 
          else if (distance > 115) { // The malicious neighbor repeat a false location information?
            ThisNode->IncreaseMaliciousNodeRecurrence(neighIP, m_nodeIP);
            cout << m_nodeIP << " : " << timeNow 
                 << " FlySafePacketSink - Malicious node " << neighIP << " recurrence is "
                 << (int)ThisNode->GetMaliciousNodeRecurrence(neighIP) << endl;
            
            if (ThisNode->GetMaliciousNodeRecurrence(neighIP) == 3){ // Is the 3rd recurrence?
                cout << m_nodeIP << " : " << timeNow 
                     << " FlySafePacketSink - Node " << neighIP << " blocked!" << endl;
                ThisNode->SetMaliciousNodeState(neighIP, 1); // set blocked
                ThisNode->UnregisterNeighbor(neighIP);
                NotifyNeighbors(neighIP, position, 1, 5); // Nofity about blocked neighbor
                maliciousList = GetMaliciousNeighborList();
                m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
                PrintMyNeighborList();
                PrintMySupiciousList();
                goto ignore_blocked_node; // Escape analysis of blocked node messages
            } 
            else { // Still less than 3 recurrrences
                cout << m_nodeIP << " : " << timeNow 
                     << " FlySafePacketSink - Keep node " << neighIP << " as suspect!" << endl;
                NotifyNeighbors(neighIP,position, 1, 4); // Nofity about suspicious neighbor
                // Ordinary operation - switch
            }
          } 
          else { // Malicious node sent a true location
            cout << m_nodeIP << " : " << timeNow 
                   << " FlySafePacketSink - Received from malicious node " << neighIP << " a true location!" << endl;
            ThisNode->DecreaseMaliciousNodeRecurrence(neighIP, m_nodeIP);
            cout << m_nodeIP << " : " << timeNow 
                   << " FlySafePacketSink - Decreased malicious node " << neighIP << " recurrence!" << endl;
            if (ThisNode->GetMaliciousNodeRecurrence(neighIP) == 0){ // Nodes became honest
              PrintMyNeighborList();
              PrintMySupiciousList();
              ThisNode->UnregisterMaliciousNode(neighIP);
              cout << m_nodeIP << " : " << timeNow 
                   << " FlySafePacketSink - Removed node " << neighIP << " from SL!" << endl;
              ThisNode->SetNeighborNodeState(neighIP, 0); // Set node as ordinary
              cout << m_nodeIP << " : " << timeNow 
                   << " FlySafePacketSink - Turned node " << neighIP << " honest!" << endl;
              NotifyNeighbors(neighIP, position, 0, 6); // Nofity about Suspicious reduction to honest
              PrintMySupiciousList();
              PrintMyNeighborList();
              }
            else{
              NotifyNeighbors(neighIP, position, 1, 6); // Nofity about Suspicious reduction - Still suspect
              cout << m_nodeIP << " : " << timeNow 
                   << " FlySafePacketSink - Keep node " << neighIP << " as suspect after a true location received!" << endl;
              // Ordinary operation - switch
            }
            }
              // Ordinary operation - switch
          }
      else if (distance > 115) { // Honest neighbor send a false location
          if(!ThisNode->IsAlreadyNeighbor(neighIP)) { // Register node in NL
            ThisNode->RegisterNeighbor(neighIP, position, distance, 0, 3, 1, 0);
            cout << m_nodeIP << " : " << timeNow 
               << " FlySafePacketSink - Register node " << neighIP << " as a neighbor!" << endl; 
            suspiciousRegistered = true;
          }
          cout << m_nodeIP << " : " << timeNow 
               << " FlySafePacketSink - Turn node " << neighIP << " suspicious!" << endl;
          ThisNode->RegisterMaliciousNode(neighIP, m_nodeIP); // Insert node in SL
          ThisNode->SetNeighborNodeState(neighIP, 1); // Set node as suspect
          PrintMyNeighborList();
          NotifyNeighbors(neighIP, position, 1, 4); // Notify neighbors
          // Ordinary operation - switch
      } 
      else { // Honest neighbor sent a true location - Ordinary operation - switch
          cout << m_nodeIP << " : " << timeNow 
                     << " FlySafePacketSink - Message received from an honest node " << neighIP << "!" << endl;
      }

      PrintMyNeighborList();
      PrintMySupiciousList();

      // Decrease the number of neighbors in NL due to a previous register during malicious nodes analsys 
      if (suspiciousRegistered && nNeigh > 0){
        nNeigh -= 1;
      }

      switch (receivedTag.GetSimpleValue()) {
      case 0: // Broadcast received (searching neighbor nodes)
              // We consider broadcast when NL = 0. Hence, when we receive such message,
              // we disregard neighbors NL
        {
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Broadcast received from " 
               << neighIP << " at position x: " << position.x << " y: " << position.y << " z: " << position.z 
               << " - " << receivedTag.GetNNeighbors() << " neighbor(s) - " 
               << " At " << distance << " meters and sent at " << receivedTag.GetMessageTime() << "s" << std::endl;
          
          if((int)ThisNode->GetState() == 1){ // Node will be malcious?
            if (timeNow >= m_maliciousTime){ // Time to become malicious
              //cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Turn to malicious operation!" << endl;
              if (!m_maliciousRegister){
                cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Turn to malicious operation!" << endl;
                m_maliciousRegister = true;
              }
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Real position is " 
                   << position.x << ", " << position.y << ", " << position.z << endl;
              position = GenerateFalseLocation(); // Generate a false location to disseminate
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - False position is " 
                   << position.x << ", " << position.y << ", " << position.z << endl;
            }
          }

          SendMessage(neighIPPort,"hello!",1, (uint32_t) nNeigh, nodePosition, nodeInfosVectorTag); // Sent identification
          
          neighListFull = GetNeighborIpListFull();
          m_txTrace(timeNow, m_nodeIP,neighIP,1,"Identification", position, neighListFull); // Callback for id message sent

          // Update my neighbor list with new neighbor broadcasted information 
          if (suspiciousRegistered){ // Registered in malicious nodes analysis
            suspiciousRegistered = false;
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          else if (ThisNode->IsAlreadyNeighbor(neighIP)) { // Check if neighbor node is in neighbors list
              
              cout << m_nodeIP << " : " << timeNow << " " << neighIP << " is already my neighbor!" << std::endl;
              cout << m_nodeIP << " : " << timeNow << " Updated " << neighIP <<  " position!" << std::endl;
              
              ThisNode->UpdateNeighbor(neighIP, position, distance, neighAttitude, 3, 1);  
          }
          else { // Put neighbor node in my neighbors list
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                   << " in my neighbors list" << std::endl;
              ThisNode->RegisterNeighbor(neighIP, position, distance, 0, 3, 1, 0);    
          }
          
          if(numberNNeighbors != 0){
            UpdateMyNeighborList(neighInfosVectorTag);
          }

          neighListFull = GetNeighborIpListFull();
          m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 0, 
                      "Hello", neighListFull, receivedTag.GetMessageTime());
          maliciousList = GetMaliciousNeighborList(); 
          m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);   
          PrintMyNeighborList();
        }
        break;
      case 1: // Identification message received
              // This message carries neighbor nodes NL
        {
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Identification received from "
              << neighIP << " at position x: " << position.x << " y: " << position.y << " z: " << position.z
              << " - It has " << nNeigh << " neighbor(s)" 
              << " - at " << distance << " meters and sent at " << receivedTag.GetMessageTime() << "s" << std::endl;

          if (suspiciousRegistered){ // Registered in malicious nodes analysis
            suspiciousRegistered = false;
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          else if (ThisNode->IsAlreadyNeighbor(neighIP)){
            ThisNode->UpdateNeighbor(neighIP,position, distance, neighAttitude, 3, 1);
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Updated " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          else {
            ThisNode->RegisterNeighbor(neighIP,position,distance,neighAttitude,3, 1, 0);
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                << " in my neighbors list" << std::endl;
          }

          if(numberNNeighbors != 0){
            UpdateMyNeighborList(neighInfosVectorTag);
          }

          neighListFull = GetNeighborIpListFull();
          m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 1, "Identification", neighListFull,
              receivedTag.GetMessageTime());
          maliciousList = GetMaliciousNeighborList();
          m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
          PrintMyNeighborList();     
        }        
        break;

      case 2: // Trap message received - Update neighbor list with neighbor node information
        {
          
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Trap message received from " 
              << neighIP << " new position x: " << position.x << " y: " << position.y << " z: " << position.z 
              << " at " << distance << " meters and sent at " << receivedTag.GetMessageTime() << "s" << std::endl;
          
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Neighborhood before update NL with this trap message!" << endl;
          PrintMyNeighborList(); 

          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - NL received with this trap message from " << neighIP << endl;
          PrintNeighborList(neighInfosVectorTag);
          
          if (suspiciousRegistered){ // Registered in malicious nodes analysis
            suspiciousRegistered = false;
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          else if (!ThisNode->IsAlreadyNeighbor(neighIP)){
            ThisNode->RegisterNeighbor(neighIP,position,distance,neighAttitude,3,1, 0);
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          else {
            ThisNode->UpdateNeighbor(neighIP,position, distance, neighAttitude, 3, 1);
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Updated " << neighIP 
                 << " location in my neighbors list" << std::endl; 
          }

          if(numberNNeighbors != 0){
            UpdateMyNeighborList(neighInfosVectorTag);
          }

          neighListFull = GetNeighborIpListFull();
          m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 2, "Trap", neighListFull,
              receivedTag.GetMessageTime());
          maliciousList = GetMaliciousNeighborList();
          m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
          PrintMyNeighborList();                
        }
        break;

      case 3: // Special identification received (Identify nodes over 1 hop and up to 80 m)
              // Actions are the same when a node receives a broadcast message,
              // but we avoid to start another neighbor discovery  
        {
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Special identification received from " 
                << neighIP << " at position x: " << position.x << " y: " << position.y << " z: " << position.z 
                << " - " << receivedTag.GetNNeighbors() << " neighbor(s) - " 
                << " At " << distance << " meters and sent at " << receivedTag.GetMessageTime() << "s" << std::endl;

          if((int)ThisNode->GetState() == 1){ // Node will be malcious?
            if (timeNow >= m_maliciousTime){ // Time to becom malicious
              if (!m_maliciousRegister){
                cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Turn to malicious operation!" << endl;
                m_maliciousRegister = true;
              }  
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Real position is " 
                   << position.x << ", " << position.y << ", " << position.z << endl;
              position = GenerateFalseLocation(); // Generate a false location to disseminate
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - False position is " 
                   << position.x << ", " << position.y << ", " << position.z << endl;
            }
          }

          SendMessage(neighIPPort,"hello!",1, (uint32_t) nNeigh, nodePosition, nodeInfosVectorTag); // Sent identification

          if (suspiciousRegistered){ // Registered in malicious nodes analysis
            suspiciousRegistered = false;
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                 << " in my neighbors list" << std::endl;
          }
          // Update my neighbor list with new neighbor broadcasted information 
          else if (ThisNode->IsAlreadyNeighbor(neighIP)) { // Check if neighbor node is in neighbors list
              
              cout << m_nodeIP << " : " << timeNow << " " << neighIP << " is already my neighbor!" << std::endl;
              cout << m_nodeIP << " : " << timeNow << " Updated " << neighIP <<  " position!" << std::endl;
              
              ThisNode->UpdateNeighbor(neighIP, position, distance, neighAttitude, 3, 1); 
          }
          else { // Put neighbor node in my neighbors list
              cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Registered " << neighIP 
                    << " in my neighbors list" << std::endl;
              ThisNode->RegisterNeighbor(neighIP, position, distance, 0, 3, 1, 0);    
          }
          
          if(numberNNeighbors != 0){
            UpdateMyNeighborList(neighInfosVectorTag);
          }

          neighListFull = GetNeighborIpListFull();
          m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 3, "Special Identification", 
              neighListFull, receivedTag.GetMessageTime());
          maliciousList = GetMaliciousNeighborList();
          m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
          PrintMyNeighborList();
        }
        break;
      
      case 4: // Message about a suspect neighbor
        {
        cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Received a message from " << neighIP 
             << " about a suspect node (Tag 4): " <<  neighInfosVectorTag[0].ip << std::endl;
        PrintNeighborList(neighInfosVectorTag);
        PrintMyNeighborList();
        PrintMySupiciousList();
        if (ThisNode->IsAMaliciousNode(neighInfosVectorTag[0].ip)){
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Increase malicious node " << neighInfosVectorTag[0].ip << " recurrence (Tag 4)!" << std::endl;
          ThisNode->IncreaseMaliciousNodeRecurrence(neighInfosVectorTag[0].ip, neighIP);
          if (ThisNode->GetMaliciousNodeRecurrence(neighInfosVectorTag[0].ip) == 3){
            ThisNode->SetMaliciousNodeState(neighInfosVectorTag[0].ip,1); // Block a suspect node in SL
            ThisNode->UnregisterNeighbor(neighInfosVectorTag[0].ip); // Remove blocked node from NL
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Remove and block a malicious node " << neighInfosVectorTag[0].ip << " (Tag 4)!" << std::endl;
          }
        }
        else{ // Node not malicious yet!!!
          if (ThisNode->IsAlreadyNeighbor(neighInfosVectorTag[0].ip)){
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Set node " << neighInfosVectorTag[0].ip << " as suspect (Tag 4)!" << std::endl;
            ThisNode->SetNeighborNodeState(neighInfosVectorTag[0].ip,1); // Set node as malicious in NL
          }
          else{
            cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Register suspect node " << neighInfosVectorTag[0].ip << " in NL (Tag 4)!" << std::endl;
            position.x = neighInfosVectorTag[0].x;
            position.y = neighInfosVectorTag[0].y;
            position.z = neighInfosVectorTag[0].z;
            distance = CalculateNodesDistance(nodePosition, position); // Calculate distance between nodes
            ThisNode->RegisterNeighbor(neighInfosVectorTag[0].ip, position, distance, 0, 3, neighInfosVectorTag[0].hop +1, 1); // Register node as malicious
          }
          ThisNode->RegisterMaliciousNode(neighInfosVectorTag[0].ip, m_nodeIP); // Register a malicious node in SL
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Set node " << neighInfosVectorTag[0].ip << " as malicious in SL (Tag 4)!" << std::endl;
        }

        neighListFull = GetNeighborIpListFull();
        m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 4, "Suspect neighbor", 
              neighListFull, receivedTag.GetMessageTime());
        maliciousList = GetMaliciousNeighborList();
        m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
        PrintMyNeighborList();
        PrintMySupiciousList();
        }
        break;

      case 5: // Message about a blocked neighbor (Nov 09, 23)
        {
        cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Received a message from " << neighIP 
             << " about a blocked node (Tag 5): " <<  neighInfosVectorTag[0].ip << std::endl;
        PrintNeighborList(neighInfosVectorTag);
        PrintMyNeighborList();
        PrintMySupiciousList();
        if (ThisNode->IsAlreadyNeighbor(neighInfosVectorTag[0].ip)){ // Remove blocked node from NL
          ThisNode->UnregisterNeighbor(neighInfosVectorTag[0].ip);
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Removed blocked node " << neighInfosVectorTag[0].ip << " from NL (Tag 5)!" << std::endl;
        }
        if (!ThisNode->IsAMaliciousNode(neighInfosVectorTag[0].ip)){ // Register malicious node in SL
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Register blocked node " << neighInfosVectorTag[0].ip << " in SL (Tag 5)!" << std::endl;
          ThisNode->RegisterMaliciousNode(neighInfosVectorTag[0].ip, neighIP);
          ThisNode->SetMaliciousNodeState(neighInfosVectorTag[0].ip,1); // Block a malicious node in SL
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Blocked malicious node " << neighInfosVectorTag[0].ip << " in SL (Tag 5)!\n" << std::endl;
        } 
        else {
          ThisNode->IncreaseMaliciousNodeRecurrence(neighInfosVectorTag[0].ip, neighIP);
          ThisNode->SetMaliciousNodeState(neighInfosVectorTag[0].ip,1); // Block a malicious node in SL
          cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Blocked malicious node " << neighInfosVectorTag[0].ip << " in SL (Tag 5)!\n" << std::endl;
        }

        neighListFull = GetNeighborIpListFull();
        m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 5, "Blocked neighbor", 
              neighListFull, receivedTag.GetMessageTime());
        maliciousList = GetMaliciousNeighborList();
        m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
        PrintMyNeighborList();
        PrintMySupiciousList();
        }
        break;

      case 6: // Message about reducing suspect level about a neighbor node (Nov 20, 23)
              // Decreased neighbor recurrence after receiving a true location information
        {
        cout << m_nodeIP << " : " << timeNow 
             << " FlySafePacketSink - Received a notification from " << neighIP 
             << " about reducing suspect level of node " << neighInfosVectorTag[0].ip << " (Tag 6)!" << endl;
        PrintMyNeighborList();
        PrintMySupiciousList();
        if (ThisNode->IsAMaliciousNode(neighInfosVectorTag[0].ip)){
          ThisNode->DecreaseMaliciousNodeRecurrence(neighInfosVectorTag[0].ip, neighIP);
          if (ThisNode->GetMaliciousNodeRecurrence(neighInfosVectorTag[0].ip) == 0){ // Nodes became honest
              ThisNode->UnregisterMaliciousNode(neighInfosVectorTag[0].ip);
              cout << m_nodeIP << " : " << timeNow 
                  << " FlySafePacketSink - Removed node " << neighInfosVectorTag[0].ip << " from SL!" << endl;
              ThisNode->SetNeighborNodeState(neighInfosVectorTag[0].ip, 0); // Set node as ordinary
              cout << m_nodeIP << " : " << timeNow 
                  << " FlySafePacketSink - Turned node " << neighInfosVectorTag[0].ip << " honest!" << endl; 
            }           
          }
        PrintMySupiciousList();
        PrintMyNeighborList(); 

        neighListFull = GetNeighborIpListFull();
        m_sinkTrace(timeNow, nodePosition, m_nodeIP, neighIP, 6, "Suspection reduction", 
              neighListFull, receivedTag.GetMessageTime());
        maliciousList = GetMaliciousNeighborList();
        m_sinkMaliciousTrace(timeNow, m_nodeIP, maliciousList);
        }
        break;

      default: // Do nothing
        break;
      }
    }

    // In case of blocking node, escape swicth message analysis
    ignore_blocked_node:

    socket->GetSockName(localAddress);

    m_rxTrace(packet, neighAdd);
    m_rxTraceWithAddresses(packet, neighAdd, localAddress);
  }
}

void FlySafePacketSink::ManipulatePeerClose(Ptr<Socket> socket) {
  cout << "FlySafe - ManipulatePeerClose" << endl;
  NS_LOG_FUNCTION(this << socket);
}

void FlySafePacketSink::ManipulatePeerError(Ptr<Socket> socket) {
  cout << "FlySafe - ManipulatePeerError" << endl;
  NS_LOG_FUNCTION(this << socket);
}

void FlySafePacketSink::ManipulateAccept(Ptr<Socket> s, const Address &neighAdd) {
  NS_LOG_FUNCTION(this << s << neighAdd);
  m_socketList.push_back(s);
}


/**
 * @brief Send a message to a neighbor node
 * @date 2022
 * 
 * @param addressTo Neighbor node address (IPv4 + port)
 * @param message Message (string)
 * @param tagValue Tag value (0, 1, 2, 3, 4 or 5)
 * @param nNeigbors Number of neighbor nodes from the source node
 * @param nodePosition Source node position
 */
void FlySafePacketSink::SendMessage(Address addressTo, string message,
                                   uint8_t tagValue, u_int32_t nNeigbors, Vector nodePosition,
                                   std::vector<ns3::MyTag::NeighInfos> nodeInfos) {

  double timeNow;

  Ipv4Address destinyIP = InetSocketAddress::ConvertFrom(addressTo).GetIpv4();

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

  cout << m_nodeIP << " : " << timeNow << " FlySafePacketSink - Sent Identification to "
      << destinyIP << " from position x: " << nodePosition.x << " y: " << nodePosition.y << " z: " << nodePosition.z 
      << " - " << tagToSend.GetNNeighbors() << " neighbor(s)" << std::endl;
  
  PrintMyNeighborList();

  packet->AddPacketTag(tagToSend);
  socket->Send(packet);
  socket->Close();
}

/**
 * @brief Get node NIC where application is installed
 * @date 12082022
 * 
 * @return Interface address (IPv4 + port)
 */
Address FlySafePacketSink::GetNodeIpAddress() {
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
Vector FlySafePacketSink::GetNodeActualPosition()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_sendEvent.IsExpired ());

  Ptr<Node> ThisNode = this->GetNode();
  Ptr<MobilityModel> position = ThisNode->GetObject<MobilityModel> ();   // Check node current position - 26Sep2022
  NS_ASSERT (position != 0);

  return(position->GetPosition ());
}

/**
 * @brief Print a node neighbors list
 * @date 26Sep2022
 */

void FlySafePacketSink::PrintMyNeighborList() {
  Vector position;
  std::vector<ns3::Ipv4Address> neighborList;

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();

  cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
       << " FlySafePacketSink - My neighbors are: " 
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
 * @brief Print a node suspicious list
 * @date Oct 02, 2023
 */

void FlySafePacketSink::PrintMySupiciousList() {
  std::vector<ns3::Ipv4Address> suspiciousList;
  std::vector<ns3::Ipv4Address> notifiers;

  Ptr<Node> ThisNode = this->GetNode();
  suspiciousList = ThisNode->GetMaliciousNodeIpList();

  cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
       << " FlySafePacketSink - My suspicious neighbors are: " 
       << (int)ThisNode->GetNMaliciousNodes() << endl;

  for (uint8_t i = 0; i < suspiciousList.size(); i++) {
    notifiers = ThisNode->GetMaliciousNodesIPNotifiers(suspiciousList[i]);
    cout << suspiciousList[i] 
         << " State: " << (int)ThisNode->GetMaliciousNodeState(suspiciousList[i])
         << " Recurrence: " << (int)ThisNode->GetMaliciousNodeRecurrence(suspiciousList[i])
         << " Notifiers: " << convertIPVectorToString(notifiers) << endl;
  }
  cout << "\n" << endl;
}


/**
 * @brief Update node NL
 * 
 * @param neighInfos neighbors infomaation
 */
void FlySafePacketSink::UpdateMyNeighborList(std::vector<ns3::MyTag::NeighInfos> neighInfos){
  Ptr<Node> ThisNode = this->GetNode();
  Vector nodePosition;
  Vector neighPosition;
  double distance, value;
  uint8_t neighAttitude;
  uint8_t hop;
  //uint8_t state;

  nodePosition = GetNodeActualPosition();

  for(auto n :neighInfos){
    if(n.ip != m_nodeIP || ThisNode->IsABlockedNode(n.ip)){ // Avoid register in NL the node itself or a blocked node
      
      neighPosition.x = n.x;
      neighPosition.y = n.y;
      neighPosition.z = n.z;
      hop = n.hop;
      //state = n.state;

      value = CalculateDistance(nodePosition, neighPosition);
      distance = std::ceil(value * 100.0) / 100.0; // 2 decimal cases
      
      // Neighbors from neighbors are registered with quality 1 to
      // reduce their permance in the NL
      
      if(ThisNode->IsAlreadyNeighbor(n.ip)){
        // Update only if positions are diferents
        if(isPositionChanged(ThisNode->GetNeighborPosition(n.ip), neighPosition)){
          // check attitude
          neighAttitude = CheckNeighAttitude(distance,ThisNode->GetNeighborDistance(n.ip));
          // update neighbor list
          ThisNode->UpdateNeighbor(n.ip, neighPosition, distance, neighAttitude,1, 
                                   std::min((hop + 1), (int)ThisNode->GetNeighborHop(n.ip)));
          std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
            << " FlySafePacketSink - Updated neighbor " << n.ip 
            << " infomation. Choose hop " << (int)std::min(hop + 1, (int)ThisNode->GetNeighborHop(n.ip)) 
            << " from new one " << (int)hop + 1 << " and registered " 
            << (int)ThisNode->GetNeighborHop(n.ip) << std::endl; 
        }
        else{ // Neighbor node is stopped
          ThisNode->SetNeighborHop(n.ip, std::min((hop + 1), (int)ThisNode->GetNeighborHop(n.ip)));
          std::cout << m_nodeIP << " : " << Simulator::Now().GetSeconds() 
            << " FlySafePacketSink - Updated neighbor " << n.ip 
            << " hop to " << (int)std::min(hop + 1, (int)ThisNode->GetNeighborHop(n.ip)) 
            << " from new one " << (int)hop + 1 << " and registered " 
            << (int)ThisNode->GetNeighborHop(n.ip) << std::endl;          
        }
      }
      else {
        // register new node in the list with the received hop plus 1
        ThisNode->RegisterNeighbor(n.ip, neighPosition, distance, 0, 1, hop + 1, 0);
      }
    }
  }
}


/**
 * @brief Check neighbor node attitude (0 - keep, 1 - inbound, 2 - outbound)
 * @date Feb 27, 2023
 * 
 * @param newDistance Actual new distance from neighbor node
 * @param oldDistance Previous saved distance
 * @return uint8_t Neighbor node attitude
 */

uint8_t FlySafePacketSink::CheckNeighAttitude(double newDistance, double oldDistance){
  uint8_t neighAttitude = 0; // Store the new neighbor node attitude

  if (newDistance == oldDistance) { // Check for neighbor node attitude
    neighAttitude = 0; // keep distance
  }
  else if (newDistance < oldDistance) {
    neighAttitude = 1; // inbound
  }
  else {
    neighAttitude = 2; // outbound        
  }

  return neighAttitude;
}

/**
 * @brief Create a vector from node neigbor list
 * @date Feb 22, 2023
 * 
 * @param neighborList Vector with neighbor list Ipv4 Adress
 */
std::vector<FlySafePacketSink::NeighInfos> FlySafePacketSink::GetNeighborListVector(){
  vector<Ipv4Address> neighborList;
  std::vector<FlySafePacketSink::NeighInfos> neighborListVector;
  Vector position;
  FlySafePacketSink::NeighInfos node;

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
 * @brief Put neighbors information in a string
 * @date Mar 28, 2023
 * 
 * @return ostringstream neighbor nodes information string
 */
ostringstream FlySafePacketSink::neighListToString() { 
  ostringstream neighString;
  vector<Ipv4Address> neighborList;
  Vector position;
  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList();

  neighString << (int)neighborList.size();

  for (uint8_t i = 0; i < neighborList.size(); i++) {
    position = ThisNode->GetNeighborPosition(neighborList[i]);
    neighString << "\t" << neighborList[i] 
                << "," << position.x << "," << position.y << "," << position.z
                << "," << ThisNode->GetNeighborDistance(neighborList[i])
                << "," << (int)ThisNode->GetNeighborAttitude(neighborList[i])
                << "," << (int)ThisNode->GetNeighborQuality(neighborList[i])
                << "," << (int)ThisNode->GetNeighborHop(neighborList[i])
                << "," << (int)ThisNode->GetNeighborNodeState(neighborList[i]);
  }
  neighString << endl;  
  return neighString;
}

/**
 * @brief Get the Neighbor Ip List Full object
 * @date Apr 7, 2023
 * 
 * @return vector<ns3::MyTag::NeighborFull> 
 */
vector<ns3::MyTag::NeighborFull> FlySafePacketSink::GetNeighborIpListFull() { 
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
vector<ns3::MyTag::MaliciousNode> FlySafePacketSink::GetMaliciousNeighborList() { 
  vector<Ipv4Address> maliciousIPList;
  //vector<Ipv4Address> notifiersIP;
  vector<ns3::MyTag::MaliciousNode> maliciousListFull;
  ns3::MyTag::MaliciousNode maliciousInfo;
  Vector position;

  Ptr<Node> ThisNode = this->GetNode();
  maliciousIPList = ThisNode->GetMaliciousNodeIpList();

  for (uint8_t i = 0; i < maliciousIPList.size(); i++) {
    maliciousInfo.ip = maliciousIPList[i];
    maliciousInfo.state = ThisNode->GetMaliciousNodeState(maliciousIPList[i]);
    maliciousInfo.recurrence = ThisNode->GetMaliciousNodeRecurrence(maliciousIPList[i]);
    //notifiersIP = ThisNode->GetMaliciousNodesIPNotifiers(maliciousIPList[i]);
    maliciousInfo.notifyIP = ThisNode->GetMaliciousNodesIPNotifiers(maliciousIPList[i]);
    maliciousListFull.push_back(maliciousInfo);
  }
  return maliciousListFull;
}



/**
 * @brief Notify neighbor nodes (one hop away and non malicious) about a malicious node
 * 
 * @param maliciousIP - malicious node IP address
 * @param tagValue - 0 (suspect) or 1 (blocked)
 */
void FlySafePacketSink::NotifyNeighbors(Ipv4Address maliciousIP, Vector position, uint8_t state, uint8_t tagValue){
  
  vector<Ipv4Address> neighborList;
  double timeNow;
  string textLog;
  string message;

  Vector nPosition = GetNodeActualPosition();

  Ptr<Node> ThisNode = this->GetNode();
  neighborList = ThisNode->GetNeighborIpList(); // get node neighbors list

  MyTag tag;
  std::vector<ns3::MyTag::NeighInfos> neighInfosVectorTag; 
  std::vector<ns3::MyTag::NeighborFull> neighListFull;

  ns3::MyTag::NeighInfos nodeInfo;

  // Insert malicious node information in a tag
  nodeInfo.ip = maliciousIP;
  nodeInfo.x = position.x;
  nodeInfo.y = position.y;
  nodeInfo.z = position.z; 
  nodeInfo.hop = 1;
  nodeInfo.state = state;
  neighInfosVectorTag.push_back(nodeInfo);
  tag.SetSimpleValue(tagValue);
  tag.SetNNeighbors(1); 
  tag.SetPosition(nPosition); // Add nodes position to tag
  tag.SetNeighInfosVector(neighInfosVectorTag);

  timeNow = Simulator::Now().GetSeconds();
  
  tag.SetMessageTime(timeNow);
  
  neighListFull = GetNeighborIpListFull();

  switch ((int)tagValue) {
  case 4: // Suspicious neighbor notification
    textLog = "suspicious";
    message = "Suspicious";
    break;
  case 5: // Blocked neighbor notification
    textLog = "blocked";
    message = "Blocked";
    break;
  case 6: // Suspicious reduction notification
    textLog = "suspicious reduction on";
    message = "Suspicious Reduction";
    break;
  }



  for (uint8_t i = 0; i < neighborList.size(); i++) { 

    // Notify one hop neighbors only and not blocked 
    if((int)ThisNode->GetNeighborHop(neighborList[i]) == 1 && neighborList[i] != maliciousIP){      
      cout << m_nodeIP << " : " << timeNow 
           << " FlySafePacketSink - Sent notification about " << textLog << " node "
           << maliciousIP << " to "<< neighborList[i] << " - Tag " << (int)tagValue
           << " - I have " << (int)ThisNode->GetNMaliciousNodes() << " neighbors" << std::endl; 

      Address DestinyAddress(InetSocketAddress(neighborList[i], 9));
      Ptr<Socket> socket = Socket::CreateSocket(GetNode(), m_tid);

      if (socket->Bind() == -1) {
        NS_FATAL_ERROR("Failed to bind socket");
      }

      socket->Connect(DestinyAddress);
      Ptr<Packet> packet;
      packet = Create<Packet>(reinterpret_cast<const uint8_t *>(message.c_str()), message.size()); // Create a packet to send the message 
      packet->AddPacketTag(tag); // add the tag to packet
      socket->Send(packet); // Send packet
      socket->Close();  // Close socket
      m_txTrace(timeNow, m_nodeIP,neighborList[i],(int)tagValue,message.c_str(), position, neighListFull); // Callback for id message sent
    }
  } 
// End NotifyNeighbors
}

} // namespace ns3

/* ------------------------------------------------------------------------
 *  End of FlysafePacketSink Class
 * ------------------------------------------------------------------------
 */