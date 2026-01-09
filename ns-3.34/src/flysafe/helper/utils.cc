#include "utils.h"
#include "ns3/flysafe-statistics.h"
#include <time.h>

namespace ns3 {

/**
 * @brief Get the Start Time Of Simulation
 * 
 * @return string - simulation start time string
 */
string
GetTimeOfSimulationStart()
{
	time_t now = time(0);
    tm *ltm = localtime(&now);
    ostringstream convert;

    if (ltm->tm_mday < 10)
    	convert << "0";
    convert << ltm->tm_mday;

    if ((ltm->tm_mon+1) < 10)
       	convert << "0";
    convert << ltm->tm_mon + 1;

    convert << 1900 + ltm->tm_year << "_" ;

    if (ltm->tm_hour < 10)
    	convert << "0";
    convert << ltm->tm_hour;

    if (ltm->tm_min < 10)
    	convert << "0";
    convert << ltm->tm_min << endl<< endl;

	return convert.str();
}

/**
 * @brief Create a Sim Scenario File
 * 
 * @param fileName - File name
 * @param simulDate - Simulation time
 * @param dataToSave - Simulation data
 */
void
CreateSimScenarioFile (string fileName, string simulDate, string dataToSave)
{
  ofstream fileSimRec;
  fileSimRec.open (fileName.c_str ());
  fileSimRec << "**** FlySafe scenario configuration file ****" << endl << endl;
  fileSimRec << "Date: " << simulDate.substr (0, 8).c_str () << " - "
             << simulDate.substr (9, 2).c_str () << ":" << simulDate.substr (11, 2).c_str () << "hs"
             << endl
             << endl;

  fileSimRec << dataToSave.c_str ();

  // Close scenario simulation configuration file
  fileSimRec << "**** End of FlySafe scenario configuration file ****" << endl;
  fileSimRec.close ();
}

/**
 * @brief Check whether positions are diferent 
 * @date Mar 5, 2023
 * 
 * @param oldPosition - Vector with old position
 * @param newPosition - Vector with new position
 * @return true - Different positions
 * @return false - Same position
 */

/**
 * @brief Check whether node position is changed
 * 
 * @param oldPosition - Old position
 * @param newPosition - Actual position
 * @return true - Actual position diferent from the old one
 * @return false - Stopped node
 */
bool
isPositionChanged (Vector oldPosition, Vector newPosition)
{
  return (oldPosition.x != newPosition.x) || (oldPosition.y != newPosition.y) || (oldPosition.z != newPosition.z);
}

/**
 * @brief Calculate distance between two nodes
 * 
 * @date Jan2023
 * 
 * @param myPosition Vector with node position
 * @param neighPosition Vector with neighbor node position
 * @return double Distance
 */

double CalculateNodesDistance(Vector myPosition, Vector neighPosition) {
  double hDistance;
  hDistance = sqrt(pow(myPosition.x - neighPosition.x, 2) + pow(myPosition.y - neighPosition.y, 2) * 1.0);
  return sqrt(pow(hDistance, 2) + pow(myPosition.z - neighPosition.z, 2) * 1.0);
}

/**
 * @brief Print a received neighbor list recovred from a tag
 * @date Feb 26, 2023
 */

void PrintNeighborList(std::vector<ns3::MyTag::NeighInfos> neighInfos) {

  for(auto n :neighInfos){
    cout << n.ip << " : Position x: " << n.x << " y: " << n.y << " z: " << n.z << " hop: " << (int)n.hop << endl;
  }
  cout << "\n" << endl;
}


/**
 * @brief Print received information about a malicous node
 * @date Nov 02, 2023
 */

void PrintMaliciousNodeInfo(std::vector<ns3::MyTag::NeighInfos> neighInfos) {

  cout << "Information received about a malicious node:" << endl;
  for(auto n :neighInfos){
    cout << n.ip << " : Position x: " << n.x << " y: " << n.y << " z: " << n.z << " hop: " << (int)n.hop << endl;
  }
  cout << "\n" << endl;
}

/**
 * @brief Generate false location data
 * @date Oct 30, 2023
 * 
 * @return Vector - Vector with location coordinates (x, y, z)
 */
Vector 
GenerateFalseLocation()
{
  Vector falseLocation;
  
  std::default_random_engine rnd{std::random_device{}()};
  std::uniform_real_distribution<double> fX(0, 1500);
  std::uniform_real_distribution<double> fY(0, 1500);
  std::uniform_real_distribution<double> fZ(91, 91);
  
  falseLocation.x = fX(rnd);
  falseLocation.y = fY(rnd);
  falseLocation.z = fZ(rnd);

  return falseLocation;
}

/**
 * @brief Generate malicious nodes
 * @date Nov 15, 2023
 * 
 * @return vector - vector with malicious nodes
 */
/*std::vector<int> 
GenerateMaliciousNodes(int nNodes, int nMalicious) {
    std::vector<int> numbers;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, nNodes-1);
    int num;

    //cout << "Generating " << nMalicious << " malicious nodes:" << endl;
    for (int i = 0; i < nMalicious; i++) {
        num = dis(gen);
        while (std::find(numbers.begin(), numbers.end(), num) != numbers.end()) {
            num = dis(gen);
        }
        numbers.push_back(num);
        //cout << "Node: " << num << endl;
    }
    std::sort(numbers.begin(), numbers.end());
    return numbers;
}*/

/**
 * @author Vinicius - MiM
 * 
 * @brief Generate malicious nodes with K-Means algorithm
 * 
 * @date Oct 06, 2025
 * 
 * @param nNodes - Number of nodes in the simulation
 * @param nMalicious - Number of malicious nodes to be generated
 * 
 * @return vector - vector with malicious nodes
 */
/*std::vector<int> 
GenerateMaliciousNodes(NodeContainer nodes, int nMalicious) {
    if (nMalicious <= 0) {
        return {};
    }

    uint32_t nNodes = nodes.GetN();
    if ((uint32_t)nMalicious >= nNodes) {
        std::vector<int> all_nodes;
        for (uint32_t i = 0; i < nNodes; ++i) {
            all_nodes.push_back(i);
        }
        return all_nodes;
    }

    std::vector<Vector> positions;
    for (uint32_t i = 0; i < nNodes; ++i) {
        positions.push_back(nodes.Get(i)->GetObject<MobilityModel>()->GetPosition());
    }

    // 1. Inicializa centróides aleatoriamente
    std::vector<Vector> centroids;
    std::vector<int> initial_indices;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, nNodes - 1);

    while (centroids.size() < (uint32_t)nMalicious) {
        int idx = dis(gen);
        if (std::find(initial_indices.begin(), initial_indices.end(), idx) == initial_indices.end()) {
            initial_indices.push_back(idx);
            centroids.push_back(positions[idx]);
        }
    }

    std::vector<int> assignments(nNodes);
    bool changed = true;
    int max_iterations = 100;
    int iter = 0;

    while (changed && iter < max_iterations) {
        changed = false;

        // 2. Atribui cada nó ao centróide mais próximo
        for (uint32_t i = 0; i < nNodes; ++i) {
            double min_dist = std::numeric_limits<double>::max();
            int best_cluster = 0;
            for (int j = 0; j < nMalicious; ++j) {
                double dist = CalculateNodesDistance(positions[i], centroids[j]);
                if (dist < min_dist) {
                    min_dist = dist;
                    best_cluster = j;
                }
            }
            if (assignments[i] != best_cluster) {
                assignments[i] = best_cluster;
                changed = true;
            }
        }

        // 3. Recalcula os centróides
        std::vector<Vector> new_centroids(nMalicious, Vector(0, 0, 0));
        std::vector<int> counts(nMalicious, 0);
        for (uint32_t i = 0; i < nNodes; ++i) {
            new_centroids[assignments[i]].x += positions[i].x;
            new_centroids[assignments[i]].y += positions[i].y;
            new_centroids[assignments[i]].z += positions[i].z;
            counts[assignments[i]]++;
        }

        for (int j = 0; j < nMalicious; ++j) {
            if (counts[j] > 0) {
                centroids[j].x = new_centroids[j].x / counts[j];
                centroids[j].y = new_centroids[j].y / counts[j];
                centroids[j].z = new_centroids[j].z / counts[j];
            }
        }
        iter++;
    }

    // 4. Seleciona os nós mais próximos dos centróides finais
    std::vector<int> malicious_nodes;
    std::vector<bool> selected(nNodes, false);

    for (int j = 0; j < nMalicious; ++j) {
        double min_dist = std::numeric_limits<double>::max();
        int closest_node_idx = -1;
        
        for (uint32_t i = 0; i < nNodes; ++i) {
            if (!selected[i]) {
                double dist = CalculateNodesDistance(positions[i], centroids[j]);
                if (dist < min_dist) {
                    min_dist = dist;
                    closest_node_idx = i;
                }
            }
        }

        if (closest_node_idx != -1) {
            malicious_nodes.push_back(closest_node_idx);
            selected[closest_node_idx] = true;
        }
    }

    std::sort(malicious_nodes.begin(), malicious_nodes.end());
    return malicious_nodes;
}*/

/**
 * @author Vinicius - MiM
 * 
 * @brief Generate malicious nodes based on neighbor density with selection criteria.
 * @details This function selects nodes that have the highest number of potential neighbors.
 *          Selection criteria:
 *          1. Malicious nodes cannot be neighbors of each other.
 *          2. Primary sort key: Number of neighbors in `effectiveRange`.
 *          3. Tie-breaker 1: Number of neighbors in `effectiveRange * 2`.
 *          4. Tie-breaker 2: Node ID (smaller is better).
 * 
 * @date Oct 06, 2025
 * 
 * @param nodes - NodeContainer with all nodes in the simulation.
 * @param nMalicious - Number of malicious nodes to be generated.
 * 
 * @return vector - vector with the IDs of the most connected, non-neighboring nodes.
 */
std::vector<int> 
GenerateMaliciousNodes(NodeContainer nodes, int nMalicious) {
    if (nMalicious <= 0) {
        return {};
    }

    uint32_t nNodes = nodes.GetN();
    if ((uint32_t)nMalicious >= nNodes) {
        std::vector<int> all_nodes;
        for (uint32_t i = 0; i < nNodes; ++i) {
            all_nodes.push_back(i);
        }
        return all_nodes;
    }

    const double effectiveRange = 115.0;
    const double secondaryRange = effectiveRange * 2.0;

    std::vector<Vector> positions;
    for (uint32_t i = 0; i < nNodes; ++i) {
        positions.push_back(nodes.Get(i)->GetObject<MobilityModel>()->GetPosition());
    }

    // Struct to hold node info for sorting
    struct NodeInfo {
        int id;
        int primaryNeighbors;
        int secondaryNeighbors;
    };

    // Pre-compute neighbor counts for all nodes
    std::vector<NodeInfo> candidates;
    for (uint32_t i = 0; i < nNodes; ++i) {
        int primaryCount = 0;
        int secondaryCount = 0;
        for (uint32_t j = 0; j < nNodes; ++j) {
            if (i == j) continue;
            double distance = CalculateNodesDistance(positions[i], positions[j]);
            if (distance <= effectiveRange) {
                primaryCount++;
            }
            if (distance <= secondaryRange) {
                secondaryCount++;
            }
        }
        candidates.push_back({static_cast<int>(i), primaryCount, secondaryCount});
    }

    // Sort the candidate list based on tie-breaking criteria
    std::sort(candidates.begin(), candidates.end(), [](const NodeInfo& a, const NodeInfo& b) {
        if (a.primaryNeighbors != b.primaryNeighbors) {
            return a.primaryNeighbors > b.primaryNeighbors; // More primary neighbors first
        }
        if (a.secondaryNeighbors != b.secondaryNeighbors) {
            return a.secondaryNeighbors > b.secondaryNeighbors; // Tie-breaker with secondary neighbors
        }
        return a.id < b.id; // Final tie-breaker by ID
    });

    // Iterative selection to ensure malicious nodes are not neighbors
    std::vector<int> malicious_nodes;
    std::vector<bool> is_disqualified(nNodes, false);

    for (const auto& candidate : candidates) {
        if (malicious_nodes.size() >= (uint32_t)nMalicious) {
            break; 
        }

        if (is_disqualified[candidate.id]) {
            continue; // Node has already been disqualified for being a neighbor of an already chosen malicious node
        }

        // Select this candidate as a malicious node
        malicious_nodes.push_back(candidate.id);
        is_disqualified[candidate.id] = true;

        // Disqualify all of its neighbors from becoming malicious
        for (uint32_t i = 0; i < nNodes; ++i) {
            if (is_disqualified[i]) continue;
            double distance = CalculateNodesDistance(positions[candidate.id], positions[i]);
            if (distance <= effectiveRange) {
                is_disqualified[i] = true;
            }
        }
    }

    // Sort the final result by ID for consistency
    std::sort(malicious_nodes.begin(), malicious_nodes.end());
    
    return malicious_nodes;
}

/**
 * @brief Convert a vector with integers to a string separated by commas
 * 
 * @param vec - Int vector
 * @return std::string - String separated by commas
 */
std::string 
convertIntVectorToString(const std::vector<int>& vec) {
    std::stringstream ss;
    for (size_t i = 0; i < vec.size(); i++) {
        ss << vec[i];
        if (i != vec.size() - 1) {
            ss << ",";
        }
    }
    return ss.str();
}


/**
 * @brief Convert a vector with IPs to a string separated by commas
 * 
 * @date Nov 23, 2023
 * 
 * @param vec - IPv4 vector
 * @return std::string - String separated by commas
 */
std::string 
convertIPVectorToString(const std::vector<ns3::Ipv4Address>& vec) {
    std::stringstream ss;
    for (size_t i = 0; i < vec.size(); i++) {
        ss << vec[i];
        if (i != vec.size() - 1) {
            ss << ", ";
        }
    }
    return ss.str();
}

/**
 * @author Vinicius - MiM
 * 
 * @brief Execute a MiM attack by spoofing the packet with a false location
 * 
 * @note This function is called when the sniffer node is in the coverage area of the sender and receiver.
 * 
 * @param snifferNode - Pointer to the sniffer node
 * @param packet - Pointer to the captured packet
 * @param snifferIp - IP address of the sniffer node
 * @param senderIp - IP address of the sender node
 * @param receiverIp - IP address of the receiver node
 * @param originalTag - Tag containing the original position and other information
 * @param senderPosition - Position of the sender node
 */
void
ExecuteMiMAttack(Statistics* stats, Ptr<Node> snifferNode, Ptr<const Packet> packet, 
                Ipv4Address snifferIp, Ipv4Address senderIp, Ipv4Address receiverIp, 
                MyTag originalTag, Vector senderPosition, int msgTag, 
                vector<ns3::MyTag::NeighborFull> neighList, double messageTime) {

    // Copy the original packet to create a forged packet
    Ptr<Packet> forgedPacket = packet->Copy();

    // Remove the original headers from the forged packet
    WifiMacHeader wifiMacHeader;
    forgedPacket->RemoveHeader(wifiMacHeader);

    LlcSnapHeader llcSnapHeader;
    bool hasLlc = forgedPacket->PeekHeader(llcSnapHeader);
    if (hasLlc) {
        forgedPacket->RemoveHeader(llcSnapHeader);
    } else {
        llcSnapHeader.SetType(0x0800); // Default type for IPv4
    }

    Ipv4Header ipv4Header;
    forgedPacket->RemoveHeader(ipv4Header);
    
    UdpHeader udpHeader;
    forgedPacket->RemoveHeader(udpHeader);

    WifiMacTrailer trailer;
    forgedPacket->RemoveTrailer(trailer);

    // Generate false location
    Vector forgedPosition = GenerateFalseLocation();

    // Create a new tag with the forged position
    MyTag forgedTag = originalTag; 
    forgedTag.SetPosition(forgedPosition); 
    forgedPacket->ReplacePacketTag(forgedTag); 

    // Find the sniffer's wifinetdevice
    Ptr<WifiNetDevice> snifferDevice = nullptr;
    for (uint32_t i = 0; i < snifferNode->GetNDevices(); ++i) {
        Ptr<NetDevice> device = snifferNode->GetDevice(i);
        snifferDevice = DynamicCast<WifiNetDevice>(device);
        if (snifferDevice) {
            break;
        }
    }

    // Get the MAC layer of the sniffer device
    Ptr<AdhocWifiMac> mac = DynamicCast<AdhocWifiMac>(snifferDevice->GetMac());
    NS_ASSERT(mac != nullptr);

    // Set the forged packet's headers
    forgedPacket->AddHeader(udpHeader);
    forgedPacket->AddHeader(ipv4Header);
    forgedPacket->AddHeader(llcSnapHeader);

    // Set the forged MAC header
    WifiMacHeader forgedHdr;
    forgedHdr.SetType(WIFI_MAC_DATA);  
    forgedHdr.SetAddr1(wifiMacHeader.GetAddr1());
    forgedHdr.SetAddr2(wifiMacHeader.GetAddr2());
    forgedHdr.SetAddr3(wifiMacHeader.GetAddr3()); 
    forgedHdr.SetDsNotFrom();
    forgedHdr.SetDsNotTo();
    forgedHdr.SetNoRetry(); 

    // Enqueue the forged packet with the forged MAC header
    mac->GetTxop()->Queue(forgedPacket, forgedHdr);
    
    // Print the MiM attack information
    double timeNow = Simulator::Now().GetSeconds();
    cout << snifferIp << " : " << timeNow << " MiM - Spoofing packet to " << receiverIp 
            << ". Original Sender: " << senderIp << " - Real position: (" << senderPosition.x << ", " 
            << senderPosition.y << ", " << senderPosition.z << ") - " << "Fake position: (" 
            << forgedPosition.x << ", " << forgedPosition.y << ", " << forgedPosition.z << ")" << endl << endl;
    
    // Call the statistics callback with the information of the forged packet
    stats->MiMCallback("", timeNow, senderPosition, forgedPosition, snifferIp, 
                        senderIp, receiverIp, msgTag, neighList, messageTime);

}

/**
 * @author Vinicius - MiM
 * 
 * @brief Extracts the necessary information from the packet and calls the statistics callback. 
 *      If the sniffer node is in the coverage area of the sender and receiver, 
 *      it also executes a MiM attack by spoofing the packet with a false location.
 * 
 * @note This function is called when a packet is received by the sniffer. 
 * 
 * @param stats - Pointer to Statistics object
 * @param snifferNode - Pointer to the sniffer node
 * @param context - Context string
 * @param packet - Pointer to the received packet
 * @param channelFreqMhz - Frequency of the channel in MHz
 * @param txvector - WifiTxVector object containing transmission parameters
 * @param mpdu - MpduInfo object containing MPDU information
 * @param snr - SignalNoiseDbm object containing signal and noise information
 * @param staId - Station ID
 */
void 
ProcessSniffedPacket(Statistics* stats, Ptr<Node> snifferNode,
                       std::string context, Ptr<const Packet> packet,
                       uint16_t channelFreqMhz, WifiTxVector txvector,
                       MpduInfo mpdu, SignalNoiseDbm snr, uint16_t staId) {

    Ptr<Packet> snifferPacket = packet->Copy();

    // Extract the MAC header from the packet
    WifiMacHeader macHeader;
    if (snifferPacket->RemoveHeader(macHeader)) {
        
        // If the packet is a data packet, remove the LLC header
        if (macHeader.IsData()) {
            LlcSnapHeader llcHeader;
            snifferPacket->RemoveHeader(llcHeader);
        }

        // Extract the IPv4 header from the packet
        Ipv4Header ipv4Header;
        if (snifferPacket->PeekHeader(ipv4Header)) {

            Ipv4Address snifferIp = snifferNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
            Ipv4Address senderIp = ipv4Header.GetSource();
            Ipv4Address receiverIp = ipv4Header.GetDestination();

            // If the sniffer IP is the same as the sender or receiver, or the message is a broadcast, skip processing
            // if (senderIp == snifferIp || receiverIp == snifferIp || receiverIp == Ipv4Address("255.255.255.255")) {
            // If the sniffer IP is the same as the sender or receiver, skip processing
            if (senderIp == snifferIp || receiverIp == snifferIp) {
                return;
            }

            // Extract the tag from the packet
            MyTag originalTag;
            if (snifferPacket->PeekPacketTag(originalTag)) {

                double timeNow = Simulator::Now().GetSeconds();

                if (originalTag.GetSimpleValue() > 6) {
                    std::cout << snifferIp << " : " << timeNow << " Sniffer - Detected encrypted/invalid tag value (" << (int)originalTag.GetSimpleValue() << "). Skipping." << endl << endl;
                    return;
                }
                              
                Vector senderPosition = originalTag.GetPosition();
                int msgTag = originalTag.GetSimpleValue();
                double messageTime = originalTag.GetMessageTime();
                
                // Message content based on the message tag
                string messageContent;
                switch (msgTag) {
                    case 0: messageContent = "Search neighbors (Hello message)"; break;
                    case 1: messageContent = "Identification (Location message)"; break;
                    case 2: messageContent = "Update location (Trap message)"; break;
                    case 3: messageContent = "Special identification (Location message to neighbors beyond 1 hop and up to 80 meters away)"; break;
                    case 4: messageContent = "Suspect neighbor (FDI)"; break;
                    case 5: messageContent = "Blocked node"; break;
                    case 6: messageContent = "Suspicious reduction"; break;
                    default: messageContent = "Unknown"; break;
                }

                // Get information about neighbors from the tag
                vector<MyTag::NeighInfos> receivedNeighInfoList = originalTag.GetNeighInfosVector();
                vector<ns3::MyTag::NeighborFull> neighborListForStats;
                for (const auto& info : receivedNeighInfoList) {
                    MyTag::NeighborFull full_info;
                    full_info.ip = info.ip;
                    full_info.position.x = info.x;
                    full_info.position.y = info.y;
                    full_info.position.z = info.z;
                    full_info.hop = info.hop;
                    full_info.state = info.state;
                    full_info.distance = 0;
                    full_info.attitude = 0;
                    full_info.quality = 0;
                    
                    neighborListForStats.push_back(full_info);
                }

                // Print the captured information
                cout << snifferIp << " : " << timeNow << " Sniffer - Message " << msgTag << " : " << messageContent << " captured from " << senderIp 
                    << " at (" << senderPosition.x << ", " << senderPosition.y << ", " << senderPosition.z << ") to " << receiverIp;

                if (!neighborListForStats.empty())
                {
                    cout << " - The neighbors of " << senderIp << " are: " << neighborListForStats.size() << endl;
                    for (const auto& neighbor : neighborListForStats)
                    {
                        cout << neighbor.ip << " : Position x: " << neighbor.position.x << " y: " << neighbor.position.y 
                            << " z: " << neighbor.position.z << " hop: " << (int)neighbor.hop << endl;
                    }
                }
                else
                {
                    cout << endl;
                }
                cout << endl;

                // Call the statistics callback with the extracted information
                stats->SnifferCallback("", timeNow, senderPosition, snifferIp, senderIp, receiverIp, 
                                      msgTag, neighborListForStats, messageTime);

                // Checks if receiver is in the sniffer's coverage area
                /*if (snifferNode->IsAlreadyNeighbor(receiverIp) && snifferNode->GetNeighborHop(receiverIp) == 1)
                {
                    ExecuteMiMAttack(stats, snifferNode, packet, 
                                    snifferIp, senderIp, receiverIp, 
                                    originalTag, senderPosition,
                                    msgTag, neighborListForStats, messageTime);
                }*/

                // Try execute MiM attack with all captured packets
                ExecuteMiMAttack(stats, snifferNode, packet, 
                                    snifferIp, senderIp, receiverIp, 
                                    originalTag, senderPosition,
                                    msgTag, neighborListForStats, messageTime);
            } 
        }        
    }
}

/**
 * @author Vinicius - MiM
 * 
 * @brief Convert EVP_PKEY to PEM string
 * 
 * @note It is a auxiliary function used in GenerateAsymmetricKeys()
 * 
 * @param pkey - EVP_PKEY pointer
 * @param isPrivate - true for private key, false for public key
 * 
 * @return std::string - PEM formatted key string
 */
std::string pkeyToPem(EVP_PKEY *pkey, bool isPrivate) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Fail to create BIO");
    }

    if (isPrivate) {
        // Write the private key (unencrypted)
        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_free(bio);
            throw std::runtime_error("Fail to write private key to BIO");
        }
    } else {
        // Write the public key
        if (!PEM_write_bio_PUBKEY(bio, pkey)) {
            BIO_free(bio);
            throw std::runtime_error("Fail to write public key to BIO");
        }
    }

    char *data_ptr;
    long len = BIO_get_mem_data(bio, &data_ptr);
    std::string pem(data_ptr, len);
    BIO_free(bio);
    return pem;
}

/**
 * @author Vinicius - MiM
 * 
 * @brief Generate asymmetric keys for nodes in the simulation.
 * 
 * @param nNodes - Number of nodes in the simulation
 */
std::vector<std::pair<std::string, std::string>> 
GenerateAsymmetricKeys(uint32_t nNodes) {
    
    std::vector<std::pair<std::string, std::string>> keyList;

    for (uint32_t i = 0; i < nNodes; ++i) {
        EVP_PKEY *pkey = NULL;
        EVP_PKEY_CTX *ctx = NULL;
        
        try {
            // Create context for key generation
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (!ctx) {
                throw std::runtime_error("Failed to create PKEY context");
            }

            // Initialize key generation
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                throw std::runtime_error("Failed to initialize keygen");
            }

            // Set the curve (secp256r1 is P-256, an excellent standard curve)
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
                throw std::runtime_error("Failed to set curve NID");
            }

            // Generate the key pair
            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                throw std::runtime_error("Failed to generate key pair");
            }
            
            // Convert keys to PEM format (string)
            std::string private_pem = pkeyToPem(pkey, true);
            std::string public_pem = pkeyToPem(pkey, false);

            // Add to the list
            keyList.push_back(std::make_pair(private_pem, public_pem));

            // Cleanup
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

        } catch (const std::exception &e) {
            std::cerr << "Error generating key pair " << i << ": " << e.what() << std::endl;
            // Cleanup in case of error
            if (ctx) EVP_PKEY_CTX_free(ctx);
            if (pkey) EVP_PKEY_free(pkey);
            // Stop to avoid partial results
            return {}; // Return empty list in case of failure
        }
    }

    return keyList;
}

/**
 * @brief Plot a 2D file
 * 
 */
void Create2DPlotFile ()
{
  std::string fileNameWithNoExtension = "plot-2d";
  std::string graphicsFileName        = fileNameWithNoExtension + ".png";
  std::string plotFileName            = fileNameWithNoExtension + ".plt";
  std::string plotTitle               = "2-D Plot";
  std::string dataTitle               = "2-D Data";

  // Instantiate the plot and set its title.
  Gnuplot plot (graphicsFileName);
  plot.SetTitle (plotTitle);

  // Make the graphics file, which the plot file will create when it
  // is used with Gnuplot, be a PNG file.
  plot.SetTerminal ("png");

  // Set the labels for each axis.
  plot.SetLegend ("X Values", "Y Values");

  // Set the range for the x axis.
  plot.AppendExtra ("set xrange [-6:+6]");

  // Instantiate the dataset, set its title, and make the points be
  // plotted along with connecting lines.
  Gnuplot2dDataset dataset;
  dataset.SetTitle (dataTitle);
  dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);

  double x;
  double y;

  // Create the 2-D dataset.
  for (x = -5.0; x <= +5.0; x += 1.0)
    {
      // Calculate the 2-D curve
      // 
      //            2
      //     y  =  x   .
      //  
      y = x * x;

      // Add this point.
      dataset.Add (x, y);
    }

  // Add the dataset to the plot.
  plot.AddDataset (dataset);

  // Open the plot file.
  std::ofstream plotFile (plotFileName.c_str());

  // Write the plot file.
  plot.GenerateOutput (plotFile);

  // Close the plot file.
  plotFile.close ();
}
} // namespace ns3