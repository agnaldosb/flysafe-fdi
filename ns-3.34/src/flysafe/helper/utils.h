#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <list>
#include <random>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <utility>
#include "ns3/mobility-module.h"
#include "ns3/gnuplot.h"

#include "sys/types.h"
#include "sys/stat.h"
#include "ns3/simulator.h"
#include "ns3/flysafe-tag.h"

#include "ns3/adhoc-wifi-mac.h"
#include "ns3/ipv4-header.h"
#include "ns3/llc-snap-header.h"
#include "ns3/udp-header.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-mac-header.h"
#include "ns3/wifi-mac-trailer.h" 
#include "ns3/wifi-net-device.h"
#include "ns3/wifi-phy.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>

using namespace std;

namespace ns3 {

/**
 * @brief Create simulation scenario file
 * @date Mar 20, 2023
 *
 * @param fileName: String with the name of the file to record
 * @param simulDate: String with simulation Date and Time
 * @param dataToSave: Strig with data to be saved
 */
void
CreateSimScenarioFile (string fileName, string simulDate, string dataToSave);

/**
 * @brief Get date and time of simulation start to be used in log files
 * @date Mar 20, 2023
 *
 * @return A string with date and time
 */
string
GetTimeOfSimulationStart();

/**
 * @brief Check whether positions are diferent 
 * @date Mar 5, 2023
 * 
 * @param oldPosition - Vector with old position
 * @param newPosition - Vector with new position
 * @return true - Different positions
 * @return false - Same position
 */

bool
isPositionChanged (Vector oldPosition, Vector newPosition);

/**
 * @brief Calculate distance between two nodes
 * 
 * @date Jan2023
 * 
 * @param myPosition Vector with node position
 * @param neighPosition Vector with neighbor node position
 * @return double Distance
 */

double 
CalculateNodesDistance(Vector myPosition, Vector neighPosition);

/**
 * @brief Print a received neighbor list recovred from a tag
 * @date Feb 26, 2023
 */

void PrintNeighborList(std::vector<ns3::MyTag::NeighInfos> neighInfos);


/**
 * @brief Print received information about a malicous node
 * @date Nov 02, 2023
 */

void PrintMaliciousNodeInfo(std::vector<ns3::MyTag::NeighInfos> neighInfos);


/**
 * @brief Generate false location data
 * @date Oct 30, 2o23
 * 
 * @return Vector - Vector with location coordinates (x, y, z)
 */
Vector GenerateFalseLocation();

/**
 * @brief Generate malicious nodes
 * @date Nov 13, 2023
 * 
 * @return vector - vector with malicious nodes
 */
/*std::vector<int> 
GenerateMaliciousNodes(int nNodes, int nMalicious);
*/
/**
 * @author Vinicius - MiM
 * 
 * @brief Generate malicious nodes
 * 
 * @date Oct 06, 2025
 * 
 * @param nNodes - Number of nodes in the simulation
 * @param nMalicious - Number of malicious nodes to be generated
 * 
 * @return vector - vector with malicious nodes
 */
std::vector<int> 
GenerateMaliciousNodes(NodeContainer nodes, int nMalicious);

/**
 * @brief Convert a vector with integers to a string separated by commas
 * 
 * @param vec - Int vector
 * @return std::string - String separated by commas
 */
std::string 
convertIntVectorToString(const std::vector<int>& vec);

/**
 * @brief Convert a vector with IPs to a string separated by commas
 * 
 * @date Nov 23, 2023
 * 
 * @param vec - IPv4 vector
 * @return std::string - String separated by commas
 */
std::string 
convertIPVectorToString(const std::vector<ns3::Ipv4Address>& vec);

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
 * @param receivedTag - Tag containing the original position and other information
 * @param senderPosition - Position of the sender node
 */ 
class Statistics;                      
void
ExecuteMiMAttack(Statistics* stats, Ptr<Node> snifferNode, Ptr<const Packet> packet, 
                Ipv4Address snifferIp, Ipv4Address senderIp, Ipv4Address receiverIp, 
                MyTag originalTag, Vector senderPosition, int msgTag, 
                vector<ns3::MyTag::NeighborFull> neighList, double messageTime);

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
                       MpduInfo mpdu, SignalNoiseDbm snr, uint16_t staId); 

/**
 * @author Vinicius - MiM
 * 
 * @brief Generate asymmetric keys for nodes in the simulation.
 * 
 * @param nNodes - Number of nodes in the simulation
 */
std::vector<std::pair<std::string, std::string>> 
GenerateAsymmetricKeys(uint32_t nNodes);

void Create2DPlotFile ();
}