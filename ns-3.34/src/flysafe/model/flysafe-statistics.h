#include <fstream>

#include "ns3/address-utils.h"
#include "ns3/address.h"
#include "ns3/node-container.h"
#include "ns3/node.h"
#include "ns3/simulator.h"
#include "ns3/mobility-module.h"
#include "ns3/vector.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-address.h"
#include "ns3/utils.h"

using namespace std;

/* ========================================================================
 * Statistics class
 * Mar 20, 2023
 *
 * Class for data statistics and collect traces
 *
 * ========================================================================
 */

namespace ns3 {

class Statistics {
public:
  Statistics(string timeLog, string folderTraces);

  void ReceiverCallback(string path, double timeNow, Vector position, 
                        Ipv4Address recvAdd, Ipv4Address fromAdd,
                        int msgTag, string message, 
                        vector<ns3::MyTag::NeighborFull> neighList,
                        double messageTime);//,
                        //vector<ns3::MyTag::MaliciousNode> maliciousList);

  void ReceiverMaliciousCallback(string path, double timeNow, Ipv4Address recvAdd,
                                 vector<ns3::MyTag::MaliciousNode> maliciousList);

  void SenderMaliciousCallback(string path, double timeNow, Ipv4Address recvAdd,
                                 vector<ns3::MyTag::MaliciousNode> maliciousList);

  void SenderCallback(string path, double timeNow, Ipv4Address senderAdd, 
                      Ipv4Address targetAdd, int msgTag, string message,
                      Vector position, vector<ns3::MyTag::NeighborFull> neighList);

  /**
  * @brief Statistics of FlySafePacketSink Application - Monitors nodes with empty NL 
  * @date Apr 28, 2023
  * 
  * @param path
  * @param timeNow Simulation time 
  * @param nodeAdd Receiver node IPv4 address
  * @param position Receiver node position
  * @param neighList Neighbor nodes information
  */
  void EmptyNLCallback(string path, double timeNow, Vector position,
                       Ipv4Address nodeAdd,
                       vector<ns3::MyTag::NeighborFull> neighList);

  /**
   * @brief Update state of malicious nodes
   *  
   * @date Dez 01, 2023 
   *
   * @param timeNow Event time
   * @param nodeIP IP of owner node 
   * @param maliciousList malicious node list from the node
   */
  void UpdateMaliciousStateControl(double timeNow, Ipv4Address nodeIP,
                            vector<ns3::MyTag::MaliciousNode> maliciousList);
                            
  bool IsInControlStateList(Ipv4Address nodeIP, Ipv4Address maliciousIP);
  uint8_t GetMaliciousControleState(Ipv4Address nodeIP, Ipv4Address maliciousIP);
  void SetMaliciousBlockedTime(Ipv4Address nodeIP, Ipv4Address maliciousIP, double tBlocked);
  void PrintMaliciousControlStateList();

  Address GetNodeIpAddress(Ptr<Node> node);
  string GetNeighborList(Ptr<Node> node);
  void AppendLineToFile(ofstream& stream, string file, string msg);
  void AppendHeaderToFile(ofstream &fileStream, string fileName, string headerLine);

  /**
  * @brief Struct to store infos from a neighbor node
  * @date 31032023
  */
  struct NeighInfos {
         Ipv4Address ip;
         double x;
         double y;
         double z;
         uint8_t hop;
         double distance;
         uint8_t state;
  }; 


  /**
  * @brief Struct to store infos from a neighbor node string infos
  * @date 31032023
  */
  struct NeighString {
         string ip;
         string x;
         string y;
         string z;
         string distance;
         string attitude;
         string quality;
         string hop;
         uint8_t state;
  }; 


  /**
  * @brief Struct to store infos to controle malicious nodes state
  * 
  * @date Dez 01, 2023
  */
  struct MaliciousControl {
         Ipv4Address nodeIP;
         Ipv4Address maliciousIP;
         uint8_t maliciousState;
         double tSuspicious;
         double tBlocked;
         double avgTime;
  }; 

  /**
   * @brief Identify possible neighbors nodes from all existent nodes (range = 81m)
   * @date 31032023
   * 
   * @param nodesPositions List of all existent nodes with positions
   */
  void IdentifyPossibleNeighbors2(std::vector<NeighInfos> nodesPositions);
  
  /**
   * @brief Evaluate node neighborhood freshness
   * @date 03042023
   * 
   */
  std::vector<ns3::Statistics::NeighInfos>
  IdentifyPossibleNeighbors(Vector nodePosition, std::vector<ns3::Statistics::NeighInfos> neighPositions);

  /**
   * @brief Converts neighbor list vector to string
   * @date Apr 7, 2023
   * 
   * @param neighList neighbor list vector
   * @return string neighbor list on string
   */
  string NeighListToString(vector<ns3::MyTag::NeighborFull> neighList);

  /**
   * @brief Converts malicious neighbor list vector to string
   * @date Nov 27, 2023
   * 
   * @param neighList neighbor list vector
   * @return string neighbor list on string
   */
  string NeighMaliciousListToString(vector<ns3::MyTag::MaliciousNode> maliciousList);

  /**
   * @brief Get all nodes positions 
   * 
   * @return std::vector<ns3::Statistics::NeighInfos> vecto with nodes positions
   */
  std::vector<ns3::Statistics::NeighInfos> getAllNodesPositions();

  /**
   * @brief Get node distances from all nodes in simulation
   * 
   * @date May 18, 2023
   * 
   * @param nodeIP Central node IPv4 address to obtain the distances
   * @param nodesPositions vector with all nodes positions
   * @return string A string with all nodes positions tab spaced
   */
  string getNodesDistances(Ipv4Address nodeIP, std::vector<ns3::Statistics::NeighInfos> nodesPositions);
      
  /**
   * @brief Compare the existent neighborhood with the discoverd neighborhood
   * 
   * @param neighList Discoverd neighborhood
   * @param possibleNeighs Possible neighbors from all nodes available in the simulation
   */
  std::vector<std::string>
  EvaluateNeighborhood(Ipv4Address nodeIP, vector<ns3::MyTag::NeighborFull> neighList, 
                                   std::vector<ns3::Statistics::NeighInfos> possibleNeighs,
                                   double timeNow);

  /**
   * @brief Create and save the total number of sent and received messages in a log file 
   * @date Dez 4, 2023
   * 
   * @param simDate Simulation date and time string
   */
  void MessageResumeLogFile(string simDate);

  /**
   * @brief Save control data from malicious nodes to log files - suspicious and blocked
   * @date Dez 4, 2023
   * 
   * @param simDate Simulation date and time string
   */
  void MaliciousControlResumeLogFile(string simDate);


  /**
   * @brief Verify wether a malicious node is already under control by another node
   *  
   * @date Dez 04, 2023
   * 
   * @param state state of interest (0 suspect, 1 blocked)
   * 
   * @return true - there is the state under control
   * @return false - there is not the state under control
   */
  bool IsStateInList(uint8_t state);


  // Global variables for control spatial awareness 
  double m_startTime;   //!< Store start time to get spatial awareness
  double m_endTime;     //!< Store end time to get spatial awareness
  //bool m_error;         //!< Store spatial awareness condition
  //int m_startAware;    //!< Store spatial awareness start condition


  // Global variables for received messages
  uint32_t m_trapMsgReceived;       //!< Store number of trap messages received
  uint32_t m_broadcastReceived;     //!< Store number of broadcast messages received
  uint32_t m_idMsgReceived;         //!< Store number of identification messages received
  uint32_t m_specialIdMsgReceived;  //!< Store number of special identification messages received
  uint32_t m_suspiciousNeighborReceived;    //!< Store number of messages about suspicious neighbors received
  uint32_t m_blockedNeighborReceived;       //!< Store number of messages about blocked neighbors received
  uint32_t m_suspiciousReductionReceived;   //!< Store number of messages reduction received
  uint32_t m_totalMsgReceived;              //!< Store the total number of messages received
  string m_nodesPositions;          //!< Store nodes positions in a time instant

  // Global variables for sent messages
  uint32_t m_broadcastSent;         //!< Store number of broadcast messages sent
  uint32_t m_idMsgSent;             //!< Store number of identification messages sent
  uint32_t m_specialIdMsgSent;      //!< Store number of special identification messages sent
  uint32_t m_trapMsgSent;           //!< Store number of emergency messages sent
  uint32_t m_suspiciousNeighborSent;    //!< Store number of messages about suspicious neighbors sent
  uint32_t m_blockedNeighborSent;       //!< Store number of messages about blocked neighbors sent
  uint32_t m_suspiciousReductionSent;   //!< Store number of messages reduction sent
  uint32_t m_totalMsgSent;              //!< Store the total number of messages sent


  string m_timeLogFile;             //!< Store the simulation start moment to append in logs file names
  string m_recvTracesFile;          //!< Store received msg traces file name
  string m_sentTracesFile;          //!< Store sent msg traces file name
  string m_positionTracesFile;      //!< Store nodes positions traces file name
  string m_folderToTraces;          //!< Store traces' for folder name

  ofstream m_sentFile;                    //!< Store stream of all sent traces file
  ofstream m_sentNodeFile;                //!< Store stream for one node sent traces file
  ofstream m_recvFile;                    //!< Store stream for receiver msg traces file
  ofstream m_neighFile;                   //!< Store stream for neighborhood evolution traces file
  ofstream m_positionFile;                //!< Store stream for nodes positions traces file
  ofstream m_neighAnalysisFile;           //!< Store stream for neighborhood analysis traces file
  ofstream m_neighAnalysisGnuplotFile;    //!< Store stream for neighborhood analysis Gnuplot traces file
  ofstream m_maliciousFile;               //!< Store stream for malicious neighborhood evolution traces file

  typedef std::vector<struct MaliciousControl> MaliciousHandlerList;
  MaliciousHandlerList m_maliciousControlState;
  // std::vector<struct MaliciousControl> m_maliciousControlState; //!< Store malicious control data
};
} // namespace ns3
