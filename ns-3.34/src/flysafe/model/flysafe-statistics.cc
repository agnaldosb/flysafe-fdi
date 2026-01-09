#include "flysafe-statistics.h"

namespace ns3 {

/**
 * @brief Statistics constructor
 * @date 20032023
 * 
 * Inputs: NIL
 *
 * Output: NIL
 */
Statistics::Statistics(string timeLog, string folderTraces) {
  m_trapMsgSent = 0;
  m_trapMsgReceived = 0;
  m_broadcastSent = 0;
  m_broadcastReceived = 0;
  m_idMsgSent = 0;
  m_idMsgReceived = 0;
  m_specialIdMsgSent = 0;
  m_totalMsgSent = 0;
  m_specialIdMsgReceived = 0;
  m_suspiciousNeighborSent = 0;
  m_blockedNeighborSent = 0;
  m_suspiciousReductionSent = 0;
  m_suspiciousNeighborReceived = 0;
  m_blockedNeighborReceived = 0;
  m_suspiciousReductionReceived = 0;
  m_totalMsgReceived = 0;
  m_nodesPositions = "";
  m_timeLogFile = timeLog;
  m_folderToTraces = folderTraces;
  m_startTime = 0.0;
  m_endTime = 0.0;
  //m_error = true;
  //m_startAware = 1;


  // Define and assign log files names
  ostringstream fileName;

  fileName << folderTraces.c_str() << "flysafe_received_traces_"
           << timeLog.substr(0, timeLog.size() - 2).c_str() << ".txt";
  m_recvTracesFile = fileName.str();
  
  fileName.str("");
  fileName << folderTraces.c_str() << "flysafe_sent_traces_"
           << timeLog.substr(0, timeLog.size() - 2).c_str() << ".txt";
  m_sentTracesFile = fileName.str();

  fileName.str("");
  fileName << folderTraces.c_str() << "flysafe_nodes_positions_"
           << timeLog.substr(0, timeLog.size() - 2).c_str() << ".txt";
  m_positionTracesFile = fileName.str();
}


/**
 * @brief Append header line to a file
 * @date May 16, 2023
 * 
 * @param fileStream file stream
 * @param fileName file name
 * @param header header
 */
void 
Statistics::AppendHeaderToFile(ofstream &fileStream, string fileName, string headerLine){
  
  ifstream my_file;
	
  my_file.open(fileName, ios::in);
	if (!my_file) { // Append header line
    AppendLineToFile(fileStream, fileName, headerLine);
	}
  else{
		my_file.close(); // close opened file
	}
}


/**
 * @brief Add message to log file
 * @date Mar 20, 2023
 * 
 * @param stream 
 * @param file File name and file folder
 * @param msg Message to add
 */
void 
Statistics::AppendLineToFile(ofstream &stream, string file, string msg) {
  stream.open(file, ios::out | ios::app);
  stream << msg;
  stream.close();
}


/**
 * @brief Statistics of FlySafePacketSink Application - Receiving messages and answers
 * @date Mar 20, 2023
 * 
 * @param path
 * @param timeNow Simulation time 
 * @param recvAdd Receiver node IPv4 address
 * @param position Receiver node position
 * @param fromAdd Sender node IPv4 address
 * @param msgTag Tag from message received
 * @param message Received message
 * @param neighList Neighbor nodes information
 */
void Statistics::ReceiverCallback(string path, double timeNow, Vector position,
                                  Ipv4Address recvAdd, Ipv4Address fromAdd, 
                                  int msgTag, string message,
                                  vector<ns3::MyTag::NeighborFull> neighList,
                                  double messageTime) //,
                                  //vector<ns3::MyTag::MaliciousNode> maliciousList)
{
  ostringstream filename;
  std::vector<NeighInfos> nodesPositions;
  std::vector<NeighInfos> possibleNeighbors;
  vector <string> evalString;
  stringstream headerLine;
  ostringstream textLine;

  m_totalMsgReceived++;

  switch (msgTag) {
  case 0: // Broadcast - Searching neighbors
    m_broadcastReceived++;
    break;

  case 1: // Unicast - Send Id to answer a broadcast
    m_idMsgReceived++;
    break;

  case 2: // Unicast - Trap msg
    m_trapMsgReceived++;
    break;

  case 3: // Unicast - Special Identification message
    m_specialIdMsgReceived++;
    break;

  case 4: // Unicast - Suspect neighbor message
    m_suspiciousNeighborReceived++;
    break;

  case 5: // Unicast - blocked neighbor message
    m_blockedNeighborReceived++;
    break;

  case 6: // Unicast - Suspicious reduction message
    m_suspiciousReductionReceived++;
    break;
  }

  ostringstream fileName; 
  
  // if (msgTag == 4){
  //   goto stopped;
  // }

  // *** Saving all received messages in one file *** 

  headerLine << "time" << "\t" << "IPTx" << "\t" << "IPRx" << "\t" << "msgTag" << "\t" << "message" << endl;
  AppendHeaderToFile(m_neighFile, m_recvTracesFile, headerLine.str());

  // Append message line to file
  textLine << timeNow << "\t" << fromAdd << "\t" << recvAdd << "\t" 
           << msgTag << "\t" << message.c_str() << endl;
  AppendLineToFile(m_recvFile, m_recvTracesFile.c_str(), textLine.str());


  // *** Saving a node received messages in its file *** 

  fileName << m_folderToTraces.c_str() << "messages_received_" << recvAdd
           << ".txt";

  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "IPTx" << "\t" << "msgTag" << "\t" << "message" << endl;
  AppendHeaderToFile(m_recvFile, fileName.str(), headerLine.str());

  // Append received message to file
  textLine.str("");
  textLine << timeNow << "\t" << fromAdd << "\t"
           << msgTag << "\t" << message.c_str() << endl;
  AppendLineToFile(m_recvFile, fileName.str(), textLine.str());


  //stopped:

  // *** Saving neighborhood evolution data in node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_evolution_" << recvAdd
          << ".txt";
  
  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "x" << "\t" << "y" << "\t" << "z" 
             << "\t" << "IP,x,y,z,dist,att,qualy,hop,state" << endl;
  AppendHeaderToFile(m_neighFile, fileName.str(), headerLine.str());

  // Append evolution data to file
  textLine.str("");
  textLine << timeNow << "\t" << position.x << "," << position.y 
           << "," << position.z << "\t" << NeighListToString(neighList);
  AppendLineToFile(m_neighFile, fileName.str(), textLine.str());

  /*
  // *** Saving malicious neighborhood evolution data in node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "malicious_neighborhood_evolution_" << recvAdd
          << ".txt";
  
  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "size" << "\t" << "IP, recurrence, state, nNotfiers, notifiers" << endl;
  AppendHeaderToFile(m_maliciousFile, fileName.str(), headerLine.str());

  // Append evolution data to file
  textLine.str("");
  textLine << timeNow << "\t" << position.x << "," << position.y 
           << "," << position.z << "\t" << NeighListToString(neighList);
           //NeighMaliciousListToString();
  AppendLineToFile(m_maliciousFile, fileName.str(), textLine.str());
  */


  // *** Get all nodes positions ***
  NodeContainer c =  NodeContainer::GetGlobal ();
  ostringstream positionInfos;
  positionInfos << timeNow;

  nodesPositions = getAllNodesPositions();
  
  for (auto n :nodesPositions){
      positionInfos << "\t"
                    << n.ip << "," << n.x << "," << n.y << "," << n.z;
  }
  positionInfos << endl;


  // *** Saving nodes positions to a file ***

  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "IP,x,y,z" << "\t" << "IP,x,y,z" << endl;
  AppendHeaderToFile(m_positionFile, m_positionTracesFile.c_str(), headerLine.str());

  // Append nodes positions to file
  if(m_nodesPositions.compare(positionInfos.str()) != 0){ // Avoid store repeated lines
    AppendLineToFile(m_positionFile, m_positionTracesFile.c_str(), positionInfos.str());
    m_nodesPositions = positionInfos.str();
  }


  // *** Saving nodes distances to a file ***
  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_distances_" << recvAdd
          << ".txt";

  // Append header line to file
  headerLine.str("");
  headerLine << "time";
  for(int i=1; i < (int)nodesPositions.size()+1; i++){
      headerLine << "\t" << "U" << i ;
  }
  headerLine << endl;  

  AppendHeaderToFile(m_positionFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to a file
  string stringDistance;
  stringDistance = getNodesDistances(recvAdd, nodesPositions);
  textLine.str("");
  textLine << timeNow << "\t" << stringDistance;
  AppendLineToFile(m_positionFile, fileName.str(), textLine.str());


  // -----------------------------------------
  // *** Performing deviation analysis ***
  // -----------------------------------------

  // *** Saving deviation data in individual node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "deviation_delay_rx_analysis_" << recvAdd
          << ".txt";
  
  // Append header line to file
  headerLine.str("");
  m_neighFile.clear();
  headerLine << "timeTX" << "\t" << "timeRX" << "\t" << "delay(ms)" << "\t" << "IPTX" << endl;
  AppendHeaderToFile(m_neighFile, fileName.str(), headerLine.str());

  // Append message times to file
  textLine.str("");
  textLine << messageTime << "\t" << timeNow << "\t" << (timeNow - messageTime) * 1000 << "\t" << fromAdd << endl;
  AppendLineToFile(m_neighFile, fileName.str(), textLine.str());


// *** Saving deviation data in a global file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "deviation_delay_rx_analysis_global.txt";
  
  // Append header line to file
  headerLine.str("");
  m_neighFile.clear();
  headerLine << "timeTX" << "\t" << "IPTX" << "\t" << "timeRX" << "\t" << "IPRX" << "\t" << "delay(ms)" << endl;
  AppendHeaderToFile(m_neighFile, fileName.str(), headerLine.str());

  // Append message times to file
  textLine.str("");
  textLine << messageTime << "\t" << fromAdd << "\t" <<
              timeNow << "\t" << recvAdd << "\t" << (timeNow - messageTime) * 1000 << endl;
  AppendLineToFile(m_neighFile, fileName.str(), textLine.str());


  // -----------------------------------------
  // *** Performing neighborhood analysis ***
  // -----------------------------------------

  string neighAnalysis;

  possibleNeighbors = IdentifyPossibleNeighbors(position, nodesPositions);
  
  // if ((int)neighList.size() == 0 &&  (int)possibleNeighbors.size() == 0){
  //   cout << recvAdd << " : " << timeNow << " Statistics - Neighbor list is empty!" << endl;
  // }

  // Evaluate existent neighborhood from the possible neighbors and one hop neighbors available
  // [0] String with neighborhood discovery analysis to log file
  // [1] String with neighborhood discovery analysis to gnuplot log file
  // [2] String with spatial awareness analysis
  // [3] String with neighbors distances analysis to gnuplot log file

  evalString = EvaluateNeighborhood(recvAdd, neighList, possibleNeighbors, timeNow);
  
  
  // *** Saving neighborhood analysis from a node to a file ***
  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_analysis_" << recvAdd
          << ".txt";

  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize,IP" << "\t" << "nPsbNeigh,IP" 
             << "\t" << "nNeighCIdent,IP" << "\t" << "Error" << endl;  
  AppendHeaderToFile(m_neighAnalysisFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to a file
  textLine.str("");
  textLine << timeNow << "\t" << evalString[0];
  AppendLineToFile(m_neighAnalysisFile, fileName.str(), textLine.str());


  // *** Saving neighborhood analysis from a node to a gnuplot file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_analysis_gnuplot_" << recvAdd
          << ".txt";

  // append header line to a gnuplot file  
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize" << "\t" << "nPsbNeigh" 
             << "\t" << "nNeighCIdent" << "\t" << "Error" << "\t" << "Aware" << endl;
  AppendHeaderToFile(m_neighAnalysisGnuplotFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to a gunplot file        
  textLine.str("");
  textLine << timeNow << "\t" << evalString[1] << endl;
  AppendLineToFile(m_neighAnalysisGnuplotFile, fileName.str(), textLine.str());  


  // // *** Saving the amount of exchanged messages to a file ***

  // // *** Enable to compute the number of messages necesary **
  // // *** to achieve and keep spatial awareness             ***

  // fileName.str("");
  // m_neighAnalysisGnuplotFile.clear();
  // fileName << m_folderToTraces.c_str() << "exchanged_messages_analysis_" << recvAdd
  //         << ".txt";

  // // append header line to a gnuplot file  
  // headerLine.str("");
  // headerLine << "time" << "\t" << "bdTx" << "\t" << "bdRX" 
  //            << "\t" << "idTX" << "\t" << "idRx" << "\t" << "trTx" << "\t" << "trRx" << endl;
  // AppendHeaderToFile(m_neighAnalysisGnuplotFile, fileName.str(), headerLine.str());

  // // Append neighborhood analysis to a gunplot file        
  // textLine.str("");
  // textLine << timeNow << "\t" << m_broadcastSent << "\t" <<  m_broadcastReceived
  //                     << "\t" << m_idMsgSent << "\t" << m_idMsgReceived
  //                     << "\t" << m_trapMsgSent << "\t" << m_trapMsgReceived << endl;
  // AppendLineToFile(m_neighAnalysisGnuplotFile, fileName.str(), textLine.str());
  

  // *** Saving localization erros analysis from a node to a file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_localization_error_analysis_" << recvAdd
          << ".txt";

  // append header line to file  
  headerLine.str("");
  headerLine << "time" << "\t" << "nNeighs" << "\t" << "AvgError" 
             << "\t" << "MinError" << "\t" << "MaxError" << "\t" << "Errors" << endl;
  AppendHeaderToFile(m_neighAnalysisFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to file if evalString not empty 
  // Empty evalString means no neighbor correctly identified
  if ((int)evalString[2].size() > 0){     
    textLine.str("");
    textLine << timeNow << "\t" << evalString[2] << endl;
    //cout << "String localization analysis: " << evalString[2].c_str() << "\n" << endl;
    AppendLineToFile(m_neighAnalysisFile, fileName.str(), textLine.str());  
  }
}


/**
 * @brief Statistics of FlySafeOnOff Application - Sending messages (broadcast)
 * @date Mar 22, 2023
 * 
 * @param path Call back node path
 * @param senderIP  Sender's IPv4 address
 * @param targetIP Target IPv4 address
 * @param msgTag Tag from message received
 * @param message Message sent
 */
void Statistics::SenderCallback(string path, double timeNow, Ipv4Address senderIP,
                                Ipv4Address targetIP, int msgTag, string message,
                                Vector position, vector<ns3::MyTag::NeighborFull> neighList) 
{
  ostringstream fileName;
  ostringstream headerLine;
  ostringstream textLine;


  m_totalMsgSent++;

  switch (msgTag) {
  case 0: // Broadcast - Searching neighbors
    m_broadcastSent++;
    break;

  case 1: // Unicast - Indentification sent to a neighbors search
    m_idMsgSent++;
    break;

  case 2: // Unicast - Indentification sent to a neighbors search
    m_trapMsgSent++;
    break;

  case 3: // Unicast - Special Id sent whether NL is empty
    m_specialIdMsgSent++;
    break;

  case 4: // Unicast - Suspect neighbor message
    m_suspiciousNeighborSent++;
    break;

  case 5: // Unicast - blocked neighbor message
    m_blockedNeighborSent++;
    break;

  case 6: // Unicast - Suspicious reduction message
    m_suspiciousReductionSent++;
    break;
  }

  // *** Saving sent messages to one file ***

  // Append header line to file
  headerLine << "time" << "\t" << "IPTx" << "\t" << "IPRx" 
      << "\t" << "msgTag" << "\t" << "message" << endl;
  AppendHeaderToFile(m_sentFile, m_sentTracesFile.c_str(), headerLine.str());

  // Save all messages sent in only one file
  textLine << timeNow << "\t" << senderIP << "\t" << targetIP 
      << "\t" << msgTag << "\t" << message.c_str() << endl;
  AppendLineToFile(m_sentFile, m_sentTracesFile.c_str(), textLine.str());


  // *** Saving node sent messages to its file ***

  // ostringstream convert;
  fileName << m_folderToTraces.c_str() << "messages_sent_" << senderIP
          << ".txt";

  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "targetIP" << "\t" 
             << "msgTag" << "\t" << "message" << endl;
  AppendHeaderToFile(m_sentNodeFile, fileName.str(), headerLine.str());           

  // Save received messages individually by IP address
  textLine.str("");
  textLine << timeNow << "\t" << targetIP << "\t" << msgTag << "\t"
           << message.c_str() << endl;
  AppendLineToFile(m_sentNodeFile, fileName.str(), textLine.str());


  // *** Monitoring node NL whenever it sends a new message ***
  // May 2, 2023

  //ostringstream filename;
  std::vector<NeighInfos> nodesPositions;
  std::vector<NeighInfos> possibleNeighbors;
  vector <string> evalString;

  // Save neighbor list information individually by IP address

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_evolution_" << senderIP
            << ".txt";

  // Append header line to eighborhood evolution node' file
  headerLine.str("");
  headerLine << "time" << "\t" << "x" << "\t" << "y" << "\t" << "z" 
             << "\t" << "IP,x,y,z,dist,att,qualy,hop,state" << endl;
  AppendHeaderToFile(m_neighFile, fileName.str(), headerLine.str()); 

  // Append neighborhood evolution to a node file
  textLine.str("");
  textLine << timeNow << "\t"
           << position.x << "," << position.y << "," << position.z 
           << "\t" << NeighListToString(neighList);
  AppendLineToFile(m_neighFile, fileName.str(), textLine.str());



  // Get all nodes positions
  NodeContainer c =  NodeContainer::GetGlobal ();
  ostringstream positionInfos;
  positionInfos << timeNow;

  nodesPositions = getAllNodesPositions();
  
  for (auto n :nodesPositions){
      positionInfos << "\t"
                    << n.ip << "," << n.x << "," << n.y << "," << n.z;
  }
  positionInfos << endl;


  // *** Saving all nodes positions to one file ***

  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "IP,x,y,z" << "\t" << "IP,x,y,z" << endl;
  AppendHeaderToFile(m_positionFile, m_positionTracesFile.c_str(), headerLine.str()); 

  // Append nodes positions line to a file
  if(m_nodesPositions.compare(positionInfos.str()) != 0){ // Avoid store same positions at the same time
    AppendLineToFile(m_positionFile, m_positionTracesFile.c_str(), positionInfos.str());
    m_nodesPositions = positionInfos.str();
  }

  // *** Saving nodes distances to a file ***
  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_distances_" << senderIP
          << ".txt";

  // Append header line to file
  headerLine.str("");
  headerLine << "time";
  for(int i=1; i < (int)nodesPositions.size()+1; i++){
      headerLine << "\t" << "U" << i ;
  }
  headerLine << endl;  

  AppendHeaderToFile(m_positionFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to a file
  string stringDistance;
  stringDistance = getNodesDistances(senderIP, nodesPositions);
  textLine.str("");
  textLine << timeNow << "\t" << stringDistance;
  AppendLineToFile(m_positionFile, fileName.str(), textLine.str());

  // *** Evaluating neighborhood nodes evolution ***

  possibleNeighbors = IdentifyPossibleNeighbors(position, nodesPositions);

  string neighAnalysis;
  
  // Evaluate existent neighborhood from the possible neighbors and one hop neighbors available
  // [0] String with neighborhood discovery analysis to log file
  // [1] String with neighborhood discovery analysis to gnuplot log file
  // [2] String with spatial awareness analysis
  // [3] String with neighbors distances analysis to gnuplot log file
  
  evalString = EvaluateNeighborhood(senderIP, neighList, possibleNeighbors, timeNow);

  // *** Saving neighborhood nodes evolution to a file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_tx_analysis_" << senderIP
          << ".txt";

  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize,IP" << "\t" << "nPsbNeigh,IP" 
             << "\t" << "nNeighCIdent,IP" << "\t" << "Error" << endl;
  AppendHeaderToFile(m_neighAnalysisFile, fileName.str(), headerLine.str()); 

  // Append neighborhood evolution line to a file
  textLine.str("");
  textLine << timeNow << "\t" << evalString[0];
  AppendLineToFile(m_neighAnalysisFile, fileName.str(), textLine.str());


  // *** Saving neighborhood nodes evolution to a gnuplot file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_tx_analysis_gnuplot_" << senderIP
          << ".txt";
  
  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize" << "\t" << "nPsbNeigh" 
             << "\t" << "nNeighCIdent" << "\t" << "Error" << endl;
  AppendHeaderToFile(m_neighAnalysisGnuplotFile, fileName.str(), headerLine.str()); 

  // Append neighborhood evolution line to a gnuplot file
  textLine.str("");
  textLine << timeNow << "\t" << evalString[1] << endl;
  AppendLineToFile(m_neighAnalysisGnuplotFile, fileName.str(), textLine.str());  
}


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
void Statistics::EmptyNLCallback(string path, double timeNow, Vector position,
                                  Ipv4Address nodeAdd,
                                  vector<ns3::MyTag::NeighborFull> neighList)
{
  ostringstream filename;
  std::vector<NeighInfos> nodesPositions;
  std::vector<NeighInfos> possibleNeighbors;
  vector <string> evalString;
  ostringstream fileName;
  ostringstream textLine;
  ostringstream headerLine;

  // ** Saving neighbor list information individually by IP address ***

  fileName << m_folderToTraces.c_str() << "neighborhood_evolution_" << nodeAdd
           << ".txt";
  
  // append header line to file
  headerLine << "time" << "\t" << "x" << "\t" << "y" << "\t" << "z" 
             << "\t" << "IP,x,y,z,dist,att,qualy,hop,state" << endl;
  AppendHeaderToFile(m_neighFile,fileName.str(), headerLine.str());

  // Append neighborhood evolution line to a node file
  textLine << timeNow << "\t"
           << position.x << "," << position.y << "," << position.z 
           << "\t" << NeighListToString(neighList);
  AppendLineToFile(m_neighFile, fileName.str(), textLine.str());


  // Get all nodes positions
  NodeContainer c =  NodeContainer::GetGlobal ();
  ostringstream positionInfos;
  positionInfos << timeNow;

  nodesPositions = getAllNodesPositions();
  
  for (auto n :nodesPositions){
      positionInfos << "\t" << n.ip << "," << n.x << "," << n.y << "," << n.z;
  }
  positionInfos << endl;
  

  // *** Saving all nodes positions to one file ***

  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "IP,x,y,z" << "\t" << "IP,x,y,z" << endl;
  AppendHeaderToFile(m_positionFile, m_positionTracesFile.c_str(), headerLine.str());

  // Append all nodes positions in a time to file
  if(m_nodesPositions.compare(positionInfos.str()) != 0){ // Avoid store same positions at the same time
    AppendLineToFile(m_positionFile, m_positionTracesFile.c_str(), positionInfos.str());
    m_nodesPositions = positionInfos.str();
  }

  // *** Saving nodes distances to a file ***
  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_distances_" << nodeAdd
          << ".txt";

  // Append header line to file
  headerLine.str("");
  headerLine << "time";
  for(int i=1; i < (int)nodesPositions.size()+1; i++){
      headerLine << "\t" << "U" << i ;
  }
  headerLine << endl;  

  AppendHeaderToFile(m_positionFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to a file
  string stringDistance;
  stringDistance = getNodesDistances(nodeAdd, nodesPositions);
  textLine.str("");
  textLine << timeNow << "\t" << stringDistance;
  AppendLineToFile(m_positionFile, fileName.str(), textLine.str());

  // ***Evaluating neighborhood nodes evolution ***

  possibleNeighbors = IdentifyPossibleNeighbors(position, nodesPositions);

  string neighAnalysis;
  
  // *** Saving neighborhood nodes evolution to node file ***

  // Evaluate existent neighborhood from the possible neighbors and one hop neighbors available
  // [0] String with neighborhood discovery analysis to log file
  // [1] String with neighborhood discovery analysis to gnuplot log file
  // [2] String with spatial awareness analysis
  // [3] String with neighbors distances analysis to gnuplot log file

  evalString = EvaluateNeighborhood(nodeAdd, neighList, possibleNeighbors, timeNow);
  
  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_analysis_" << nodeAdd
          << ".txt";
  
  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize,IP" << "\t" << "nPsbNeigh,IP" 
             << "\t" << "nNeighCIdent,IP" << "\t" << "Error" << endl;
  AppendHeaderToFile(m_neighAnalysisFile, fileName.str(), headerLine.str());

  // Append neighborhood evolution line to a file
  textLine.str("");
  textLine << timeNow << "\t" << evalString[0];
  AppendLineToFile(m_neighAnalysisFile, fileName.str(), textLine.str());


  // *** Saving neighborhood nodes evolution to a gnuplot node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_analysis_gnuplot_" << nodeAdd
          << ".txt";
  
  // append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "NLSize" << "\t" << "nPsbNeigh" 
             << "\t" << "nNeighCIdent" << "\t" << "Error" << "\t" << "Aware" << endl;
  AppendHeaderToFile(m_neighAnalysisGnuplotFile, fileName.str(), headerLine.str());

  // Append neighborhood nodes evolution line
  textLine.str("");
  textLine << timeNow << "\t" << evalString[1] << endl;
  AppendLineToFile(m_neighAnalysisGnuplotFile, fileName.str(), textLine.str()); 

  
  // *** Saving localization erros analysis from a node to a file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "neighborhood_rx_localization_error_analysis_" << nodeAdd
          << ".txt";

  // append header line to file  
  headerLine.str("");
  headerLine << "time" << "\t" << "nNeighs" << "\t" << "AvgError" 
             << "\t" << "MinError" << "\t" << "MaxError" << "\t" << "Errors" << endl;
  AppendHeaderToFile(m_neighAnalysisFile, fileName.str(), headerLine.str());

  // Append neighborhood analysis to file if evalString not empty 
  // Empty evalString means no neighbor correctly identified
  if ((int)evalString[2].size() > 0){     
    textLine.str("");
    textLine << timeNow << "\t" << evalString[2] << endl;
    //cout << "String localization analysis: " << evalString[2].c_str() << endl;
    AppendLineToFile(m_neighAnalysisFile, fileName.str(), textLine.str());  
  } 
}


/**
 * @brief Identify possible neighbors (1 hop only)
 * @date Apr 3, 2023
 * 
 * @param nodesPositions List of all existent nodes with positions
 */
std::vector<ns3::Statistics::NeighInfos> Statistics::IdentifyPossibleNeighbors(Vector nodePosition, std::vector<ns3::Statistics::NeighInfos> allNodesPositions){
  vector<NeighInfos> possibleNeighs; 
  double distance, value;
  Vector neighPosition;

  // Calculate the distance between this node to all nodes in simulation 
  for (uint8_t i = 0; i < allNodesPositions.size(); i++) {
    neighPosition.x = allNodesPositions[i].x;
    neighPosition.y = allNodesPositions[i].y;
    neighPosition.z = allNodesPositions[i].z;
    value = CalculateDistance(nodePosition, neighPosition);
    distance = std::ceil(value * 100.0) / 100.0; // 2 decimal cases
    allNodesPositions[i].distance = distance;
    if (distance > 0.0 && distance < 86.0){
      possibleNeighs.push_back(allNodesPositions[i]);
      //cout << "Possible neighbor: " << allNodesPositions[i].ip << endl;
    }
  }
  /*
  cout << "\n ****** Distances analysis ******\n" 
       << "Distances between this node and all nodes in simulation:" << endl;
  for(auto n :allNodesPositions){
    cout << "IP: " << n.ip << " Position x: " << n.x << " y: " << n.y << " z: " << n.z << " Distance: " << n.distance << endl;
  }
  cout <<"\n" << endl; */
  return possibleNeighs;
}

/**
 * @brief Get all nodes positions 
 * 
 * @return std::vector<ns3::Statistics::NeighInfos> vector with nodes positions
 */
std::vector<ns3::Statistics::NeighInfos> Statistics::getAllNodesPositions(){
  std::vector<NeighInfos> nodesPositions;
  NeighInfos nodePosition;
  NodeContainer c =  NodeContainer::GetGlobal ();
  ostringstream positionInfos;

  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<MobilityModel> position = node->GetObject<MobilityModel> ();
      Vector pos = position->GetPosition ();
      nodePosition.x = pos.x;
      nodePosition.y = pos.y;
      nodePosition.z = pos.z;
      nodePosition.hop = 0;
      nodePosition.distance = 0;
      nodePosition.state = 0;
      //nodePosition.ip = node->GetObject<Ipv4Address>();
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
      Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1, 0);
      nodePosition.ip = iaddr.GetLocal();
      nodesPositions.push_back(nodePosition);
    }
  return nodesPositions;

}


/**
 * @brief Get node distances from all nodes in simulation
 * 
 * @param nodeIP Central node IPv4 address to obtain the distances
 * @param nodesPositions vector with all nodes positions
 * @return string A string with all nodes positions tab spaced
 */
string Statistics::getNodesDistances(Ipv4Address nodeIP, std::vector<ns3::Statistics::NeighInfos> nodesPositions){
  double distance;
  double value;
  ostringstream distanceLine;
  Vector nodeRef, nodeNeigh;

  for(auto n : nodesPositions){ 
    if (n.ip == nodeIP){ // Get nodeIP position (reference)
      nodeRef.x = n.x;
      nodeRef.y = n.y;
      nodeRef.z = n.z;
      for(auto m : nodesPositions){
        nodeNeigh.x = m.x;
        nodeNeigh.y = m.y;
        nodeNeigh.z = m.z;
        value = CalculateDistance(nodeRef, nodeNeigh);
        distance = std::ceil(value * 100.0) / 100.0; // 2 decimal cases
        distanceLine << distance << "\t";
      }
    }
  }
  distanceLine << endl;
  return distanceLine.str();

}


/**
 * @brief Converts neighbor list vector to string
 * @date Apr 7, 2023
 * 
 * @param neighList neighbor list vector
 * @return string neighbor list on string
 */
string Statistics::NeighListToString(vector<ns3::MyTag::NeighborFull> neighList){
ostringstream neighString;

  for(auto n : neighList){
    if (n.quality != 0){
      neighString << '\t';
      neighString << n.ip << "," << n.position.x << "," << n.position.y << "," << n.position.z 
                  << "," << n.distance << "," << (int)n.attitude << "," << (int)n.quality 
                  << "," << (int) n.hop << "," << (int)n.state;
    }
  }
  neighString << endl;
  // "IP,x,y,z,dist,att,qualy,hop"
  return neighString.str();
}

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Converts malicious neighbor list vector to string
 * @date Nov 27, 2023
 * 
 * @param neighList neighbor list vector
 * @return string neighbor list on string
 */
/*string Statistics::NeighMaliciousListToString(vector<ns3::MyTag::MaliciousNode> maliciousList){

  ostringstream maliciousString;
  
  if (maliciousList.size() == 0) { // No malicious neighbors
    maliciousString << "0";
  }
  else{
    maliciousString << (int)maliciousList.size();
    for(auto n : maliciousList){
      maliciousString << '\t';
      maliciousString << n.ip << "," << (int)n.state << "," << (int)n.recurrence 
                   << "," << (int)n.notifyIP.size() << "," << convertIPVectorToString(n.notifyIP); 
    }
  }
  maliciousString << endl;
  // "IP,state,recurrence,nNotifiers,notifiers"
  return maliciousString.str();
}*/

/**
 * @brief Compare the existent neighborhood with the discoverd neighborhood
 * 
 * @param neighList Discoverd neighborhood
 * @param possibleNeighs Possible neighbors from all nodes available in the simulation
 */
//std::string 
// void
std::vector<std::string>
Statistics::EvaluateNeighborhood(Ipv4Address nodeIP, vector<ns3::MyTag::NeighborFull> neighList, 
                                 std::vector<ns3::Statistics::NeighInfos> possibleNeighs,
                                 double timeNow){
  vector<string> results;
  ostringstream strFound, strNotFound, strFinal, neighs, pNeighs, strToGraph;
  int yes = 0, no = 0;
  int i, z;
  vector <int> NLCtrl((int)neighList.size(),0); // Store neighbors correctly identified
  vector <int> PNCtrl((int)possibleNeighs.size(),0); // Store neighbors not identified
  vector <double> distanceError;

  for (i = 0; i < (int)neighList.size(); i++){
    for (z = 0; z < (int)possibleNeighs.size(); z++){
      if (neighList[i].ip == nodeIP){ // Discard the node itself
        break;
      }
      if (neighList[i].ip == possibleNeighs[z].ip){
        NLCtrl[i] = 1;
        PNCtrl[z] = 1;
        break;
      }
    }
  }

  //cout << "Neighbors correctly identified: " << endl;
  for (i = 0; i < (int)NLCtrl.size(); i++){
    neighs << neighList[i].ip << ","; // Put the neighbors IP in a string
    if (NLCtrl[i] == 1){
      //cout << neighList[i].ip << " distance: " << neighList[i].distance << endl;
      strFound << neighList[i].ip << ",";
    }
  }

 // cout << "Neighbors not identified: " << endl;
  for (i = 0; i < (int)PNCtrl.size(); i++){
    pNeighs << possibleNeighs[i].ip << ","; // Put the possible neighbors IP in a string
    if (PNCtrl[i] == 0){
      //cout << possibleNeighs[i].ip << " distance: "<< possibleNeighs[i].distance << endl;
      strNotFound << possibleNeighs[i].ip << ",";
    }
  }

  // String information order
  // NNeigh, NeighIP \t NPNeigh, PNeighIP \t NNeighFound, NeighFoundIP \t 
  // NNeighNotFound, NeighNotFoundIP \t Error: NPNeighNotFound/NPNeigh

  if ((int)neighList.size() == 0){
    strFinal << 0;
  }
  else{
    strFinal << (int)neighList.size() << "," << neighs.str().substr(0,neighs.str().size()-1);
  }
  
  if ((int)possibleNeighs.size() == 0){
    strFinal << "\t" << 0;
  }
  else{
    strFinal << "\t" << (int)possibleNeighs.size() << "," << pNeighs.str().substr(0,pNeighs.str().size()-1);
  }

  yes = accumulate(NLCtrl.begin(), NLCtrl.end(),0); // Sum vector values
  if (yes == 0){ // Neighbors are not plausible neighbors
    strFinal << "\t" << 0; 
  }
  else{
    strFinal << "\t" << yes << "," << strFound.str().substr(0,strFound.str().size()-1); 
  }

  no = (int)PNCtrl.size() - accumulate(PNCtrl.begin(), PNCtrl.end(),0); // Plausible neighbors not identified  
  if(no == 0){
    strFinal << "\t"; 
  }
  else{
    strFinal << "\t" << no << "," << strNotFound.str().substr(0,strNotFound.str().size()-1); 
  }
  strFinal << no << "/" << (int)PNCtrl.size() << endl;
  
  results.push_back(strFinal.str());

  // string to gnuplot graph: Number of neighbor nodes identified, Number of possible neighbors, 
  // Number of neighbor nodes correclty identified, Error, Awareness condition
  // "NLSize" << "\t" << "nPsbNeigh" << "\t" << "nNeighCIdent" << "\t" << "Error" << "\t" << "Aware"

  if (no > 0) { // There are error, no spatial awareness
    strToGraph << (int)neighList.size() << "\t" << (int)possibleNeighs.size() << "\t" << yes << "\t" << no << "\t" << 0;
  }
  else{
    strToGraph << (int)neighList.size() << "\t" << (int)possibleNeighs.size() << "\t" << yes << "\t" << no<< "\t" << 1;
  }
  results.push_back(strToGraph.str());

  
  // Evaluating neighborhood spatial awareness
  // Jun 09, 2023
  /**
   * @brief 
   * 
   *
  strFinal.str("");
  strFinal.clear();

  if(m_startAware == 1){ // starting analysis
    m_startAware = 0;
    m_endTime = timeNow;
    if (no == 0){
      m_error = false;
    }
    results.push_back("START CONDITION");
    cout << timeNow << "\t" << "START CONDITION" << endl;
    //strFinal << m_startTime << "\t" << m_endTime << "\t" << (m_endTime - m_startTime) << "\t" << "START"; 
    //results.push_back(strFinal.str()); 
  }
  else{
    if(no > 0){ // We have an error now
      if(m_error == true){ // We already have an error
        m_endTime = timeNow;
        results.push_back("");
      }
      else{ // We dont have an error (transition)
        m_endTime = timeNow;
        strFinal << m_startTime << "\t" << m_endTime << "\t" << (m_endTime - m_startTime) << "\t" << (int)m_error; 
        results.push_back(strFinal.str()); 
        m_startTime = m_endTime;
        m_error = true;
      }
    }
    else{ // We dont have error now
      if(m_error == true){  // We had an error before (transition)
        m_endTime = timeNow;
        strFinal << m_startTime << "\t" << m_endTime << "\t" << (m_endTime - m_startTime) << "\t" << (int)m_error; 
        results.push_back(strFinal.str()); 
        m_startTime = m_endTime;
        m_error = false;        
      }
      else{ // We didnt have error before
        m_endTime = timeNow;
        results.push_back("");        
      }
    }
  }
  */

  

  // Evaluate localization errors from nodes correctly identified
  // Employ NLCtrl vector
  // May 26, 2023

  double dist;

  // Evaluate localization distance erros only when there are correctly identified nodes
  // string created at the end: nNeighs AvgError MinError MaxError Errors

  strFinal.str("");
  strFinal.clear();

  if(yes != 0){ // There are nodes correclty identified
    for (i = 0; i < (int)NLCtrl.size(); i++){
      //cout << "Localization evaluation: ";
      if (NLCtrl[i] == 1){
        for(auto n : possibleNeighs){
          if(neighList[i].ip == n.ip){
            //cout << "IP " << n.ip << " Distance in NL: " << neighList[i].distance << " Real distance: " << n.distance;
            dist = neighList[i].distance - n.distance;
            if (dist < 0){
              dist = dist * (-1);
            }
            //cout << " Error: " << dist;
            distanceError.push_back(dist);
          }
        }
      }
      //cout << endl;
    }

    double sumDist = 0.0;
    // string to create: nNeighs AvgError MinError MaxError Errors
    strFinal << yes << "\t"; // insert nNeighs in the result string

    for (int x = 0; x < (int)distanceError.size(); x++){
      sumDist += distanceError[x];
    }
    // Vinicius - MiM - Oct 29, 2025 - Commented because was calculating average two times
    //double value = sumDist/(int)distanceError.size();
    strFinal << (sumDist/(int)distanceError.size());
    //strFinal << (std::ceil(value * 100.0) / 100.0);

    auto minmax = std::minmax_element(distanceError.begin(), distanceError.end());
    strFinal << "\t"  << *minmax.first; // get MinError
    strFinal << "\t" << *minmax.second; // get MaxError

    for (int z = 0; z < (int)distanceError.size(); z++){
      strFinal << "\t" << distanceError[z]; // get Errors
    }
  }  
  else{
    strFinal << ""; 
  }
  results.push_back(strFinal.str());

  //return strFinal.str();
  return results;
}

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Statistics of FlySafePacketSink Application - Tracing malicious neighborhood evolution
 * @date Nov 23, 2023
 * 
 * @param path
 * @param timeNow Simulation time 
 * @param recvAdd Receiver node IPv4 address
 * @param maliciousList Malicious neighbor nodes information
 */
/*void Statistics::ReceiverMaliciousCallback(string path, double timeNow, Ipv4Address recvAdd,
                                        vector<ns3::MyTag::MaliciousNode> maliciousList)
{
  ostringstream filename;
  stringstream headerLine;
  ostringstream textLine;
  ostringstream fileName; 

  // *** Saving malicious neighborhood evolution data in node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "malicious_neighborhood_evolution_" << recvAdd
          << ".txt";
  
  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "size" << "\t" << "IP, state, recurrence, nNotfiers, notifiers" << endl;
  AppendHeaderToFile(m_maliciousFile, fileName.str(), headerLine.str());

  // Append evolution data to file
  textLine.str("");
  textLine << timeNow << "\t" << NeighMaliciousListToString(maliciousList);
  AppendLineToFile(m_maliciousFile, fileName.str(), textLine.str());

  UpdateMaliciousStateControl(timeNow, recvAdd, maliciousList);

}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Statistics of FlySafePacketSink Application - Tracing malicious neighborhood evolution
 * @date Nov 23, 2023
 * 
 * @param path
 * @param timeNow Simulation time 
 * @param recvAdd Receiver node IPv4 address
 * @param maliciousList Malicious neighbor nodes information
 */
/*void Statistics::SenderMaliciousCallback(string path, double timeNow, Ipv4Address recvAdd,
                                        vector<ns3::MyTag::MaliciousNode> maliciousList)
{
  ostringstream filename;
  stringstream headerLine;
  ostringstream textLine;
  ostringstream fileName; 

  // *** Saving malicious neighborhood evolution data in node file ***

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "malicious_neighborhood_evolution_" << recvAdd
          << ".txt";
  
  // Append header line to file
  headerLine.str("");
  headerLine << "time" << "\t" << "size" << "\t" << "IP, state, recurrence, nNotfiers, notifiers" << endl;
  AppendHeaderToFile(m_maliciousFile, fileName.str(), headerLine.str());

  // Append evolution data to file
  textLine.str("");
  textLine << timeNow << "\t" << NeighMaliciousListToString(maliciousList);
  AppendLineToFile(m_maliciousFile, fileName.str(), textLine.str());

  UpdateMaliciousStateControl(timeNow, recvAdd, maliciousList);
}*/


/**
 * @author Vinicius - MiM
 * @brief Statistics of captured packets - Sniffer Callback
 * @note This callback is used to log sniffed packets information from sniffer nodes.
 * @date Jul 16, 2025  
 * 
 * @param path Path to the sniffer file
 * @param timeNow Current simulation time
 * @param senderPosition Position of the sender node
 * @param snifferIp IP address of the sniffer node
 * @param senderIp IP address of the sender node
 * @param receiverIp IP address of the receiver node
 * @param msgTag Message tag of the packet
 * @param neighList List of neighbor nodes with their information
 * @param messageTime Time when the message was sent
 */
void Statistics::SnifferCallback(string path, double timeNow, Vector senderPosition, 
                        Ipv4Address snifferIp, Ipv4Address senderIp, Ipv4Address receiverIp,
                        int msgTag, vector<ns3::MyTag::NeighborFull> neighList, 
                        double messageTime)
{
    ostringstream fileName;
    ostringstream headerLine;
    ostringstream textLine;
    ostringstream aux_neighString;
    string neighListString;
    string message;

    // Save sniffer traces to a file
    // File name: flysafe_sniffer_traces_<node>.txt
    fileName << m_folderToTraces.c_str() << "flysafe_sniffer_traces_"
             << snifferIp << ".txt";

    headerLine << "time" << "\t\t" << "senderIP" << "\t\t" << "receiverIP" << "\t\t" << "msgBroad" << "\t\t" << "msgId" << "\t\t" << "msgTrap" << "\t\t" 
              << "messageTime" << "\t\t" << "senderPosition"  << "\t\t" << "senderNeighborList" << endl;

    AppendHeaderToFile(m_sentFile, fileName.str(), headerLine.str());

    for(auto n : neighList)
    {
        aux_neighString << '\t' << n.ip << " : x: " << n.position.x << " y: " 
                        << n.position.y << " z: " << n.position.z << " hop: " << (int)n.hop << " ";
    }

    neighListString = aux_neighString.str();
    
    if (!neighListString.empty()) {
        neighListString.pop_back(); 
    }

    switch (msgTag) {
        case 0: message = "1\t\t0\t\t0"; break;
        case 1: message = "0\t\t1\t\t0"; break;
        case 2: message = "0\t\t0\t\t1"; break;
        default: message = ""; break;
    }

    textLine << timeNow << "\t\t\t" << senderIp << "\t\t" << receiverIp << "\t\t" << message << "\t\t"
            << messageTime << "\t\t" << senderPosition.x << ", " << senderPosition.y << ", " << senderPosition.z << "\t\t" << neighListString << endl;
    AppendLineToFile(m_sentFile, fileName.str(), textLine.str());
}

/**
 * @author Vinicius - MiM
 * @brief Statistics of altered packets - MiM Callback
 * @note This callback is used to log altered packets information from sniffer nodes.
 * @date Sep 22, 2025  
 * 
 * @param path Path to the sniffer file
 * @param timeNow Current simulation time
 * @param senderPosition Position of the sender node
 * @param snifferIp IP address of the sniffer node
 * @param senderIp IP address of the sender node
 * @param receiverIp IP address of the receiver node
 * @param msgTag Message tag of the packet
 * @param neighList List of neighbor nodes with their information
 * @param messageTime Time when the message was sent
 */
void Statistics::MiMCallback(string path, double timeNow, Vector senderPosition, Vector forgedPosition,
                        Ipv4Address snifferIp, Ipv4Address senderIp, Ipv4Address receiverIp,
                        int msgTag, vector<ns3::MyTag::NeighborFull> neighList, 
                        double messageTime)
{
    ostringstream fileName;
    ostringstream headerLine;
    ostringstream textLine;
    ostringstream aux_neighString;
    string neighListString;
    string message;

    m_totalMsgSent++;

    switch (msgTag) {
    case 0: // Broadcast - Searching neighbors
        m_broadcastSent++;
        break;

    case 1: // Unicast - Indentification sent to a neighbors search
        m_idMsgSent++;
        break;

    case 2: // Unicast - Indentification sent to a neighbors search
        m_trapMsgSent++;
        break;

    case 3: // Unicast - Special Id sent whether NL is empty
        m_specialIdMsgSent++;
        break;

    case 4: // Unicast - Suspect neighbor message
        m_suspiciousNeighborSent++;
        break;

    case 5: // Unicast - blocked neighbor message
        m_blockedNeighborSent++;
        break;

    case 6: // Unicast - Suspicious reduction message
        m_suspiciousReductionSent++;
        break;
    }

    // Save MiM traces to a file
    // File name: flysafe_MiM_traces_<node>.txt
    fileName << m_folderToTraces.c_str() << "flysafe_MiM_traces_"
             << snifferIp << ".txt";

    headerLine << "time" << "\t\t" << "senderIP" << "\t\t" << "receiverIP" << "\t\t" << "msgBroad" << "\t\t" << "msgId" << "\t\t" << "msgTrap" << "\t\t" 
              << "originalMessageTime" << "\t\t" 
              << "senderPosition"  << "\t\t" << "forgedPosition"  << "\t\t" << "senderNeighborList" << endl;

    AppendHeaderToFile(m_sentFile, fileName.str(), headerLine.str());

    for(auto n : neighList)
    {
        aux_neighString << '\t' << n.ip << " : x: " << n.position.x << " y: " 
                        << n.position.y << " z: " << n.position.z << " hop: " << (int)n.hop << " ";
    }

    neighListString = aux_neighString.str();
    
    if (!neighListString.empty()) {
        neighListString.pop_back(); 
    }

    switch (msgTag) {
        case 0: message = "1\t\t0\t\t0"; break;
        case 1: message = "0\t\t1\t\t0"; break;
        case 2: message = "0\t\t0\t\t1"; break;
        default: message = ""; break;
    }

    textLine << timeNow << "\t\t\t" << senderIp << "\t\t" << receiverIp << "\t\t" << message << "\t\t"
            << messageTime << "\t\t" 
            << senderPosition.x << ", " << senderPosition.y << ", " << senderPosition.z << "\t\t"
            << forgedPosition.x << ", " << forgedPosition.y << ", " << forgedPosition.z << "\t\t" << neighListString << endl;
    AppendLineToFile(m_sentFile, fileName.str(), textLine.str());
}

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Update state of malicious nodes
 * 
 * @date Dez 01, 2023 
 *
 * @param timeNow Event time
 * @param nodeIP IP of owner node 
 * @param maliciousList malicious node list from the node
 */
/*void Statistics::UpdateMaliciousStateControl(double timeNow, Ipv4Address nodeIP,
                                        vector<ns3::MyTag::MaliciousNode> maliciousList){
  
  ns3::Statistics::MaliciousControl tempMalicious;

  for (auto n :maliciousList) {
    if(IsInControlStateList(nodeIP, n.ip)){ // malicious node is already under control
      if ((int)GetMaliciousControleState(nodeIP, n.ip) == 0){ // Disregard blocked nodes
        if ((int)n.state == 1){ // Consider only malicious nodes changing state
          SetMaliciousBlockedTime(nodeIP, n.ip, timeNow);
          PrintMaliciousControlStateList();
        }
      }
    }
    else{
      tempMalicious.nodeIP = nodeIP;
      tempMalicious.maliciousIP = n.ip;
      tempMalicious.maliciousState = n.state;
      tempMalicious.tSuspicious = timeNow;
      if ((int)n.state == 0){ // suspect node
        tempMalicious.tBlocked = 9999.99;       
      }
      else { // blocked node
        tempMalicious.tBlocked = timeNow;
      }
      tempMalicious.avgTime = 0.0;
      m_maliciousControlState.push_back(tempMalicious);
    }
  }
}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Verify wether a malicious node is already under control by another node
 * 
 * @date Dez 01, 2023
 * 
 * @param maliciousIP malicious node IP
 * @param nodeIP node IP controlling malicious neighbors
 * 
 * @return true - Node under control
 * @return false - Node not under control
 */
/*bool Statistics::IsInControlStateList(Ipv4Address nodeIP, Ipv4Address maliciousIP){
  bool inList = false;

  for (auto n : m_maliciousControlState){
    if (n.nodeIP == nodeIP && n.maliciousIP == maliciousIP){
      inList = true;
      break;
    }
  }
  return inList;
}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Get malicious node state under control
 * 
 * @date Dez 01, 2023
 * 
 * @param maliciousIP malicious node IP
 * @param nodeIP node IP controlling malicious neighbors
 * 
 * @return uint8_t malicious node state (0 suspect, 1 blocked)
 */
/*uint8_t Statistics::GetMaliciousControleState(Ipv4Address nodeIP, Ipv4Address maliciousIP){
  uint8_t mState = 0;

  for (auto n :m_maliciousControlState){
    if (n.nodeIP == nodeIP && n.maliciousIP == maliciousIP) {
      mState = n.maliciousState;
      break;
    }
  }
  return mState;
}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Set malicious node blocked time
 * 
 * @date Dez 01, 2023
 * 
 * @param maliciousIP malicious node IP
 * @param nodeIP node IP controlling malicious neighbors
 * 
 * @param tBlocked blocked time
 */
/*void Statistics::SetMaliciousBlockedTime(Ipv4Address nodeIP, Ipv4Address maliciousIP, double tBlocked){

  for (MaliciousHandlerList::iterator i = m_maliciousControlState.begin (); i != m_maliciousControlState.end (); i++){
    if (i->nodeIP == nodeIP && i->maliciousIP == maliciousIP) {
      cout << nodeIP << " : " << tBlocked << " Statistics - Set Malicious Blocked Time for node " << maliciousIP << endl;
      i->maliciousState = 1;
      i->tBlocked = tBlocked;
      i->avgTime = i->tBlocked - i->tSuspicious;
      break;
    }
  }
}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/*void Statistics::PrintMaliciousControlStateList(){

    if((int)m_maliciousControlState.size() == 0){
    cout << "Statistics: Malicious control State list is empty!" << endl;
    }
    else{
      cout << "NodeIP" << "\t" << "MaliciousIP" << "\t" << "MaliciousState" << "\t" 
          << "tSuspicious" << "\t" << "tBlocked" << "\t" << "AvgTime" << endl;
      for (auto n : m_maliciousControlState){
        cout << n.nodeIP << "\t" << n.maliciousIP << "\t" << (int)n.maliciousState << "\t" 
          << n.tSuspicious << "\t" << n.tBlocked << "\t" << n.avgTime << endl;
      }
  }
}*/

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
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
/*bool Statistics::IsStateInList(uint8_t state){
  bool inList = false;

  for (auto n : m_maliciousControlState){
    if (n.maliciousState == state){
      inList = true;
      break;
    }
  }
  return inList;
}*/


/**
 * @brief Create and save the total number of sent and received messages in a log file 
 * @date Dez 4, 2023
 * 
 * @param simDate Simulation date and time string
 */
void Statistics::MessageResumeLogFile(string simDate){
  ostringstream textLine;
  ostringstream fileName; 

  fileName.str("");
  fileName << m_folderToTraces.c_str() << "total_messages_sent_and_received_"
          << simDate.substr(0, simDate.size() - 2).c_str() << ".txt";

  // Append evolution data to file
  textLine.str("");
  textLine << "type           " << "\t" << "sent" << "\t" << "received" << endl;
  textLine << "Broadcasts     " << "\t" << m_broadcastSent << "\t" << m_broadcastReceived << endl;
  textLine << "Identification " << "\t" << m_idMsgSent << "\t" << m_idMsgReceived << endl;
  textLine << "Trap           " << "\t" << m_trapMsgSent << "\t" << m_trapMsgReceived << endl;
  textLine << "SpecialId      " << "\t" << m_specialIdMsgSent << "\t" << m_specialIdMsgReceived << endl;
  textLine << "SuspNeighbors  " << "\t" << m_suspiciousNeighborSent << "\t" << m_suspiciousNeighborReceived << endl;
  textLine << "BlockedNeighbor" << "\t" << m_blockedNeighborSent << "\t" << m_blockedNeighborReceived << endl;
  textLine << "SuspReduction  " << "\t" << m_suspiciousReductionSent << "\t" << m_suspiciousReductionReceived << endl;
  textLine << "Total          " << "\t" << m_totalMsgSent << "\t" << m_totalMsgReceived << endl;

  AppendHeaderToFile(m_maliciousFile, fileName.str(), textLine.str());
}

/** 
 * @author Vinicius - MiM
 * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
 * @date Jul 14, 2025  
 */
/**
 * @brief Save control data from malicious nodes to log files - suspicious and blocked
 * @date Dez 4, 2023
 */
/*void Statistics::MaliciousControlResumeLogFile(string simDate){

  ostringstream textLine;
  ostringstream fileName; 
  
  if (IsStateInList(1)){ // Create a log file with blocked neighbors under control
    fileName.str("");
    fileName << m_folderToTraces.c_str() << "blocked_neighbors_control_"
            << simDate.substr(0, simDate.size() - 2).c_str() << ".txt";

    if((int)m_maliciousControlState.size() != 0){
      textLine << "NodeIP" << "\t" << "MaliciousIP" << "\t" << "MaliciousState" << "\t" 
          << "tSuspicious" << "\t" << "tBlocked" << "\t" << "AvgTime" << endl;
      for (auto n : m_maliciousControlState){
        if((int)n.maliciousState == 1) {
          textLine << n.nodeIP << "\t" << n.maliciousIP << "\t" << (int)n.maliciousState << "\t" 
            << n.tSuspicious << "\t" << n.tBlocked << "\t" << n.avgTime << endl;
        }
      }
      AppendHeaderToFile(m_maliciousFile, fileName.str(), textLine.str());
    }
  }

  if (IsStateInList(0)){ // Create a log file with suspicious neighbors under control
    textLine.str("");
    fileName.str("");
    fileName << m_folderToTraces.c_str() << "suspicious_neighbors_control_"
            << simDate.substr(0, simDate.size() - 2).c_str() << ".txt";

    if((int)m_maliciousControlState.size() != 0){
      textLine << "NodeIP" << "\t" << "MaliciousIP" << "\t" << "MaliciousState" << "\t" 
          << "tSuspicious" << endl;
      for (auto n : m_maliciousControlState){
        if((int)n.maliciousState == 0) {
          textLine << n.nodeIP << "\t" << n.maliciousIP << "\t" << (int)n.maliciousState << "\t" 
            << n.tSuspicious << endl;
        }
      }
      AppendHeaderToFile(m_maliciousFile, fileName.str(), textLine.str());
    }
  }
}*/


} // namespace ns3

/* ------------------------------------------------------------------------
 * End of Statistics class
 * ------------------------------------------------------------------------
 */
