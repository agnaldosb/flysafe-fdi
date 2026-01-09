/* ========================================================================
 * FlySafe Simulation
 *
 * Author:  Agnaldo de Souza Batista (asbatista@inf.ufpr.br)
 *
 * Date: Aug 08, 2022
 * Update: 
 * ========================================================================
 */
#include "sys/stat.h"
#include "sys/types.h"
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

#include "ns3/address-utils.h"
#include "ns3/address.h"
#include "ns3/application-container.h"
#include "ns3/applications-module.h"
#include "ns3/attribute.h"
#include "ns3/callback.h"
#include "ns3/core-module.h"
#include "ns3/data-rate.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"     // Vinicius - MiM - Jul 16, 2025 - To inspect IP headers in the sniffer
#include "ns3/log.h"
#include "ns3/mobility-module.h"
#include "ns3/names.h"
#include "ns3/net-device.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/node-container.h"
#include "ns3/node.h"
#include "ns3/ns2-mobility-helper.h"
#include "ns3/object-factory.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/stats-module.h"
#include "ns3/string.h"
#include "ns3/tag.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/traced-callback.h"
#include "ns3/udp-header.h"       // Vinicius - MiM - Jul 16, 2025 - To inspect UDP headers in the sniffer
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-socket.h"
#include "ns3/uinteger.h"
#include "ns3/wifi-mac-header.h"  // Vinicius - MiM - Jul 16, 2025 - To inspect MAC headers in the sniffer
#include "ns3/wifi-module.h"
#include "ns3/wifi-phy.h" // Vinicius - MiM - Jul 17, 2025
#include "ns3/rng-seed-manager.h"

// Created files
#include "ns3/flysafe-onoff.h"
#include "ns3/flysafe-packet-sink.h"
#include "ns3/flysafe-tag.h"
#include "ns3/flysafe-statistics.h"
#include "ns3/utils.h"


/*
 * Model:
 *
 * 	   WiFi (Ad hoc)
 *  Node1		  Node2
 *  Source		  Sink
 *   (*) --------> (*)
 *  10.0.0.1	 10.0.0.2
 *  OnOff		 OnOff		>> Search neighbors
 * PacketSink	 PacketSink	>> Receive messages and answers
 * StatusOn		 StatusOn	>> Controls emergency situation
 */

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("ScenarioFlySafe_v1");

/* ========================================================================
 * Experiment
 * ========================================================================
 */

void FlySafeSimulation(uint32_t nNodes, string simDate, char runMode, int nMalicious, bool defense, bool mitigation) { // Vinicius - MiM - Nov 12, 2025 - Added defense parameter

  string tracesFolder;
  string scenarioSimFile;
  NodeContainer::Iterator it;
  uint16_t port = 9;
  double start = 0.0;
  double stop = 1200.0;
  string traceFile = "scratch/traces2d.txt";
  string label;

  // Creating and defining seeds to be used
  unsigned seed = chrono::system_clock::now().time_since_epoch().count();
  //default_random_engine e(seed);
  srand(seed);
  RngSeedManager::SetSeed(seed);

  //----------------------------------------------------------------------------------
  // Create a folder for traces (flysafe_traces) inside ns3 folder
  //----------------------------------------------------------------------------------

  tracesFolder = "flysafe_traces/";
  errno = 0;
  int folder =
      mkdir(tracesFolder.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  if (folder < 0 && errno != EEXIST)
    cout << "FlySafe: Fail creating folder for traces!" << endl;

  tracesFolder.append(simDate.substr(0, simDate.size() - 2).c_str());
  tracesFolder.append("/");

  // Creates a folder for specific simulation
  folder = mkdir(tracesFolder.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  if (folder == -1)
    cout << "FlySafe: Fail creating sub folder for specific traces!" << folder << endl;

  ostringstream convert;
  convert << tracesFolder.c_str() << "flysafe_simulation_scenario_"
          << simDate.substr(0, simDate.size() - 2).c_str() << ".txt";
  scenarioSimFile = convert.str();

  // Create a string stream to store simulation scenario data
  stringstream fileSim;

  // Save start seed in file
  fileSim << "Start seed: " << seed << endl << endl;

  fileSim << "Security Defenses: " << (defense ? "Enabled" : "Disabled") << endl << endl; // Vinicius - MiM - Nov 12, 2025 - Log defense status
  fileSim << "Mitigation Mechanism: " << (mitigation ? "Enabled" : "Disabled") << endl << endl; // Vinicius - MiM - Dec 01, 2025 - Log mitigation status

  MobilityHelper mobilityUAVs;

  // mobilityUAVs.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
  //                 "Mode", StringValue ("Time"),
  //                 "Time", StringValue ("1s"),
  //                 "Speed", StringValue ("ns3::UniformRandomVariable[Min=1.0|Max=40.0]"),
  //                 "Bounds", StringValue ("0|600|0|600"));
  // mobilityUAVs.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
  //                   "X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=600.0]"),
  //                   "Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=600.0]"),
  //                   "Z", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1.0]"));

  mobilityUAVs.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                  "Mode", StringValue ("Time"),
                  "Time", StringValue ("0.5s"),
                  "Speed", StringValue ("ns3::UniformRandomVariable[Min=20.0|Max=20.0]"),
                  "Bounds", StringValue ("0|1500|0|1500"));
  mobilityUAVs.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                    "X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"),
                    "Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"),
                    "Z", StringValue ("ns3::UniformRandomVariable[Min=91.0|Max=91.0]"));

  NodeContainer Nodes;
  // Create nodes to be used during simulation
  Nodes.Create(nNodes);
  
  // Save Mobility stttings
  fileSim << "Mobility Model settings: ns3::RandomWalk2dMobilityModel" << endl; 
  fileSim << "Mode: Time" << endl;
  fileSim << "Mode: 0.5s" << endl;
  fileSim << "Speed: Min=20.0|Max=20.0" << endl;
  fileSim << "Bounds: 0|1500|0|1500" << endl << endl;

  fileSim << "PositionAllocator settings: ns3::RandomBoxPositionAllocator" << endl; 
  fileSim << "X: Min=0.0|Max=1500.0" << endl;
  fileSim << "Y: Min=0.0|Max=1500.0" << endl;
  fileSim << "Z: Min=91.0|Max=91.0" << endl << endl;

  //----------------------------------------------------------------------------------
  // Confiure mobility mode according to the selected runMode
  // R: Random Way Point only
  // M: RWP + first node with real mobility
  //----------------------------------------------------------------------------------
  if (runMode == 'R'){
    cout << "Mobility mode: Random Way Point only\n" << endl;
    fileSim << "Mobility mode: Random Way Point only" << endl << endl;
    
    // Install mobility RWP in all nodes
    mobilityUAVs.Install(Nodes);
  } else {
    cout << "Mobility mode: RWP + first node with real mobility\n" << endl;
    fileSim << "Mobility mode: RWP + first node with real mobility" << endl << endl;

    // Load real traces to the first node
    // Import node's mobility from the trace file
    // Necessary to use a helper from NS2
    Ns2MobilityHelper ns2 = Ns2MobilityHelper(traceFile);
    it = Nodes.Begin();
    // Install node's mobility only in the first node
    ns2.Install(it,it);
    //ns2.Install(Nodes.Get(0));
    // Install RWP from the second node 
    for (it = Nodes.Begin()+1; it != Nodes.End(); it++) {
      mobilityUAVs.Install(*it);
    }
  }

  NS_LOG_INFO("FlySafe - Setting parameters to " + label + " mode...");

  //----------------------------------------------------------------------------------
  // Set wifi network - Ad Hoc
  //----------------------------------------------------------------------------------

  NS_LOG_INFO("FlySafe - Configuring wifi network (Ad Hoc)...");

  // Create wifi network 802.11a

  WifiHelper wifi;
  
  // wifi.SetStandard(WIFI_PHY_STANDARD_80211a);
  // By default, WifiHelper will use WIFI_STANDARD_80211a
  
  // 80211a configuration
  //wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
  //                             StringValue("OfdmRate6Mbps"), "RtsCtsThreshold",
  //                             UintegerValue(0));

  // 80211n configuration with 2.4GHz, best range
  wifi.SetStandard (WIFI_STANDARD_80211n_2_4GHZ);
  Config::SetDefault ("ns3::LogDistancePropagationLossModel::ReferenceLoss", DoubleValue (40.046));
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager","DataMode", StringValue ("HtMcs3"),
                                "ControlMode", StringValue ("HtMcs3"));

  // MAC Layer non QoS
  WifiMacHelper wifiMac;
  wifiMac.SetType("ns3::AdhocWifiMac");

  // PHY layer
  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
  wifiPhy.SetChannel(wifiChannel.Create());

  // Creating and installing netdevices in all nodes
  NetDeviceContainer devices;
  devices = wifi.Install(wifiPhy, wifiMac, Nodes);

  // Create and install Internet stack protocol
  InternetStackHelper stack;
  stack.Install(Nodes);

  // Set IPv4 address to node's interfaces
  Ipv4AddressHelper address;
  Ipv4InterfaceContainer NodesInterface;
  address.SetBase("192.168.1.0", "255.255.255.0");

  NodesInterface = address.Assign(devices);

  //----------------------------------------------------------------------------------
  // Generate and distribute asymmetric keys for all nodes - Vinicius - MiM
  //----------------------------------------------------------------------------------
  
  if (defense) {
    NS_LOG_INFO("FlySafe - Generating and distributing asymmetric keys...");
    
    std::vector<std::pair<std::string, std::string>> allKeys = GenerateAsymmetricKeys(nNodes);

    // Security check: Ensure the key generator worked
    if (allKeys.size() != nNodes) {
        NS_LOG_ERROR("Failed to generate keys! Expected " << nNodes << " keys, but got " << allKeys.size() << ". Aborting.");
        return; // Exit simulation
    }

    // Distribute the key pairs (private/public) to each node
    for (uint32_t i = 0; i < nNodes; i++) {
        Ptr<Node> node = Nodes.Get(i);
        std::string privateKeyPEM = allKeys[i].first;
        std::string publicKeyPEM = allKeys[i].second;

        // Set keys in the Node object
        node->SetPrivateKey(privateKeyPEM);
        node->SetPublicKey(publicKeyPEM);
    }
  }

  //----------------------------------------------------------------------------------
  // Install applications
  //----------------------------------------------------------------------------------

  NS_LOG_INFO("FlySafe - Install applications...");

  //----------------------------------------------------------------------------------
  // Setting all nodes as honest
  //----------------------------------------------------------------------------------

  int i;

  for(i=0; i < (int)nNodes; i++) {
     Nodes.Get(i)->SetState(0);
  }



  //----------------------------------------------------------------------------------
  // Generate malicious nodes
  //----------------------------------------------------------------------------------
  
  /** 
     * @author Vinicius - MiM
     * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
     * @date Oct 06, 2025
     */
  //std::vector<int> malicious = GenerateMaliciousNodes(nNodes, nMalicious);
  std::vector<int> malicious = GenerateMaliciousNodes(Nodes, nMalicious);
  fileSim << "Malicious nodes: " << convertIntVectorToString(malicious) << endl << endl;
  NS_LOG_INFO("FlySafe - Generate and set malicious nodes...");

  for(i=0; i < nMalicious; i++) {
     Nodes.Get(malicious[i])->SetState(1);
     cout << "Setting node 192.168.1." << malicious[i]+1 << " as malicious!" << endl; // << endl;
  }

  //----------------------------------------------------------------------------------
  // Set Sink application
  //----------------------------------------------------------------------------------

  Address SinkBroadAddress(InetSocketAddress(Ipv4Address::GetAny(),
                                             port)); // SinkAddress for messages
  
  NS_LOG_INFO("FlySafe - Install Sink application...");

  //cout << "FlySafePacketSink - Address: " << Ipv4Address::GetAny() << endl;

  //----------------------------------------------------------------------------------
  // Set Sink application
  //----------------------------------------------------------------------------------
  // Install Sink in all nodes
  i = 0;
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    Ptr<FlySafePacketSink> SinkApp = CreateObject<FlySafePacketSink>();
    (*it)->AddApplication(SinkApp);

    SinkApp->SetStartTime(Seconds(start));
    SinkApp->SetStopTime(Seconds(stop));
    /** 
     * @author Vinicius - MiM
     * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
     * @date Jul 14, 2025  
     */
    /*if((*it)->GetState() == 0){ //Ordinary node
      SinkApp->Setup(SinkBroadAddress, 1, 9999.99); // 1 -> UDP, 2 -> TCP
    }
    else {
      SinkApp->Setup(SinkBroadAddress, 1, 6.0); // 1 -> UDP, 2 -> TCP
      //cout << "PacketSink - Configure node " << i << " malicious start time!"  << endl;
    }*/
    SinkApp->Setup(SinkBroadAddress, 1, 9999.99, defense, mitigation, 20.0, 115.0); // Vinicius - MiM - All nodes are ordinary / set defense active or not
    i++;
  }


  //----------------------------------------------------------------------------------
  // Set OnOff application
  //----------------------------------------------------------------------------------

  // Install OnOff in all nodes

  NS_LOG_INFO("FlySafe - Install OnOff application...");
  
  i = 0;
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {

    Ptr<FlySafeOnOff> OnOffApp = CreateObject<FlySafeOnOff>(); 
    (*it)->AddApplication(OnOffApp); 
    
    /** 
     * @author Vinicius - MiM
     * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
     * @date Jul 14, 2025  
     */
    /*if((*it)->GetState() == 0){ //Ordinary node
      OnOffApp->Setup(InetSocketAddress(Ipv4Address("255.255.255.255"), 9),
                    1, 9999.99); // 1 -> UDP, 2 -> TCP
    }
    else {
      OnOffApp->Setup(InetSocketAddress(Ipv4Address("255.255.255.255"), 9),
                    1, 6.0); // 1 -> UDP, 2 -> TCP
      //cout << "OnOff - Configure node " << i << " malicious start time!"  << endl;
    }*/
    OnOffApp->Setup(InetSocketAddress(Ipv4Address("255.255.255.255"), 9),
                    1, 9999.99, defense); // Vinicius - MiM - All nodes are ordinary / set defense active or not
    i++;

    // Set to send to broadcast address
    //OnOffApp->Setup(InetSocketAddress(Ipv4Address("255.255.255.255"), 9),
    //                1, 9999.99); // 1 -> UDP, 2 -> TCP
    
    //OnOffApp->Setup(SinkBroadAddress,1);
    OnOffApp->SetAttribute(
        "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
    OnOffApp->SetAttribute(
        "OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
    OnOffApp->SetAttribute("DataRate", StringValue("500kb/s"));
    OnOffApp->SetAttribute("PacketSize", UintegerValue(6));

    OnOffApp->SetStartTime(Seconds(start));
    OnOffApp->SetStopTime(Seconds(stop));
    start += 0.2; // Avoid to start all the OnOff together
  }

  // Create statistics object to collect several data of interest
  Statistics statistics(simDate, tracesFolder.c_str());

  //----------------------------------------------------------------------------------
  // Saving simulation scenario data
  //----------------------------------------------------------------------------------

  // Create a file and save simulation scenario data
  NS_LOG_INFO("FlySafe - Saving simulation scenario data to " + tracesFolder + "...");


  CreateSimScenarioFile(scenarioSimFile.c_str(), simDate, fileSim.str());


  //----------------------------------------------------------------------------------
  // Callback configuration
  //----------------------------------------------------------------------------------
  NS_LOG_INFO("FlySafe - Configuring callbacks...");

  // Callback Trace to Collect data from FlySafePacketSink Application
  // Installed in all nodes
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    uint32_t nodeID = (*it)->GetId();
    ostringstream paramTest;
    paramTest << "/NodeList/" << (nodeID)
              << "/ApplicationList/*/$ns3::FlySafePacketSink/SinkTraces";
    Config::Connect(paramTest.str().c_str(),
                    MakeCallback(&Statistics::ReceiverCallback, &statistics));
  }

  /** 
   * @author Vinicius - MiM
   * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
   * @date Jul 14, 2025  
   */
  // Callback Trace to Collect data maliciuous nodes evolution in FlySafePacketSink Application
  // Installed in all nodes
  //for (it = Nodes.Begin(); it != Nodes.End(); it++) {
  //  uint32_t nodeID = (*it)->GetId();
  //  ostringstream paramTest;
  //  paramTest << "/NodeList/" << (nodeID)
  //            << "/ApplicationList/*/$ns3::FlySafePacketSink/SinkMaliciousTraces";
  //  Config::Connect(paramTest.str().c_str(),
  //                  MakeCallback(&Statistics::ReceiverMaliciousCallback, &statistics));
  //}


  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    uint32_t nodeID = (*it)->GetId();
    ostringstream paramTest;
    paramTest << "/NodeList/" << (nodeID)
              << "/ApplicationList/*/$ns3::FlySafePacketSink/TxTraces";
    Config::Connect(paramTest.str().c_str(),
                    MakeCallback(&Statistics::SenderCallback, &statistics));
  }

  // Callback Trace to Collect data from FlySafeOnOff Application
  // Installed in all nodes
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    uint32_t nodeID = (*it)->GetId();
    ostringstream paramTest;
    paramTest << "/NodeList/" << (nodeID)
              << "/ApplicationList/*/$ns3::FlySafeOnOff/TxTraces";
    Config::Connect(paramTest.str().c_str(),
                    MakeCallback(&Statistics::SenderCallback, &statistics));
  }

  // Callback Trace to Collect data from FlySafeOnOff Application
  // when nodes are stopped
  // Installed in all nodes
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    uint32_t nodeID = (*it)->GetId();
    ostringstream paramTest;
    paramTest << "/NodeList/" << (nodeID)
              << "/ApplicationList/*/$ns3::FlySafeOnOff/StopTraces";
    Config::Connect(paramTest.str().c_str(),
                    MakeCallback(&Statistics::ReceiverCallback, &statistics));
  }

  // Callback Trace to Collect data from FlySafeOnOff Application
  // when nodes are stopped
  // Installed in all nodes
  for (it = Nodes.Begin(); it != Nodes.End(); it++) {
    uint32_t nodeID = (*it)->GetId();
    ostringstream paramTest;
    paramTest << "/NodeList/" << (nodeID)
              << "/ApplicationList/*/$ns3::FlySafeOnOff/EmptyNLTraces";
    Config::Connect(paramTest.str().c_str(),
                    MakeCallback(&Statistics::EmptyNLCallback, &statistics));
  }

  /** 
   * @author Vinicius - MiM
   * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
   * @date Jul 14, 2025  
   */
  // Callback Trace to Collect data from FlySafeOnOff Application
  // when nodes are stopped
  // Installed in all nodes
  //for (it = Nodes.Begin(); it != Nodes.End(); it++) {
  //  uint32_t nodeID = (*it)->GetId();
  //  ostringstream paramTest;
  //  paramTest << "/NodeList/" << (nodeID)
  //            << "/ApplicationList/*/$ns3::FlySafeOnOff/TxMaliciousTraces";
  //  Config::Connect(paramTest.str().c_str(),
  //                  MakeCallback(&Statistics::SenderMaliciousCallback, &statistics));
  //}
  
  wifiPhy.EnablePcap("flysafe", Nodes); //false);

  /** 
   * @author Vinicius - MiM
   * @note Configure chosen malicious nodes to act as sniffers
   * @date Jul 16, 2025  
  */
  if (!malicious.empty()) { 
      
      NS_LOG_INFO("FlySafe - Configuring " << malicious.size() << " designated malicious node(s) as sniffer(s)...");
      cout << endl;
      for (int snifferNodeId : malicious) {
        
          Ptr<Node> snifferNode = Nodes.Get(snifferNodeId);
          Ptr<NetDevice> snifferDevice = snifferNode->GetDevice(0); 

          ostringstream oss;
          oss << "/NodeList/" << snifferNode->GetId() << "/DeviceList/0/$ns3::WifiNetDevice/Phy/MonitorSnifferRx";
          Config::Connect(oss.str(), MakeBoundCallback(&ProcessSniffedPacket, &statistics, snifferNode));
                      
          wifiPhy.EnablePcap("sniffer-node-" + std::to_string(snifferNode->GetId()), 
                            snifferNode->GetId(), 
                            snifferDevice->GetIfIndex(), 
                            true); 
          cout << "Setting node " << snifferNode->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << " as sniffer!" << endl;           
      } 
  } else {
      NS_LOG_INFO("FlySafe - No node configured as sniffer (nMalicious = 0)...");
  }

  if (defense) {
      NS_LOG_INFO("FlySafe - Cryptography is ENABLED...");
  } else {
      NS_LOG_INFO("FlySafe - Cryptography is DISABLED...");
  }
  if (mitigation) {
      NS_LOG_INFO("FlySafe - Mitigation mechanisms are ENABLED...");
  } else {
      NS_LOG_INFO("FlySafe - Mitigation mechanisms are DISABLED...");
  }

  //Network Animation using NetAnim.
  AnimationInterface anim("flysafe.xml");
  uint32_t droneRes = anim.AddResource ("../ns-3.34/scratch/drone_image.png");
  uint32_t maliciousRes = anim.AddResource ("../ns-3.34/scratch/malicious_image.png");
  for (uint32_t i = 0; i < Nodes.GetN (); ++i) {
    anim.UpdateNodeImage (Nodes.Get(i)->GetId (), droneRes);
    anim.UpdateNodeSize  (Nodes.Get(i)->GetId (), 75, 75);
  }
  for (int snifferNodeId : malicious) {
    anim.UpdateNodeImage (Nodes.Get(snifferNodeId)->GetId (), maliciousRes);
  }


  //----------------------------------------------------------------------------------
  // Start / Stop simulation
  //----------------------------------------------------------------------------------

  NS_LOG_INFO("FlySafe - Starting Simulation...");
  Simulator::Stop(Seconds(stop));
  Simulator::Run();
  Simulator::Destroy();

  //----------------------------------------------------------------------------------
  // Save amount of messages and control data to log files
  //----------------------------------------------------------------------------------

  statistics.MessageResumeLogFile(simDate);
  /** 
   * @author Vinicius - MiM
   * @note Reason for comment: Malicious UAV Implementation - Used for injection of fake data
   * @date Jul 14, 2025  
   */
  //statistics.MaliciousControlResumeLogFile(simDate);

  //----------------------------------------------------------------------------------
  // Tracing
  //----------------------------------------------------------------------------------

  // Code here!!
}





/* ------------------------------------------------------------------------
 * End of Experiment
 * ------------------------------------------------------------------------
 */

/* ========================================================================
 * Main
 * ========================================================================
 */

int main(int argc, char *argv[]) {
  uint32_t nNodes = 0;
  string simTime;
  char runMode;
  int nMalicious;
  bool defense = true; // Vinicius - MiM - Nov 12, 2025 - Defense mechanisms enabled by default
  bool mitigation = true; // Vinicius - MiM - Dec 01, 2025 - Mitigation mechanisms enabled by default
  
  
  set<char> runModeSet = {'R','M'};

  // runMode = S: Standard Execution

  LogComponentEnable("ScenarioFlySafe_v1", LOG_LEVEL_INFO);

  NS_LOG_INFO("FlySafe - Initializing...");

  CommandLine cmd;
  cmd.AddValue("nNodes", "Number of node devices", nNodes);
  cmd.AddValue("runMode", "Mode of simulation execution", runMode);
  cmd.AddValue("nMalicious", "Number of malicious nodes", nMalicious);
  cmd.AddValue("defense", "Enable or disable security defenses (default: true)", defense); // Vinicius - MiM - Nov 12, 2025
  cmd.AddValue("mitigation", "Enable or disable mitigation mechanisms (default: true)", mitigation); // Vinicius - MiM - Dec 01, 2025
  cmd.Parse(argc, argv);

  if (nNodes < 2 ) {
    cout << "FlySafe - Error: Number of nodes must be greater than 1!\n" 
         << "Example: ./waf --run \"scratch/flysafe.cc -nNodes=4 -runMode=R\" > results.txt"
         << endl;
    NS_LOG_INFO("FlySafe - Done!...");
    return 1;
  } else if (nMalicious >= (int)nNodes){
    cout << "FlySafe - Error: Number of malicious nodes must less than than number of nodes!\n" 
         << "Example: ./waf --run \"scratch/flysafe.cc -nNodes=4 -runMode=R -nMalicious=1\" > results.txt"
         << endl;
    NS_LOG_INFO("FlySafe - Done!...");
    return 1;    
  
  } else {
    if (runModeSet.find(runMode) == runModeSet.end()) {
      cout << "FlySafe - Error: runMode supports the following:\n"
          << "\t- R: RWP 2D mobility only\n" 
          << "\t- M: RWP + first node with real mobility\n" << endl;
      NS_LOG_INFO("FlySafe - Done!...");
      return 1;
    }
  }

  simTime = GetTimeOfSimulationStart();

  //SeedManager::SetRun(2); // update seed to n executions

  cout << "Start of simulation: " << simTime.c_str() << endl;

  FlySafeSimulation(nNodes, simTime, runMode, nMalicious, defense, mitigation); // Vinicius - MiM - Nov 12, 2025 - Added defense parameter

  cout << "End of simulation: " << GetTimeOfSimulationStart().c_str() << endl;
  //Create2DPlotFile();

  NS_LOG_INFO("FlySafe - Done!...");

  return 0;
}

/* ------------------------------------------------------------------------
 * End of Main
 * ------------------------------------------------------------------------
 */