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
#include "ns3/mobility-module.h"
#include "ns3/gnuplot.h"

#include "sys/types.h"
#include "sys/stat.h"
#include "ns3/simulator.h"
#include "ns3/flysafe-tag.h"

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
std::vector<int> 
GenerateMaliciousNodes(int nNodes, int nMalicious);

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

void Create2DPlotFile ();
}