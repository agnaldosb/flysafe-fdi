#include "utils.h"
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
std::vector<int> 
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