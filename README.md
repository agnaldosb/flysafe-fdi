#  FlySafe - Resilient UAVs location sharing service based on information freshness and opportunistic deliveries

Unmanned aerial vehicles (UAV) have been recognized as a versatile platform for various services. During the flight, these vehicles must avoid collisions to operate safely. In this way, they demand to keep spatial awareness, i.e., to know others in their coverage area. However, mobility and positioning hamper building UAV network infrastructure to support reliable basic services. Thus, such vehicles call for a location service with up-to-date information resilient to false location injection threats. This work proposes FlySafe, a resilient UAV location-sharing service that employs opportunistic approaches to deliver UAVs’ location. FlySafe takes into account the freshness of UAVs’ location to maintain their spatial awareness. Further, it counts on the age of the UAV’s location information to trigger device discovery. Simulation results showed that FlySafe achieved spatial awareness up to 94.15% of UAV operations, being resilient to false locations injected in the network. Moreover, the accuracy in device discovery achieved 94.53% with a location error of less than 2 m.

```
Batista, A. and dos Santos, A. L. (2025). Resilient uavs location sharing
service based on information freshness and opportunistic deliveries.
Pervasive and Mobile Computing, 111:102066.
doi: https://doi.org/10.1016/j.pmcj.2025.102066
```

This repository contains the implementation of FlySafe using the NS-3 network simulator.

## Environment Configuration

The project has been implemented and validated in the following environment:

1.  **Local Environment:**
    *   Operating System: macOS Catalina, version 10.15.7
    *   CPU: 2,9 GHz Intel Core i5 Quad-Core
    *   RAM: 8 GB 1600 MHz DDR3

2.  **Virtual Machine (VM):**
    *   VirtualBox Version: 6.1.14 r140239 (Qt5.6.3)
    *   Operating System: Ubuntu 20.04
    *   Simulator: NS-3.34
    *   RAM: 4 GB

## NS-3 installation

Install NS-3, version 3.34, according to the manual instructions

> **Note:** It is recommended to employ version 3.34. Other versions may not work properly.

Default path: `~/ns-allinone-3.34/`

## FlySafe installation

Follow the steps below to integrate the files from this repository into your NS-3.34 installation.

> **Note:** It is recommended to backup the original files of your `ns-3.34` directory before proceeding.

1.  **FlySafe Module:**
    *   Copy the entire `ns-3.34/src/flysafe/` folder from this repository to `ns-3.34/src/` folder of your NS-3. 

2.  **Network Models:**
    *   Copy the files from `ns-3.34/src/network/model/` folder from this repository to the same folder of your NS-3.
  
3.  **Scratch Folder:**
    *   Copy the file from the `ns-3.34/scratch/` folder from this repository to the `ns-3.34/scratch/` folder of your NS-3.

## FlySafe execution

There are two main ways to run the simulation: via command line for a single execution or using the automation script for multiple executions.

1. **Terminal Execution (Single Simulation)**
2. 
To run a single instance of the simulation, execute the `./waf` command from the `ns-3.34/` directory as follows:

```bash
./waf --run "scratch/flysafe.cc -nNodes=40 -runMode=R -nMalicious=1 -defense=true -mitigation=true" > result.txt
```

**Parameter Explanation:**

*   `-nNodes=40`: Defines the total number of nodes (UAVs) in the simulation.
*   `-runMode=R`: Defines the mobility/execution mode (e.g., 'R' for Random Way Point).
*   `-nMalicious=1`: Defines the number of malicious nodes present in the network.
*   `-defense=true`: Enables (`true`) or disables (`false`) security defense mechanisms (encryption).
*   `-mitigation=true`: Enables (`true`) or disables (`false`) attack mitigation mechanisms.
*   `> result.txt`: Redirects all simulation log output to the `result.txt` file. This facilitates viewing results and avoids cluttering the terminal with too much information.

```bash
./waf --run "scratch/flysafe.cc -nNodes=40 -runMode=R -nMalicious=1 -defense=true -mitigation=true" > result.txt
```

### 2. Script Execution (Multiple Simulations)

To perform test batteries, use the `run_flysafe.sh` file. This script runs the simulation sequentially the number of times you desire.

**How to configure and use:**

1.  Open the `run_flysafe.sh` file in a text editor.
2.  Locate the variables at the beginning of the file to configure your simulation:
    *   `TOTAL_RUNS`: Change this value to define how many times the simulation should run (e.g., `TOTAL_RUNS=35`).
    *   `SIM_COMMAND`: Change this line to define the simulation parameters (-nNodes -runMode -nMalicious -defense -mitigation), just as you would in the terminal.
3.  Grant execution permission to the script (if running for the first time):

```bash
chmod +x run_flysafe.sh
```

4.  Run the script in the terminal:

```bash
./run_flysafe.sh
```

The script will run the simulations one after another and organize the output files automatically.

## Results

The simulation generates results in the following structure:

1.  **Output Folder:** A folder named `flysafe_traces` is created inside the `ns-3.34/` directory (if it does not already exist).
2.  **Simulation Subfolders:** Inside `flysafe_traces`, a specific folder is created for each simulation run to store its results.

**File Location Behavior:**

*   **When running via Terminal (`./waf ...`):**
    The `result.txt` file (if redirected) and the `.pcap` files for each node are generated directly in the root `ns-3.34/` folder.

*   **When running via Script (`./run_flysafe.sh`):**
    The script automatically moves the `result.txt` and all `.pcap` files to the corresponding simulation folder inside `flysafe_traces`. This ensures that logs from all simulations are organized and stored correctly without overwriting each other.
