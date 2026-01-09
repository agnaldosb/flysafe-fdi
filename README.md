# Man in the Middle attack on Flysafe location system

This repository contains the implementation of the Man in the Middle attack on FlySafe using the NS-3 network simulator.

## Environment Configuration

The project has been tested and validated in the following environments:

1.  **Local Environment:**
    *   Operating System: Ubuntu 20.04
    *   Simulator: NS-3.34
    *   Processor: Intel Core i7-10750H (12 cores)
    *   RAM: 16 GB

2.  **Virtual Machine (VM):**
    *   VirtualBox Version: 7.2.2 r170484
    *   Operating System: Ubuntu 20.04
    *   Simulator: NS-3.34
    *   Processor: Intel Core i7-14700 (35 cores)
    *   RAM: 112 GB

**Default installation path:** `~/ns-allinone-3.34/`

## Installation

Follow the steps below to integrate the files from this repository into your NS-3.34 installation.

> **Note:** It is recommended to backup the original files of your `ns-3.34` directory before proceeding.

1.  **Root Directory:**
    *   Open the `ns-3.34/` folder of your NS-3 and add the files from the `ns-3.34/` folder of this repository.

2.  **Scratch Folder:**
    *   Open the `ns-3.34/scratch/` folder of your NS-3 and add the files from the `ns-3.34/scratch/` folder of this repository.

3.  **FlySafe Module:**
    *   Open the `ns-3.34/src/` folder of your NS-3 and add the entire `ns-3.34/src/flysafe/` folder from this repository.

4.  **Network Models:**
    *   Open the `ns-3.34/src/network/model/` folder of your NS-3 and replace the existing files with the corresponding files found in this same folder of this repository.

5.  **Wifi Models:**
    *   Open the `ns-3.34/src/wifi/model/` folder of your NS-3 and replace the existing files with the corresponding files found in this same folder of this repository.

## How to Run the Simulation

There are two main ways to run the simulation: via command line for a single execution or using the automation script for multiple executions.

### 1. Terminal Execution (Single Simulation)

To run a single instance of the simulation, use the `./waf` command from the `ns-3.34/` directory:

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