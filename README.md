# PWNTOOL - Hacker's Toolkit (Proof of Concept)

> **⚠️ PROJECT DISCONTINUED ⚠️**
> 
> This project has been stopped and is no longer under active development. The concept and codebase are now available for anyone to build upon, expand, or continue development. We encourage the community to fork this repository and take the project in new directions.
> 
> **For those interested in the alpha version we were building, please visit:** [pwnpanel repository](https://github.com/BytexGrid/pwnpanel)

## Overview

PWNTOOL is a proof-of-concept application designed as a Hacker's Toolkit, providing a graphical user interface for various cybersecurity tools. This project aims to demonstrate a simplified, interactive environment for common penetration testing and network analysis tasks.  
It serves as an early working prototype for an upcoming full-featured project called **pwnpanel**.

- **pwnpanel repo:** [https://github.com/BytexGrid/pwnpanel](https://github.com/BytexGrid/pwnpanel)
- **Concept by:** Muhammed Shafin P (@hejhdiss)
- **User interface design:** BytexGrid

## UI Design Credits

PWNTOOL is a working proof-of-concept implementation for an upcoming full-featured project named **pwnpanel**, currently under collaborative development. The visual user interface of this prototype was designed specifically for this project by **BytexGrid**, based on the original concept and architecture by **Muhammed Shafin P (@hejhdiss)**. This version demonstrates the early functionality and layout direction of pwnpanel, combining intuitive design with essential cybersecurity tool integration.


## Contributors

This project is contributed by **BytexGrid** and **Muhammed Shafin P (@hejhdiss)**.

## Current Features (Proof of Concept)

The current version of PWNTOOL focuses on robust integration with **Ettercap**, demonstrating core functionalities essential for managing cybersecurity tools.

### Ettercap Installation

The application provides a flexible approach to installing Ettercap, catering to different user preferences and system configurations. This is primarily managed through the "Ettercap Installation Options" popup, which offers several methods:

* **User Password Input:** A crucial step is the requirement for a sudo password. This is securely handled by piping the password to `sudo -S` before executing commands, ensuring the installation scripts run with necessary elevated privileges without direct password prompts in the terminal window itself.

* **Installation Methods:**

  * **"Install from Source (No Dependencies)":** Directly clones the Ettercap GitHub repository and attempts to build and install it using `make && make install`. This method assumes your system already has the necessary build tools and basic development libraries.

  * **"Install from Source (With All Dependencies)":** This is a more robust option. Before building Ettercap from source, it first uses `apt-get install -y` to ensure all predefined dependencies are installed on your system. This minimizes common build errors due to missing libraries.

  * **"Build from Source (With Selected Dependencies)":** This method offers fine-grained control, presenting a checklist of Ettercap's common dependencies. Users can select only those they believe are missing or specifically require, and the application then proceeds with an `apt-get install` for the chosen dependencies before compiling Ettercap from source.

  * **"Install via Apt (Auto Dependency Resolving)":** This is the simplest and often most reliable method for Debian/Ubuntu-based systems. It directly uses `apt update && apt install ettercap-graphical -y` to let the system's package manager handle the entire installation, including all necessary dependencies.

* **Real-time Output & Status:** All installation commands are executed in a separate thread, with their output streamed in real-time to a dedicated "Terminal Manager" tab within the application. This provides transparent feedback on the installation progress and any errors encountered.

  * **Installation Check (`which ettercap`):** After each installation attempt, the application performs a crucial check using the `which ettercap` command. This command searches the system's `PATH` environment variable for the `ettercap` executable.

    * If `which ettercap` returns a path (e.g., `/usr/sbin/ettercap`), it means the installation was successful, and the Ettercap executable is accessible from common system locations. The tool's status in the UI is updated to "Installed".

    * If `which ettercap` does not find the executable or returns an error, it indicates that Ettercap either failed to install correctly or is not in a standard location where the system can find it. This provides immediate feedback on the installation's outcome, and the tool's status remains "Not Installed".

* **"Open Ettercap Folder":** This utility function allows users to quickly navigate to the Ettercap installation directory in their system's file explorer.

### Ettercap Running

Once Ettercap is installed, the application provides ways to launch and interact with it:

* **"Graphical UI (Ettercap's Own Window)":** This option attempts to launch Ettercap's native graphical interface (`ettercap -G`) in a separate system window. PWNTOOL simply triggers its launch.

* **"Text-based (All commands in popup, output in new tab)":** This is a key feature for command-line interaction. It constructs a command using `ettercap -T` followed by any arguments provided by the user in the popup.

  * **Automated Prepending for New Tabs:** Crucially, the "Create New Tab" button in the "PWNTOOL Terminal Manager" also *automatically prepends* `ettercap -T` to whatever command you type. This means any new tab you open is implicitly an Ettercap text-mode session, ready for Ettercap commands. You can even leave the input field blank to simply open Ettercap in its interactive text mode.

  * The constructed command (e.g., `ettercap -T -M arp:remote // //`) is then executed in a new `TerminalTab`, providing real-time output within the application.

* **Centralized Tab Management:** The `TabbedTerminalManager` and `TerminalTab` classes are central to running commands:

  * **`TerminalTab`**: Each tab is an independent process, running the specified command. It captures `stdout` and `stderr` and displays them in a `ScrolledText` widget. It also includes "Ctrl+C" and "Ctrl+Z" buttons/bindings to send `SIGINT` (terminate) and `SIGTSTP` (suspend) signals to the running process, offering basic process control.

  * **`TabbedTerminalManager`**: This window hosts multiple `TerminalTab` instances, allowing users to run several Ettercap (or other) commands concurrently in isolated, monitorable environments.

## Planned Features (Future Development)

The current implementation provides a solid foundation with robust Ettercap integration. The long-term vision is to expand PWNTOOL into a comprehensive toolkit supporting **over 60 diverse cybersecurity tools**, simplifying complex command-line interactions through an intuitive GUI.

Here's a detailed vision for how this expansion will take place:

* **Enhanced Ettercap Interaction (Next Steps for Ettercap):**

  * **Specific Action Buttons:** Instead of requiring manual input for `ettercap -T` arguments, dedicated buttons for common Ettercap actions (e.g., "Start ARP Spoofing," "Start Sniffing," "List Hosts") will be added. Clicking these will auto-generate the necessary `ettercap -T` commands in the background.

  * **Configurable Ettercap Options:** For actions like ARP spoofing, users will be able to select target and gateway IPs from discovered hosts (once host discovery is implemented).

  * **Real-time Parsing:** For advanced Ettercap integration, we plan to parse the output of Ettercap to display information in a structured, more user-friendly way within the UI (e.g., a table of sniffed credentials, a list of active connections).

* **Full Integration of Other Tools (Scaling Beyond Ettercap):**

  * **New More Tools:** Prioritize implementing the full installation and running logic for these tools, similar to Ettercap's current level of support. This will involve defining their specific dependencies, installation paths, and common run commands.

  * **General Tool Management Module:** This is critical for efficiently adding 60+ tools. We will develop a more abstract and configurable way to define and manage tools. Instead of hardcoding logic for each tool, a `Tool` class or a flexible configuration system (e.g., using JSON files) will allow adding new tools by simply providing their `repo_url`, `install_commands`, `run_modes`, `dependencies`, and UI elements.

  * **Tool-Specific UI Panels:** For each major tool, dedicated UI panels within the content area will provide graphical controls and input fields for their most common functions, moving beyond relying solely on text-based command input.

* **Network Scanning & Host Discovery (Foundational for Many Tools):**

  * Integrate a robust network scanner (e.g., leveraging `nmap` via `subprocess`) to allow users to discover active hosts and open ports on their network.

  * Populate discovered hosts and service information into dropdowns or lists within tool-specific UIs (like Ettercap's ARP spoofing options), making it easier to select targets for various attacks and analyses.

* **Session Management & Persistence:**

  * Allow users to save and load their current terminal sessions, including the output and commands executed.

  * Implement comprehensive logging of all commands executed, their outputs, and any errors, potentially with filtering and search capabilities.

* **Enhanced User Experience & Feedback:**

  * More specific and user-friendly error messages when commands fail (e.g., "Ettercap failed to start: Check if network interfaces are up or if you have sufficient permissions," rather than generic Python errors).

  * Visual indicators (e.g., a red border around the terminal tab, status icons) when a process is running, completes successfully, or exits with an error code.

  * Progress bars or loading indicators for long-running installation or scanning tasks.

* **Security Considerations (As the Project Matures):**

  * While the `echo 'password' | sudo -S` method is common for simple scripts, for a more robust and "production-ready" tool, we will investigate more secure methods of handling `sudo` privileges. This might involve setting up specific `sudoers` configurations for commands used by the application, or even leveraging more advanced privilege escalation frameworks securely.

By expanding on these areas, your PWNTOOL concept can evolve into a truly comprehensive, user-friendly, and powerful toolkit for cybersecurity tasks, moving well beyond just Ettercap to manage a wide array of hacking utilities.

## Getting Started

### Prerequisites

* Python 3.x
* `tkinter` (usually comes with Python)
* `git` (for cloning repositories)
* `sudo` access (for installations)

### Installation & Usage (Linux/Unix-like systems)

1. **Clone the repository:**

   ```bash
   git clone https://github.com/hejhdiss/pwntool.git
   cd pwntool
   ```

2.  **Run the application:**

    ```bash
    python3 sample.py
    ```

## Tested Platform

- **Operating System:** Xubuntu 24.04.2 LTS
- **Virtualization Platform:** VMware Workstation 17
- **Notes:** The project has been tested and confirmed working in this environment. Compatibility with other Linux distributions or setups may vary.

## Community Development

Since this project is now discontinued, we encourage the community to:

- Fork this repository and continue development
- Build upon the existing concepts and architecture
- Create new implementations or improvements
- Share your work with the cybersecurity community

The codebase and concepts are available under the licenses below for anyone to use and expand upon.

## Advanced Feature Ideas for Community Development

The following are advanced feature concepts envisioned by the original concept creator (**Muhammed Shafin P**) that the community can implement. All these ideas are released under **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)** license and are free for anyone to build upon:

### **Full Package Manager Support**
- **Multi-Distribution Support:** Extend beyond `apt` to support `yum`, `dnf`, `pacman`, `zypper`, `portage`, `brew`, and other package managers
- **Package Manager Auto-Detection:** Automatically detect the system's package manager and use appropriate installation commands
- **Fallback Installation Methods:** If package manager installation fails, automatically fallback to source compilation or alternative installation methods
- **Package Version Management:** Allow users to choose specific versions of tools and manage upgrades/downgrades
- **Dependency Conflict Resolution:** Intelligent handling of package conflicts and dependency resolution

### **Operating System Auto-Detection & Parsing**
- **Comprehensive OS Detection:** Detect Linux distributions, Windows versions, macOS variants, and BSD systems
- **Architecture Detection:** Support for x86, x64, ARM, and other processor architectures
- **Kernel Version Parsing:** Extract and utilize kernel version information for compatibility checks
- **Distribution-Specific Optimizations:** Tailor installation and execution methods based on detected OS characteristics
- **Virtual Environment Detection:** Identify if running in Docker, VMs, WSL, or other virtualized environments

### **Advanced Tool Management System**
- **Tool Categories & Tagging:** Organize tools by categories (network scanning, web testing, forensics, etc.) with searchable tags
- **Tool Dependency Mapping:** Visual dependency graphs showing tool relationships and requirements
- **Custom Tool Integration:** Plugin system allowing users to add their own tools with JSON/YAML configurations
- **Tool Health Monitoring:** Regular checks for tool availability, updates, and functionality
- **Batch Operations:** Install, update, or remove multiple tools simultaneously

### **Enhanced Network Intelligence**
- **Network Topology Discovery:** Automatically map network infrastructure and device relationships
- **Service Fingerprinting:** Advanced service detection and version identification
- **Vulnerability Correlation:** Cross-reference discovered services with known vulnerability databases
- **Real-time Network Monitoring:** Continuous monitoring of network changes and new device detection
- **Geographic IP Mapping:** Visual representation of target locations and network paths

### **Target Management & Session Persistence**
- **Target Database:** Persistent storage of discovered hosts, services, and vulnerabilities
- **Session Templates:** Pre-configured attack/testing scenarios for common penetration testing workflows
- **Progress Tracking:** Visual indicators of testing progress across different targets and attack vectors
- **Collaborative Sessions:** Multi-user support for team-based penetration testing
- **Evidence Collection:** Automated screenshot, log, and output collection for reporting

### **Advanced Security & Privilege Management**
- **Privilege Escalation Framework:** Secure handling of administrative privileges without hardcoded passwords
- **Tool Sandboxing:** Isolation of potentially dangerous tools in containerized environments
- **Audit Logging:** Comprehensive logging of all actions for compliance and forensic purposes
- **Permission-Based Access:** User role management with different access levels to tools and features
- **Secure Communication:** Encrypted communication channels for remote tool execution

### **Modern User Experience Enhancements**
- **Dark/Light Theme Support:** Multiple UI themes with user customization options
- **Responsive Design:** Adaptive interface that works on different screen sizes and orientations
- **Drag-and-Drop Workflows:** Visual workflow builder for chaining multiple tools together
- **Real-time Collaboration:** Live sharing of terminal sessions and results between team members
- **Advanced Reporting:** Automated generation of professional penetration testing reports

### **Developer & Extension Framework**
- **Plugin Architecture:** Modular system allowing third-party tool integrations
- **API Framework:** RESTful API for remote control and integration with other security platforms
- **Scripting Support:** Built-in support for Python, Bash, and PowerShell script execution
- **Custom Command Macros:** User-defined command sequences for repetitive tasks
- **Tool Marketplace:** Community-driven repository for sharing custom tool configurations

### **Performance & Scalability**
- **Parallel Processing:** Multi-threaded execution of multiple tools simultaneously
- **Resource Management:** Intelligent CPU and memory allocation for resource-intensive operations
- **Cloud Integration:** Support for cloud-based tool execution and distributed scanning
- **Caching Systems:** Intelligent caching of tool outputs and network discovery results
- **Background Operations:** Non-blocking execution of long-running tasks with progress notifications

### **Ethical Use & Compliance Features**
- **Legal Compliance Checks:** Built-in warnings and confirmations for potentially illegal operations
- **Scope Limitation:** Configurable boundaries to prevent accidental testing of unauthorized targets
- **Evidence Chain of Custody:** Secure handling and documentation of collected evidence
- **Reporting Standards:** Support for industry-standard reporting formats (OWASP, NIST, etc.)
- **Permission Verification:** Integration with authorization systems to verify testing permissions

These feature concepts represent a comprehensive vision for what this toolkit could become. The community is encouraged to implement any or all of these ideas, either as extensions to the existing codebase or as inspiration for completely new implementations. All contributions should maintain the open-source spirit and give appropriate attribution to the original concept creator.

## Contributing

As a proof-of-concept that is now discontinued, the original development has ended. However, the community is welcome to fork the repository, make changes, and continue development independently. Feel free to create your own versions and share them with others.

## Licenses

### Software License (Code)

MIT License

Copyright (c) 2025 BytexGrid, Muhammed Shafin P

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### Concept License

Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)

This license applies to the *concept and design ideas* of PWNTOOL as conceived by Muhammed Shafin P.

You are free to:
* **Share** — copy and redistribute the material in any medium or format for any purpose, even commercially.
* **Adapt** — remix, transform, and build upon the material for any purpose, even commercially.

Under the following terms:
* **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **ShareAlike** — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

To view a copy of this license, visit <https://creativecommons.org/licenses/by-sa/4.0/>