# KubePWN: Kubernetes Security Audit Tool :shield:

![alt text](https://i.postimg.cc/BbSGZ5Fn/logo-rem.png)


<p align="left">
    <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" title="version" alt="version">
</p>

Welcome to **KubeSF**, An ultimate solution for Kubernetes security audits. KubeSF is a powerful security audit tool designed to assess the security of a Kubernetes clusters at namespace and pod level. By combining static and runtime analysis, KubeSF helps in identifing vulnerabilities and potential security risks, ensuring that the Kubernetes environment is robust and secure.

## Features

- **Namespace-level Security Audit:** Analyzes security configurations and permissions within Kubernetes namespaces to ensure proper isolation and access control.
  
- **Pod-level Security Assessment:** Evaluates security at the pod level by performing both static and runtime analysis on the pods.
 
- **Static Analysis:** Scans Kubernetes configuration files used to deploy a resource statically to identify misconfigurations and security loopholes. 
  
- **Runtime Analysis:** Performs real-time analysis on running pods and containers to detect runtime security threats and vulnerabilities.
  
- **Actionable Insights:** Receive detailed reports with actionable insights to remediate security issues and enhance the Kubernetes security posture.

## Getting Started

### Prerequisites

- **Kubernetes Cluster:** Ensure you have a running Kubernetes cluster where you have necessary permissions to perform security audits.

### Installation

1. **Clone the Repository:**
   ```
   git clone https://github.com/abhiabhi2306/KubeSF.git
   cd KubeSF
   ```

2. **Install the necessary packages**
   ```
   pip3 install -r requirements.txt
   cd web-ui
   pip3 install -r requirements.txt
   ```
3. **Install kubectl (if not already available in PATH)**
   ```
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   ```


   ### Usage
Single Mode (To run in a specific pod):

 `python3 main.py --single [namespace-name] [pod-name]`

All Mode (All namespaces will be audited):

   `python3 main.py --all-namespaces`

List Mode (Run in a list of namespaces):

   `python3 main.py --list namespaces.txt`

   the namespaces.txt file should be in the example format:

  ``` 
  demo-1 
  demo-2
  demo-3
   ```

   where demo-1, demo-2, demo-3 are namespace names.
   
### Future Roadmap

* Additional recommendations like possible exploits and fix recommendations
* Sensitive information in container images
* Taints and tolerations checks
* Additional privilege escalation checks
* Container escape test cases
* More concurrency-related features
* Report Generation (PDF)

### Contributors

* Abhishek S (@abhiabhi2306)
* Ajith Prabhu M (@agent-killjoy)
  
