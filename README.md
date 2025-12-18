# WAZUH Process Tree Viewer (WPTV)
WAZUH Process Tree Viewer (WPTV) is a high-performance forensic visualization tool designed for the Wazuh ecosystem. It transforms raw Windows Security Logs (Event ID 4688) into interactive, draggable relationship graphs, enabling analysts to trace process lineages (Parent-Child) during Threat Hunting and Incident Response (IR) operations.

--------------------------------
> Version: 1.0 
> Last Updated: 2025-12-18
> Wazuh Compatibility: 4.14.1
> OpenSearch Dashboards: 2.19.3

![WPTV Main Dashboard](img/wazuh_process_tree_viewer.png)

## Project Architecture & File Structure:
1. server.py: Entrypoint. The Flask server that handles web routing and serves the frontend.
2. process_tree_api.py: The Core API. Contains extensive logic for data handling and graph structure preparation.
3. logic.py: Backend Logic. Handles alerts.json parsing, UTC timezone normalization, and Hex-to-Dec conversion.
4. public/index.html: Frontend. Interactive UI powered by vis-network.js with Dark Mode support.
5. requirements.txt: Dependencies. Required Python libraries for the environment.
6. wazuh-process-tree.service: SystemD Configuration. Template for background service management.

🛠️ Installation & Setup
## 1. Directory Structure
We recommend deploying the plugin within the Wazuh dashboard directory:
* mkdir -p /usr/share/wazuh-dashboard/plugins/process_tree_api 
* cd /usr/share/wazuh-dashboard/plugins/process_tree_api
> Clone the repository files here < 

## 2. Virtual Environment
Isolate dependencies to prevent system conflicts:
* python3 -m venv venv
* source venv/bin/activate
* pip install -r requirements.txt

## 3. Critical Permissions
The service must be able to read Wazuh logs and be executed by the dashboard user:
* chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/process_tree_api
* chmod -R 755 /usr/share/wazuh-dashboard/plugins/process_tree_api

## Service Management (SystemD)
To ensure WPTV starts automatically and remains highly available, use the provided SystemD configuration.
> Create the service file:
* sudo nano /etc/systemd/system/wazuh-process-tree.service

[Unit]
Description=Wazuh Process Tree View (PTV)

After=network.target

[Service]
Type=simple
User=wazuh-dashboard
WorkingDirectory=/usr/share/wazuh-dashboard/plugins/process_tree_api
ExecStart=/usr/share/wazuh-dashboard/plugins/process_tree_api/venv/bin/python3 server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target

## Management Commands:
* (Start): # sudo systemctl start wazuh-process-tree
* (Stop): # sudo systemctl stop wazuh-process-tree
* (Check Status): # sudo systemctl status wazuh-process-tree
* (Enable on Boot): # sudo systemctl enable wazuh-process-tree

## Usage Guide
HEY! Ensure Audit Process Creation is enabled on Windows targets to generate Event ID 4688.
> Go to: https://medium.com/@k1sh/habilitando-e-monitorando-a-auditoria-de-cria%C3%A7%C3%A3o-de-processo-com-wazuh-eventid-4688-com-o-7893524baff5

* Access the tool via browser: https://<YOUR_WAZUH_IP>:5000
* Enter the Agent ID (e.g., 001).
* https://<YOUR_WAZUH_IP>:5000/?agent_id=001
* Select the Time Range (WPTV uses UTC comparison for forensic precision).
* Click Analisar Agente (Analyze Agent).

## Special Thanks

* I would like to extend my sincere gratitude to **AwwalQuan** for their invaluable support, guidance, and contributions during the development of this project. And also to the **Wazuh Community** for providing an amazing open-source platform for security research.

## Contributors:
[@AwwalQuan](https://github.com/AwwalQuan)

[@wazuh](https://github.com/wazuh)

## License
Distributed under the MIT License. See LICENSE for more information.
