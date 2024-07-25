# T1136.001 Create Account: Local Account
Adversaries may create a local account to maintain access to victim systems. These accounts are configured for users, remote support, services, or administration on a single system. Commands like net user /add on Windows or dscl -create on macOS can be used to create such accounts.
![T1136](https://github.com/user-attachments/assets/e9ff00c8-b8c2-4733-b326-492fb6e5f8ae)
# HOW TO DETECT T1136.001
MITRE suggests monitoring executed commands (DS0017) such as net user /add, useradd, dscl -create, and kubectl create serviceaccount, and process creations (DS0009) like net.exe. Additionally, audit new user and service accounts (DS0002) to detect suspicious activities, using events like Windows Event ID 4720.
![Detection](https://github.com/user-attachments/assets/94585269-648e-48d9-9c8e-ae5e1d3ac0b7)
Also You can Refer to analytics, specifically CAR 2021–05–010, for more details.
![CAR-2021-05-010](https://github.com/user-attachments/assets/b32df23b-ad94-4ae3-87f0-4ab48e3defaf)
We will use this SPLUNK search query :

(source=”WinEventLog:Microsoft-Windows-Sysmon/Operational” EventCode=”1") OR (source=”WinEventLog:Security” EventCode=”4688") (Image= C:\Windows\System32\net.exe OR Image= C:\Windows\System32\net1.exe ) AND CommandLine = * -exportPFX * )

This query will be preconfigured for our lab to setup an alert in Splunk, as shown below.
![Alert conf](https://github.com/user-attachments/assets/84f33b39-9318-4315-880a-dceeb061a49b)
Now, let’s put theory into practice by engaging TA0003 with some practical emulation using Atomic Red Team!
