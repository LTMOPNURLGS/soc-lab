# T1546.002 Event Triggered Execution: Screensaver
Malicious actors may alter screensaver settings to execute malicious code. The screensaver executable (SCRNSAVE.exe) is stored in the registry at HKCU\Control Panel\Desktop\.
![T1546-002](https://github.com/user-attachments/assets/3c7eddfd-2dd6-4fd6-9057-832ba9eb6f3f)
HOW TO DETECT T1546.002
![Detection](https://github.com/user-attachments/assets/bbd40ee9-6b5a-408f-b78b-a55ec31b490c)
MITRE suggests monitoring for new file creations and modifications involving screensaver files, such as SCRNSAVE.EXE. It's also essential to track registry key changes, new process creations, and specific command executions that interact with the HKCU\Control Panel\Desktop registry key.

To implement a detection strategy, we will configure an alert in our Splunk instance. The search query provided by MITRE detects new process creation where registry commands (%reg%) and actions (%add%) target the screensaver settings in the registry:

(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR (source="WinEventLog:Security" EventCode="4688") (CommandLine=*reg* AND CommandLine=*add* AND CommandLine=*HKCU\Control Panel\Desktop*)

The modified query on the alert setup image has almost the same meaning, ensuring we identify and respond to suspicious activities related to screensaver settings manipulation.
![ALERT PROCESS](https://github.com/user-attachments/assets/21643ad6-cc5e-4543-8e8f-617e070b129f)
Let’s fire up some Alerts then!
