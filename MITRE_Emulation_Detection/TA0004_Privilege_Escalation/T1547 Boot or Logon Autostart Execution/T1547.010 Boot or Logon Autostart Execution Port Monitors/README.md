T1547.010 Boot or Logon Autostart Execution: Port Monitors
Adversaries can achieve persistence or elevate privileges by configuring port monitors to run a malicious DLL during system boot. This can be done using the AddMonitor API call to set the DLL, which will be executed by the print spooler service (spoolsv.exe) with SYSTEM level permissions at startup.

Alternatively, if they have sufficient permissions, adversaries can write the DLL’s path to the Driver value in the registry under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. This ensures the DLL is loaded when the system boots.

For the official description, refer to the MITRE ATT&CK T1547.010 page.

https://attack.mitre.org/techniques/T1547/010/
![mitre](https://github.com/user-attachments/assets/fab4582a-5101-484b-8036-2f98ef24b861)

How to Detect T1547.010
To detect adversaries using port monitors for persistence or privilege escalation, monitor for newly created files that could be used as port monitors, abnormal DLLs loaded by spoolsv.exe, and suspicious registry modifications under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. Additionally, watch for process API calls to AddMonitor that may indicate misuse.
![detection](https://github.com/user-attachments/assets/6fde2909-a2e0-4ab9-8a29-443292f4424c)

Now, let’s head to our Splunk instance and create our first query and set up a new alert

ALERT FOR DS0022 File Creation
The Splunk search query we will use is:

index=”wineventlog” source=WinEventLog:Security (EventCode=4663 OR EventCode=4656)

| search Object_Type=”File” Object_Name=”*.dll”

| eval timestamp=strftime(_time, “%Y-%m-%d %H:%M:%S”)

| table timestamp, EventCode, host, Account_Name, Object_Name, Object_Type, Accesses, Process_Name, Process_Command_Line

| sort — _time

This query monitors for events related to file creation or access, specifically looking for DLL files. It uses Windows Security Event logs with event codes 4663 and 4656, which are related to file access and creation activities. By tracking these events, we can detect potential malicious activities involving port monitors.

To ensure these logs are generated, you need to enable the following audit setting:

Object Access: Enable auditing for object access to track attempts to access or modify files and other objects.

Alternatively, you can use Sysmon (System Monitor). Ensure you have Sysmon rules created to generate detailed logs about process creations, file modifications, and registry changes, for detecting the upcoming events.

Event codes:
4663: Indicates an attempt to access an object, such as a file.
4656: Indicates that a handle to an object was requested.

These events are crucial for detecting when new DLL files are created or accessed, which is a part of our detection strategy for DS0022 (File Creation). This query will help us identify suspicious file activities that could be related to the Red Team Atomic Test for T1547.010.

However, please note that this query could generate a lot of noise in a production environment due to the high volume of legitimate file access events. It may require further tuning and filtering to reduce false positives.

Below is the setup for configuring this alert in Splunk for real-time monitoring:
![FILE ALERT SET](https://github.com/user-attachments/assets/0a736451-2493-4d6c-aecf-74635c8185d8)

ALERT FOR DS0011 Module Load
The Splunk search query we will use is:

index=”winevenlog” source=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational” EventCode=7

| search Image=”C:\\Windows\\System32\\spoolsv.exe”

| where NOT like(ImageLoaded, “C:\\Windows\\System32\\%”)

| where NOT like(ImageLoaded, “C:\\Windows\\SysWOW64\\%”) | eval is_suspicious=if(match(OriginalFileName, “.*\\.dll”), “No”, “Yes”) | eval timestamp=strftime(_time, “%Y-%m-%d %H:%M:%S”) | table timestamp, EventCode, host, User, Image,ImageLoaded, is_suspicious | sort — _time

This query focuses on:

Event Code 7: Indicates an image (DLL) loaded event.
Image: Filters for the spoolsv.exe process.
ImageLoaded: Identifies DLLs loaded by spoolsv.exe, excluding those in the System32 and SysWOW64 directories.
The query evaluates whether the loaded module is suspicious by checking if it is a DLL and logs relevant details, including the timestamp, host, user, and loaded image.

Ensure Sysmon is configured to capture image load events (Event Code 7) to generate the necessary logs.

Below is the setup for configuring this alert in Splunk for real-time monitoring:
![MODULE LOADED DLL spoolsv](https://github.com/user-attachments/assets/c2f21256-3d8f-4aaa-b415-e7c3c88a889c)

ALERT FOR DS0024 Windows Registry Key Modification
The Splunk search query we will use is:

index=”winevenlog” source=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational” EventCode=13 | search Image=”C:\\Windows\\system32\\reg.exe” AND TargetObject=”HKLM\\System\\CurrentControlSet\\Control\\Print\\Monitors\\*” | eval timestamp=strftime(_time, “%Y-%m-%d %H:%M:%S”)

| table timestamp, EventCode, User, TargetObject, Details, Image

| sort — _time

This query focuses on:

Event Code 13: Indicates a registry object was modified.
Image: Filters for the reg.exe process, which is used to modify the registry.
TargetObject: Identifies changes made to the registry key path HKLM\System\CurrentControlSet\Control\Print\Monitors.
The query logs relevant details, including the timestamp, user, target object, and the process image.

Ensure Sysmon is configured to capture registry key modification events (Event Code 13) to generate the necessary logs. Alternatively, you can use Windows Event Logs to track registry modifications by enabling detailed auditing.

Below is the setup for configuring this alert in Splunk for real-time monitoring:
![REGKEY ALERT](https://github.com/user-attachments/assets/d21feb8d-9fc6-4825-93aa-aaf7b36722c7)

Now, let’s put theory into practice by engaging TA0004 with some practical emulation using Atomic Red Team.

T1547.010 Atomic Test #1 — Add Port Monitor persistence in Registry
![detection](https://github.com/user-attachments/assets/41d664a4-6bea-4eba-a8ec-5b7782bbc80f)

https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.010/T1547.010.md

This test modifies the Windows registry to add a new port monitor entry. When the system reboots, the specified DLL will be executed by the print spooler service (spoolsv.exe) with SYSTEM-level privileges.

Running the command Invoke-AtomicTest T1547.010–1 on your Windows machine will start the test, simulating the modification of a registry entry to add the PortMonitor.dll file that will run with SYSTEM-level privileges on reboot.
![emulation](https://github.com/user-attachments/assets/652efc2f-6114-496d-bfd7-efcf8ee79da1)

Reboot the machine to complete the threat emulation and then check your Splunk instance for triggered alerts.
![Trigered location](https://github.com/user-attachments/assets/1a119426-3d40-489a-b840-cd5f2073feee)
![AlertsTrigered](https://github.com/user-attachments/assets/54c66936-fed0-4907-90b3-3ca7613f54c5)

Triggered Alerts
All previously configured alerts have been triggered. Further investigation is required to determine if they are true positives.

Analysis of Triggered Alerts
1. Alert for DS0022 (!!!File Creation!!! SUSPICIOUS.DLL !!!)
![RERSULT FILE CREATION](https://github.com/user-attachments/assets/3cd42109-53ae-4f3b-8f10-226595faffce)

The file creation alert shows that a DLL file named PortMonitor.dll was accessed with Execute/Traverse and ReadAttributes permissions. The process involved was spoolsv.exe, indicating the print spooler service is involved.

2. Alert for DS0011 (!!! Suspicious DLL loaded by spoolsv.exe !!!!)
![RESULT DLL LOADED](https://github.com/user-attachments/assets/1086a69b-5357-458d-b108-00be82d1c121)

The module load alert indicates that the DLL PortMonitor.dll was loaded by the spoolsv.exe process, running under NT AUTHORITY\SYSTEM. The DLL was loaded from a user directory, which is considered suspicious as legitimate DLLs for the print spooler should reside in the system directories.

3. Alert for DS0024 (!!! Suspicious Reg Key Modification !!!)
![RESULT REG MODIFY](https://github.com/user-attachments/assets/a0c74f48-b44e-40bc-acc3-6f3440b21a32)

The registry modification alert shows that a new entry was added under the Print\Monitors registry key, pointing to the PortMonitor.dll file. This action was performed by the reg.exe process, executed by an Administrator user.

Conclusion
From a SOC Analyst’s perspective, the triggered alerts and associated events exhibit behavior consistent with malicious activity for several reasons:

Suspicious DLL File Accessed: The creation and access of a DLL file named PortMonitor.dll in a user directory is unusual, especially for a file meant to be used by a critical system service like spoolsv.exe. Typically, legitimate DLLs used by system services are located in system directories such as C:\Windows\System32.

Critical Process Involvement: The spoolsv.exe process, which is responsible for handling print jobs, loaded this DLL. The fact that this critical system process, which runs with high privileges, is loading a DLL from an unconventional location raises significant red flags.

Registry Modification: The modification of the registry to include a new port monitor under HKLM\System\CurrentControlSet\Control\Print\Monitors is particularly concerning. This registry path is crucial for configuring port monitors, which are used by the print spooler service to manage printing. By adding a new entry here, the adversary ensures that the PortMonitor.dll will be loaded by spoolsv.exe every time the system boots. The fact that this modification was made using reg.exe by an Administrator account further indicates that the adversary had elevated privileges, which were likely used to maintain persistence and control over the system.

These events, when combined, suggest that an adversary has successfully manipulated the system to load a potentially malicious DLL with high privileges on startup. This behavior is indicative of an attempt to establish persistence and maintain control over the compromised system.

While this technique primarily serves as a persistence mechanism, it also facilitates privilege escalation. By ensuring the malicious code runs on startup, it achieves persistence. However, because the code runs with elevated privileges (SYSTEM level), it also enables the adversary to perform actions requiring higher-level permissions. This dual functionality can make it challenging to classify the tactic as solely persistence or privilege escalation, as it effectively achieves both.

I encourage you to create your own search queries and alerts for the rest of the recommended detection strategies for this technique listed in the image below. As a hint for constructing your next query, in previous posts, we touched on queries for DS0017 Command Execution using cmd.exe.
![further reading](https://github.com/user-attachments/assets/09dde589-1ebd-4d24-8afb-c90ef39a194b)
