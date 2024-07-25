## T1047 — Windows Management Instrumentation
Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. For more details, visit MITRE ATT&CK page for T1047.
![MITRE DESCRIPTION](https://github.com/user-attachments/assets/8d3b20f9-2ab9-41e7-950b-41c5e7e1aa60)
By using a general query to search Sysmon logs for new processes created by wmic.exe, we can detect T1047 technique. For more details, visit MITRE ATT&CK page for T1047.
![MITRE DETECTION](https://github.com/user-attachments/assets/6ab6b4f9-3618-445b-aee7-e43ea6ec5df3)
In order to practice it we will emulate:

#T1047 Atomic Test #1
