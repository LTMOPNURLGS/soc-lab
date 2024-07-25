## T1569 — System Services
The T1569 technique consists of two sub-techniques that adversaries use to abuse system services or daemons to execute commands or programs. For more details, visit the MITRE ATT&CK page for T1569.
![POSTER]![Description MITRE](https://github.com/user-attachments/assets/ba591cad-56a1-4ce0-9dd4-26d67b8a93a3)
## HOW TO DETECT T1569 — System Services
To detect these threats, MITRE suggests monitoring command execution, file modification, process creation, service creation, and Windows registry key modifications. As you can see in the screenshot below:
![POSTER]![MITRE Detection](https://github.com/user-attachments/assets/cc55363c-e507-45c6-ae29-8d1961b32e1c)
With this knowledge, we can now explore the sub-techniques and conduct practical emulations.
## T1569.002 — System Services: Service Execution
Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. For more details, visit MITRE ATT&CK page for T1569.002
![MITRE DESCRIPTION](https://github.com/user-attachments/assets/5ca9b1b8-e549-4bf0-a8ea-59eedbaeeebe)
## HOW TO DETECT T1569.002 — System Services: Service Execution
The search query provided by MITRE to detect service execution is shown in the image below. This query will examine the Sysmon log for process creation and look for execution of services and cmd.
![MITRE Analytics](https://github.com/user-attachments/assets/57de65f0-d118-4cef-9c4b-eaaa18dd212d)
More search queries can be found in the Cyber Analytics Repository (CAR) for this technique, which you can read. I recommend exploring them, as there are plenty listed for service execution.
![CAR to READ REcommended](https://github.com/user-attachments/assets/d870a06f-b606-4dfd-a4cf-68410ed9ed19)
Let’s get to work and burn some RAM calories. Wake up your Windows VM.
