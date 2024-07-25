# T1047 Atomic Test #1 — WMI Reconnaissance Users
![Atomic Description](https://github.com/user-attachments/assets/a67a5b7b-6df4-4248-8192-99e3ec054195)
Running the command Invoke-AtomicTest T1047 1 on your Windows machine will start the test, which simulates an adversary listing all local user accounts through WMI.![Emulation](https://github.com/user-attachments/assets/5036b49c-5dd3-454f-bb38-1620a5c8b819)
Going back to our Splunk instance, we can successfully detect the activity using the following query:

index=wineventlog source=”WinEventLog:Microsoft-Windows-Sysmon/Operational” EventCode=1 AND Image=”wmic.exe”
![Splunk query](https://github.com/user-attachments/assets/ef80cade-7870-4a2d-bf1d-f5acc1b36a72)
