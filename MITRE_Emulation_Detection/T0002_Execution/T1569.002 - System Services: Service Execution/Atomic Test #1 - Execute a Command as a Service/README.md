# T1569.002 — Atomic Test #1 — Execute a Command as a Service
![ATOMIC DEScription](https://github.com/user-attachments/assets/5cbe28ee-8e31-48cc-8673-2b12730c3221)
Running the command Invoke-AtomicTest T1569.002 1 on your Windows machine will start the test, which will make cmd.exe create a new service using sc.exe that will start powershell.exe to create a new file art-marker.txt. This test requires admin privileges to start the service. Even if admin privileges are not granted, we can proceed with the test and attempt to detect the emulated threat using EventID 1. Additionally, you can look for registry key modifications - EventID 13.
![Emulation](https://github.com/user-attachments/assets/c9d3afae-7683-446a-9976-28e234e09a35)
A general query like: index=wineventlog source=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational” EventCode=1 | where Image LIKE “C:\\Windows\\System32\\sc.exe” will help in identifying the creation of new services by looking for processes initiated by sc.exe. In our case and small lab environment, this query will do the work as you can see below:
![SPLUNK QUERY CMD](https://github.com/user-attachments/assets/9927b4b6-575e-4890-9956-90cc0931c033)
You could also construct a query to look for EventID 4697 and EventID 7045 to find new services created or use EventID 11 to look for file creation and trace back in the logs to identify the cause.
