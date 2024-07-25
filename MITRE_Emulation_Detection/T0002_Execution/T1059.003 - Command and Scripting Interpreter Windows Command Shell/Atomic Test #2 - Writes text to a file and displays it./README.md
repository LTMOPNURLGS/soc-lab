## T1059.003-ATOMIC TEST 2 — Writes text to a file and displays it
![POSTER]![Atomic description](https://github.com/user-attachments/assets/2204e550-afbc-4e86-82ac-2aae82bad9c7)
Running the command Invoke-AtomicTest T1059.003 2 on your Windows machine will start the test, which will simulate writing text to a file and displaying the results. This test emulates the dropping of a malicious file to disk.
![POSTER]![Emulation - Copy](https://github.com/user-attachments/assets/a17f6618-5fb2-4d82-893a-e1294039577e)
For this Atomic test, we can use the analytics provided by CAR.
![POSTER]![CAR DESCRIPTION - Copy](https://github.com/user-attachments/assets/d664a943-3a45-4fc5-9995-482c12657408)
![POSTER]![CAR](https://github.com/user-attachments/assets/313ac069-7a2f-4632-a0b7-203206f23334)
The provided analytic isn’t explicitly for Splunk, so we’ve converted it for our lab. Here’s the query and the results you can expect: index=wineventlog EventCode=1 Image=”C:\\windows\\System32\\cmd.exe” source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
![POSTER]![Splunk query - Copy](https://github.com/user-attachments/assets/e490e6c0-c303-4417-87fa-c68dd32bd091)

