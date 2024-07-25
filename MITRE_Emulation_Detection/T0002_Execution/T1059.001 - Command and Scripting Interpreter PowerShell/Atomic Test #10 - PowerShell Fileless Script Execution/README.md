## T1059.001 Atomic Test 10 — PowerShell Fileless Script Execution
![POSTER] ![ATOMIC Description](https://github.com/user-attachments/assets/77ed8829-5e81-4803-bb65-0a870be08b7d)
Running the command Invoke-AtomicTest T1059.001 10 on your Windows machine will start the test, which will simulate the execution of a PowerShell payload from the Windows Registry. This command will create a file named art-marker.txt in the C:\Windows\Temp directory with the content "Hello from the Atomic Red Team".
![POSTER]![helloFromAtomic](https://github.com/user-attachments/assets/6da5d95e-5ace-4241-9eaa-96d249c67288)
Let’s now examine the logs to see what occurred. Access your Splunk instance and utilise the same search query from the previous test. By analysing these logs, you should be able to detect the simulated execution of the PowerShell payload. If successful, you will see entries indicating the creation and execution of the encoded PowerShell commands.
![POSTER]![SPLUNK SEARCH QUERY](https://github.com/user-attachments/assets/f31a0672-2317-4774-86d9-93c49949b81d)
![POSTER]![Detection](https://github.com/user-attachments/assets/8ef5cd50-ce7a-43c5-a828-dcbb4d6f6e69)
I strongly recommend you explore the remaining Atomic tests and thoroughly read the .yaml files. This will help you understand the underlying scripts and how they function. Additionally, it’s beneficial to check the mitigation against each sub-technique provided by MITRE
