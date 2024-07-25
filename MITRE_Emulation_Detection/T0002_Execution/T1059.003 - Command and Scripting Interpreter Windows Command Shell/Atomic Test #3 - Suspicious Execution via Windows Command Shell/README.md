## T1059.003- Atomic TEST 3 Suspicious Execution via Windows Command Shell
![POSTER]![Atomic Description](https://github.com/user-attachments/assets/a91fe275-a8ba-4825-9e2b-2b767a5a2867)
Running the command Invoke-AtomicTest T1059.003 3 on your Windows machine will start the test, which will simulate command line execution via a suspicious invocation.
![POSTER]![Emulation](https://github.com/user-attachments/assets/7c4b82fa-5ef8-4030-90fb-5e4bf38b9872)
In order to detect it, we will use the same analytic to check for process creation as we did in the previous test. You should receive results similar to mine.
![POSTER]![Splunk query](https://github.com/user-attachments/assets/5de092c8-7d26-454d-b681-3c95aae57c25)
