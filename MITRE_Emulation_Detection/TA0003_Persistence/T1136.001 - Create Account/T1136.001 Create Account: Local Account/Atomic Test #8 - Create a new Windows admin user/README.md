# T1136.001 Atomic Test #8 — Create a new Windows admin user
![Atomic](https://github.com/user-attachments/assets/0c56cba8-6e3e-43d9-b689-bcdeeb91f9c9)
This test creates new admin user using net user /add and adding it to the local group of administrators.
Running the command Invoke-AtomicTest T1136.001-8 on your Windows machine will start the test, simulating the creation of a new admin user.
![Emulation](https://github.com/user-attachments/assets/efd4d53a-7fdc-49c0-a3c9-e54b8888ff47)
Now, let’s check our Splunk instance to see if there is an active alert triggered by the creation of the new admin user.
![Trigered Allert](https://github.com/user-attachments/assets/ab4152b1-49e3-43c9-a1e4-eeebc1d63325)
It seems that the alert we set up earlier was triggered, indicating that a new admin account was created. Investigating the alert further shows that the command net user /add was executed, resulting in a new net.exe process and the addition of the newly created admin user “T1136.001_Admin” to the local administrators group.
![result](https://github.com/user-attachments/assets/8000c2c4-64fe-469b-ba3a-f9b968b1332e)
![SPLUNK](https://github.com/user-attachments/assets/0273ade1-a3b8-4d10-85e9-4cf52d901ffe)
