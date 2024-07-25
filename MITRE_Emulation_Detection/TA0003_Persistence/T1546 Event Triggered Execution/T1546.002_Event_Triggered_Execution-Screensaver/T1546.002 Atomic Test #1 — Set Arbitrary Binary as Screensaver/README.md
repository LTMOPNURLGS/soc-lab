# T1546.002 Atomic Test #1 — Set Arbitrary Binary as Screensaver
![atomic](https://github.com/user-attachments/assets/1e8fe087-a3dd-4470-ba84-6ef687cb3273)
This test copies a binary evilscreensaver.scr into the Windows System32 folder and modifies Registry “HKEY_CURRENT_USER\Control Panel\Desktop” in order to set the binary as a screensaver.

Running the command Invoke-AtomicTest T1546.002-1 on your Windows machine will start the test, simulating the setup of malicious screensaver.
![emulating](https://github.com/user-attachments/assets/fd4af1c6-854f-4e32-a04c-68ddb6b1b390)
Now, let’s check our Splunk instance to see if there is an active alert triggered.
![TRIGERED](https://github.com/user-attachments/assets/22947403-93c3-434c-b9f4-11a7d086912f)
A suspicious action was detected, and upon further investigation, we can see that the commands highlighted in red are likely malicious.
![result](https://github.com/user-attachments/assets/ce2ba6b3-4057-491e-a9e3-7436b0dbabb8)
