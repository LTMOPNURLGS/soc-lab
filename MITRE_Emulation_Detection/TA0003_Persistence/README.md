# Overview of the Persistence Tactic
The Persistence tactic (TA0003) in the MITRE ATT&CK framework encompasses techniques that adversaries employ to sustain their access to systems across reboots, credential changes, and other disruptions that could terminate their access. These techniques are vital for adversaries to ensure ongoing control and facilitate further malicious activities. Techniques used for persistence include modifying registry keys and system settings (T1546.002), creating new user accounts (T1136.001), and other actions that allow adversaries to maintain their foothold on systems. For an in-depth description, refer to the MITRE ATT&CK Persistence Tactic page.
![MATRIX TA0003](https://github.com/user-attachments/assets/3cd6311a-d0a2-45cc-8fb9-31f91e1582ea)
The Persistence tactic includes over a dozen techniques, such as creating new user accounts and modifying system settings. There are many other methods adversaries use to ensure continuous access. It is important to familiarise yourself with all these techniques to effectively defend against them.

For the upcoming exercises, we will again utilise MITRE analytics available at ( https://car.mitre.org/ ), along with detection suggestions provided by MITRE. These resources will guide our practical emulation and detection efforts, enhancing our ability to counter persistence techniques effectively.
![CAR](https://github.com/user-attachments/assets/513a6d3e-be30-4238-ac1d-7ab324eca7cc)
Now, It is time for our first technique from TA0003
