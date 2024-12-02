# RRDS
Real-time Ransomware Defense System through Windows-based User-level File Event Monitoring


# case1 - [WastedLocker’s techniques point to a familiar heritage](https://news.sophos.com/en-us/2020/08/04/wastedlocker-techniques-point-to-a-familiar-heritage/)

According to the link above, the ransomware changes the name of the original binary to MoveFileW api by adding the .bbawasted extension.

![image](https://github.com/user-attachments/assets/464462b1-c540-46f1-bd56-f58b3922100e)

So we created a simple poc ransomware based on the content. (/code/case1_ransomeware_test)
and, You can hook the code through dll engagement to identify ransomware behavior and extensions and even recover it. Attached is the poc video below.

https://github.com/user-attachments/assets/f96dc695-f396-419d-a624-99b03335b679

# References
- [microsoft/Detours](https://github.com/microsoft/Detours)
- [captain-woof/malware-study](https://github.com/captain-woof/malware-study/tree/main/ApiHookingDetours/ApiHookingDetours/detours)
- [sensepost/mydumbedr](https://github.com/sensepost/mydumbedr)




