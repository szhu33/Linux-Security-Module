# mp4

## Design Decision
1. For non-target tasks, it has full access to all directory and NO_ACCESS object. It has read-only access to other objects.
2. For target tasks, goes as instruction document.

## Details of how it works.
1. Kernel can normally reboot, which means non-target tasks can have full access to non-labeled object.
2. Marked file.txt as write-only, and vim is non-target task. Then vim can open file.txt as a read-only file.
![image](https://github.com/ittlepearl/mp4/blob/master/images/non-target-read1.png)
![image](https://github.com/ittlepearl/mp4/blob/master/images/non-target-read2.png)
3. Marked file.txt as write-only, and vim is target task. Then vim can not open file.txt since its mask has MAY_READ.
![image](https://github.com/ittlepearl/mp4/blob/master/images/target-write-only.png)
3. Marked file.txt as read-write
![image](https://github.com/ittlepearl/mp4/blob/master/images/read-write.png)
It should be able to open file.txt. But since vim is target so it can not open library(which should be labeled as No_Access). Therefore, permission denied.
