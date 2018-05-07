# mp4

## Design Decision
1. For non-target tasks, it has full access to all directory and NO_ACCESS object. It has read-only access to other objects.
2. For target tasks, goes as instruction document.

## Details of how it works.
1. Kernel can normally reboot, which means non-target tasks can have full access to non-labeled object.
2. Marked file.txt as write-only, and vim is non-target task. Then vim can open file.txt as a read-only file.
![image](https://github.com/ittlepearl/mp4/blob/master/images/non-target-read1.png)
3. Marked 
3. Marked file.txt as read-write
