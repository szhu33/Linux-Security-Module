# mp4

## Design Decision
1. For non-target tasks, it has full access to all directory and NO_ACCESS object. It has read-only access to other objects.
2. For target tasks, goes as instruction document.
3. As for least priviledge policy for passwd, I skip all the files or diretories that passwd tries to access and that are in the should_skip directories. For the rest files, I set extended attribute according to the mask in the strace' output and trying to maintain least priviledge.

## Details of how it works.
1. Kernel can normally reboot, which means non-target tasks can have full access to non-labeled object.
2. I fail to execute the MAC policy because I fail to get osid. All the osid is 0. But I do believe other parts are correct! Because I tested at a time and if I can get osid correct, I can use cat(target) to open read-only file while vim(target) is denied. Then if I set the file as read-write, vim is able to open it. Though I don't remember at which point I made the mistake about osid, But ther parts are correct!
![image](https://github.com/ittlepearl/mp4/blob/master/images/testoutput.png)


## Details of passwd policy
1. I generated the strace output by running `sudo strace -o output -e trace=file sudo passwd dummyuser`
2. For analyzing the output, I use python to filter out the files in skip_path and files that don't exist
3. For all the files, set extended atrribute as read-only (according to the mask O_RDONLY and O_RDONLY|O_CLOEXEC.
4. For all the directories, set extended atrribute as dir.
5. Output: I fail to test the policy. 
