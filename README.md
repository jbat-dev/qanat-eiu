# exec_in_usersession
This program makes it possible a specified windows program to  be in the Usersession, although it is executeed in session 0, windows service programu.

# requirement
Should be launched from LOCAL SYSTEM account normaly.
Target user session must be exist. Auto login is not supported.

## useage
exec_in_usersession.exe target_exe ["args for target_exe"] [options]

example1:  
exec_in_usersession.exe c:\windows\notepad.exe c:\mytest.txt

example2: exe-args have multiple args separated by a space.  
exec_in_usersession.exe cp "c:\mytest.txt c:\mytest.2.txt"

example3: specify a user  
exec_in_usersession.exe c:\windows\notepad.exe c:\mytest.ini --xiu-un:username

example4: output a logfile with example3.
exec_in_usersession.exe c:\windows\notepad.exe c:\mytest.ini --xiu-un:username --xiu-lf:c:\mylogfile.txt

## copyright
JB Advanced Technology Inc. and okahashi117 2019

## Thanks!
HABARA!!!
