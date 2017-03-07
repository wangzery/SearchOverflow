# SearchOverflow
A IDAPython script for searching overflows in IDA.     

Now support：strcpy(), _strcpy(), strcat(), _strcat(), sprintf(), _sprintf(), wsprintfA(), lstrcatA(), lstrcpyA()     
  
Refactored by Bugscam.

##Usage
Load script in IDA，then use command：SearchOverflow()

##VersionLog：   
   
v1.2:Add sprintf(), _sprintf(), wsprintfA(), only support arg includes "%s".     
    
v1.1:Add lstrcatA(), lstrcpyA(), fixed command outputs.
