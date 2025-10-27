# WSUSploit.NET

C# PoC for CVE-2025-59287

Basically a port of the initial public PoC. Warning, will mess up WSUS.


## Disclaimer: 
This is for ethical and legal security testing, research, and education. Do not use any of this software in any unauthorized manner. 

## Defensive Considerations

These HTTP calls in this order. A more advanced threat actor may throw in random HTTP calls to avoid this detection.
IIS Log Path :`C:\inetpub\logs\LogFiles\<WSUS IIS SERVER>\<LOG FILE NAME>.log`
```
POST /ReportingWebService/ReportingWebService.asmx
POST /SimpleAuthWebService/SimpleAuth.asmx 
POST /ClientWebService/Client.asmx 
POST /ReportingWebService/ReportingWebService.asmx
```


Windows Event 7053 

Source: Windows Server Update Services

Windows Logs > Application
```
...
System.InvalidCastException -- Unable to cast object of type 'System.Windows.Data.ObjectDataProvider' to type 'System.Windows.Media.Brush'.
...
```