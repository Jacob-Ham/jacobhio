---
tags:
  - Authenticated
  - OPSEC
  - AD
---
## Identify
---
## Windows Defender
---
```Python
Get-MpComputerStatus
```
If RealTimeProtection: True, we have defender enabled
## **AppLocker**
---
```PowerShell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
## Bypassing Policy with LOLBAS
They exist in trusted paths (C:\Windows and C:\Program Files) and may also be digitally signed by Microsoft. 
Examples: [https://lolbas-project.github.io/](https://lolbas-project.github.io/)
**Example**: msbuild.exe
Build and execute a C# project stored in the target XML file:

<details>
  <summary>helloworld.xml</summary>
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest : Task, ITask
            {
                public override bool Execute()
                {
                    Console.WriteLine("Hello World");
                    return true;
                }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```
</details> 

```powershell
msbuild.exe helloworld.xml
```


!!! alert "note"
	Organizations often block the `PowerShell.exe` executable, but forget about the other [PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`



## **PowerShell Constrained Language Mode**
---
Will prevent tons of useful powershell features
```PowerShell
$ExecutionContext.SessionState.LanguageMode
```
## LAPS
---
[https://github.com/leoloobeek/LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
Can help us find ADUsers that have permissions to read LAPS passwords
```PowerShell
Find-LAPSDelegatedGroups
```
The Find-AdmPwdExtendedRights checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.
```PowerShell
Find-AdmPwdExtendedRights
```
Find computers with laps enabled
```PowerShell
Get-LAPSComputers
```