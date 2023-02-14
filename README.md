# Summary
This script reports various useful OS and hardware info from a list of remote computers by polling them asynchronously.  
It optionally outputs a log and a CSV file of the data.  

This is an update of [Get-Model](https://github.com/engrit-illinois/Get-Model) primarily just to add the asynchronicity feature. This relies on the new `-Parallel` parameter of the `ForEach-Object` cmdlet, which makes this incompatible with PowerShell 5.1, a limitation not present in `Get-Model`. This new module also gathers quite a bit more information, including network adapter info.  

# Requirements
- Powershell 6+

# Usage
1. Download `Get-MachineInfo.psm1` to the appropriate subdirectory of your PowerShell [modules directory](https://github.com/engrit-illinois/how-to-install-a-custom-powershell-module).
2. Run it using the examples and parameter documentation below.

# Examples

### Return info for single machine
`Get-MachineInfo "espl-114-01"`

### Return info for multiple specific machines
- `Get-MachineInfo "espl-114-01","espl-114-02","tb-207-01"`

### Return info for multiple machines matching a wildcard query
- `Get-MachineInfo "espl-114-*"`

### Return info for multiple queries
- `Get-MachineInfo "espl-114-*","tb-207-01","tb-306-*"`

### Return info for all machines in a given OU
- `Get-MachineInfo -OUDN "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -ComputerName "*"

### Capture the info silently and return just the MACs of the machines:
```powershell
$info = Get-MachineInfo "esb-apl-*" -NoConsoleOutput -PassThru
$info | Select Name,{$_.NetAdapters.Mac}
```

# Parameters

### -ComputerName [string[]]
Required string array.  
The list of computer names and/or computer name query strings to poll.  
Use an asterisk (`*`) as a wildcard.  
The parameter name may be omitted if the value is given as the first or only parameter.   

### -OUDN [string]
Optional string.  
The distinguished name of the OU to limit the computername search to.  
Default is `"OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"`.  

### -PassThru
Optional switch.  
If specified, the resulting info is returned in a PowerShell object.  
If not specified, nothing is returned to the output stream, except logging (if any).  
When specifying -PassThru, capture the info like so: `$info = Get-MachineInfo ...`.  

### -ThrottleLimit [int]
Optional integer.  
The maximum number of computers which will be asynchronously polled simultaneously.  
Default is `50`.   

### -Log \<string\>
Optional string.  
The full path of a text file to log to.  
If omitted, no log will be created.  
If `:TS:` is given as part of the string, it will be replaced by a timestamp of when the script was started, with a format specified by `-LogFileTimestampFormat`.  
Specify `:ENGRIT:` to use a default path (i.e. `c:\engrit\logs\<Module-Name>_<timestamp>.log`).  

### -Csv \<string\>
Optional string.  
The full path of a CSV file to output resulting data to.  
If omitted, no CSV will be created.  
If `:TS:` is given as part of the string, it will be replaced by a timestamp of when the script was started, with a format specified by `-LogFileTimestampFormat`.  
Specify `:ENGRIT:` to use a default path (i.e. `c:\engrit\logs\<Module-Name>_<timestamp>.csv`).  

### -NoConsoleOutput
Optional switch.  
If specified, progress output is not logged to the console.  

### -Indent \<string\>
Optional string.  
The string used as an indent, when indenting log entries.  
Default is four space characters.  

### -LogFileTimestampFormat \<string\>
Optional string.  
The format of the timestamp used in filenames which include `:TS:`.  
Default is `yyyy-MM-dd_HH-mm-ss`.  

### -LogLineTimestampFormat \<string\>
Optional string.  
The format of the timestamp which prepends each log line.  
Default is `[HH:mm:ss:ffff]⎵`.  

### -Verbosity \<int\>
Optional integer.  
The level of verbosity to include in output logged to the console and logfile.  
Specifying `1` outputs some additional logs per machine polled.  
Default is `0`.  
<br />
<br />

# Notes
- Machines for which data could not be retrieved will have an `Error` value of `TRUE` and will have null data otherwise.
- Machines for which data was retrieved will have a null `Error` value.
- By mseng3. See my other projects here: https://github.com/mmseng/code-compendium.
