# Summary
This script reports various inventory-related info from a list of remote computers by polling them asynchronously.  
It optionally outputs a log and a CSV file of the data.  

This is an update of [Get-Model](https://github.com/engrit-illinois/Get-Model) primarily just to add the asynchronicity feature. This relies on the new `-Parallel` parameter of the `ForEach-Object` cmdlet, which makes this incompatible with PowerShell 5.1, a limitation not present in `Get-Model`.  

# Usage
1. Download `Get-MachineInfo.psm1` to `$HOME\Documents\WindowsPowerShell\Modules\Get-MachineInfo\Get-MachineInfo.psm1`
2. Run it using the examples and parameter documentation below.

# Examples
- `Get-MachineInfo "espl-114-01"`
- `Get-MachineInfo "espl-114-01","espl-114-02","tb-207-01"`
- `Get-MachineInfo "espl-114-*"`
- `Get-MachineInfo "espl-114-*","tb-207-01","tb-306-*"`
- `Get-MachineInfo -OUDN "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -ComputerName "*" -LogDir "c:\engrit\logs" -Log -Csv`

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

### -Log
Optional switch.  
Whether or not to log output to a log file.  
Log filename will be `Get-MachineInfo_yyyy-MM-dd_HH-mm-ss.log`.  
Log will be created in the directory specified by the `-LogDir` parameter.  

### -Csv
Optional switch.  
Whether or not to log retrieved data to a CSV file.  
CSV filename will be `Get-MachineInfo_yyyy-MM-dd_HH-mm-ss.csv`.  
CSV will be created in the directory specified by the `-LogDir` parameter.  

### -LogDir [string]
Optional string.  
The directory in which to create log and/or CSV files, if any are created.  
Default is `"c:\engrit\logs"`.  

### -ThrottleLimit [int]
Optional integer.  
The maximum number of computers which will be asynchronously polled simultaneously.  
Default is `50`.  

### -CIMTimeoutSec [int]
Optional integer.  
The number of seconds to wait for a CIM query to a target machine before giving up.  
Default is `10`.  

# Notes
- Machines for which data could not be retrieved will have an `Error` value of `TRUE` and will have null data otherwise.
- Machines for which data was retrieved will have a null `Error` value.
- By mseng3. See my other projects here: https://github.com/mmseng/code-compendium.
