# Documentation home: https://github.com/engrit-illinois/Get-MachineInfo
function Get-MachineInfo {
	
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[string[]]$ComputerName,
		
		[string]$OUDN = "OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu",
		
		[int]$CIMTimeoutSec = 10,
		
		[switch]$Log,
		
		[switch]$Csv,
		
		[string]$LogDir = "c:\engrit\logs",
		
		[int]$ThrottleLimit = 50
	)
	
	$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
	$LOGPATH = "$LogDir\Get-MachineInfo_$ts.log"
	$CSVPATH = $LOGPATH.Replace(".log",".csv")
	
	function log {
		param(
			[string]$Msg,
			[switch]$NoTS,
			[switch]$NoLog
		)
		
		$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
		if(!$NoTS) {
			$msg = "[$ts] $msg"
		}
		
		Write-Host $Msg
		
		if($Log -and (-not $NoLog)) {
			if(!(Test-Path -PathType Leaf -Path $LOGPATH)) {
				$shutup = New-Item -ItemType File -Force -Path $LOGPATH
			}
			$Msg | Out-File $LOGPATH -Append
		}
	}

	function Get-Comps {
		log "Getting computer names from AD..."
		$comps = @()
		$ComputerName | ForEach-Object {
			$query = $_
			$results = Get-ADComputer -Filter "name -like '$query'" -SearchBase $OUDN | Select -ExpandProperty name
			$comps += @($results)
		}
		$joinString = "`",`""
		log "    Computers: `"$($comps -join $joinString)`"."
		$comps
	}
	
	function Get-Data($comps) {
		log "Retrieving data..."
		log "    Name,Error,Make,Model,Memory,Serial,BiosVersion" -NoLog
		
		$data = $comps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
			function log($msg) {
				Write-Host $msg
			}
			
			$comp = $_
			$object = [PSCustomObject]@{
				"Name" = $comp
			}
			
			$CIMTimeoutSec = $using:CimTimeoutSec
			$errAction = "Stop"
			
			try {
				$result1 = Get-CIMInstance -ClassName "Win32_ComputerSystem" -ComputerName $comp -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				$result2 = Get-CIMInstance -ClassName "Win32_BIOS" -ComputerName $comp -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
			}
			catch {
				$err = $_.Exception.Message
				if(-not $err) {
					$err = "Error"
				}
			}
			$object | Add-Member -NotePropertyName "Error" -NotePropertyValue $err
			
			if($result1) {
				$object | Add-Member -NotePropertyName "Make" -NotePropertyValue $result1.Manufacturer
				$object | Add-Member -NotePropertyName "Model" -NotePropertyValue $result1.Model
				$object | Add-Member -NotePropertyName "Memory" -NotePropertyValue "$([math]::round($result1.TotalPhysicalMemory / 1MB))MB"
			}
			
			if($result2) {
				$object | Add-Member -NotePropertyName "Serial" -NotePropertyValue $result2.SerialNumber
				$object | Add-Member -NotePropertyName "BIOS" -NotePropertyValue $result2.SMBIOSBIOSVersion
			}
			
			log "    $($object.Name),$($object.Make),$($object.Model),$($object.Memory),$($object.Serial),$($object.BIOS),$($object.Error)"
			
			$object
		}
		log "Done retrieving data."
			
		$data
	}
	
	function Format-Data($data) {
		$data | Sort Name | Select Name,Make,Model,Memory,Serial,BIOS,Error
	}
	
	function Output-Csv($data) {
		log "-Csv was specified. Outputting gathered data to `"$CSVPATH`"..."
		$data | Export-Csv -Path $CSVPATH -NoTypeInformation -Encoding Ascii
		log "Done."
		
	}
	
	$comps = Get-Comps
	$data = Get-Data $comps
	$data = Format-Data $data
	if($Csv) {
		Output-Csv $data
	}
	log "EOF"
	$data
}