# Documentation home: https://github.com/engrit-illinois/Get-MachineInfo
function Get-MachineInfo {
	
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[string[]]$ComputerNames,
		
		[string]$OUDN = "OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu",
		
		[switch]$PassThru,
		
		[int]$CIMTimeoutSec = 10,
		
		[int]$ThrottleLimit = 50,
		
		# ":ENGRIT:" will be replaced with "c:\engrit\logs\$($MODULE_NAME)_:TS:.csv"
		# ":TS:" will be replaced with start timestamp
		[string]$Csv,
			
		# ":ENGRIT:" will be replaced with "c:\engrit\logs\$($MODULE_NAME)_:TS:.log"
		# ":TS:" will be replaced with start timestamp
		[string]$Log,

		# This logging is designed to output to the console (Write-Host) by default
		# This switch will silence the console output
		[switch]$NoConsoleOutput,
		
		[string]$Indent = "    ",
		[string]$LogFileTimestampFormat = "yyyy-MM-dd_HH-mm-ss",
		[string]$LogLineTimestampFormat = "[HH:mm:ss] ",
		
		[int]$Verbosity = 0
	)
	
	# Logic to determine final log filename
	$MODULE_NAME = "Get-MachineInfo"
	$ENGRIT_LOG_DIR = "c:\engrit\logs"
	$ENGRIT_LOG_FILENAME = "$($MODULE_NAME)_:TS:"
	$START_TIMESTAMP = Get-Date -Format $LogFileTimestampFormat

	if($Log) {
		$Log = $Log.Replace(":ENGRIT:","$($ENGRIT_LOG_DIR)\$($ENGRIT_LOG_FILENAME).log")
		$Log = $Log.Replace(":TS:",$START_TIMESTAMP)
	}
	if($Csv) {
		$Csv = $Csv.Replace(":ENGRIT:","$($ENGRIT_LOG_DIR)\$($ENGRIT_LOG_FILENAME).csv")
		$Csv = $Csv.Replace(":TS:",$START_TIMESTAMP)
	}
	
	function log {
		param (
			[Parameter(Position=0)]
			[string]$Msg = "",
			
			# Replace this value with whatever the default value of the full log file path should be
			[string]$Log = $Log,

			[int]$L = 0, # level of indentation
			[int]$V = 0, # verbosity level

			[ValidateScript({[System.Enum]::GetValues([System.ConsoleColor]) -contains $_})]
			[string]$FC = (get-host).ui.rawui.ForegroundColor, # foreground color
			[ValidateScript({[System.Enum]::GetValues([System.ConsoleColor]) -contains $_})]
			[string]$BC = (get-host).ui.rawui.BackgroundColor, # background color

			[switch]$E, # error
			[switch]$NoTS, # omit timestamp
			[switch]$NoNL, # omit newline after output
			[switch]$NoConsole, # skip outputting to console
			[switch]$NoLog # skip logging to file
		)
		if($E) { $FC = "Red" }

		$ofParams = @{
			"FilePath" = $Log
			"Append" = $true
		}
		
		$whParams = @{}
		
		if($NoNL) {
			$ofParams.NoNewLine = $true
			$whParams.NoNewLine = $true
		}
		
		if($FC) { $whParams.ForegroundColor = $FC }
		if($BC) { $whParams.BackgroundColor = $BC }

		# Custom indent per message, good for making output much more readable
		for($i = 0; $i -lt $L; $i += 1) {
			$Msg = "$Indent$Msg"
		}

		# Add timestamp to each message
		# $NoTS parameter useful for making things like tables look cleaner
		if(-not $NoTS) {
			if($LogLineTimestampFormat) {
				$ts = Get-Date -Format $LogLineTimestampFormat
			}
			$Msg = "$ts$Msg"
		}

		# Each message can be given a custom verbosity ($V), and so can be displayed or ignored depending on $Verbosity
		# Check if this particular message is too verbose for the given $Verbosity level
		if($V -le $Verbosity) {

			# Check if this particular message is supposed to be logged
			if(-not $NoLog) {

				# Check if we're allowing logging
				if($Log) {

					# Check that the logfile already exists, and if not, then create it (and the full directory path that should contain it)
					if(-not (Test-Path -PathType "Leaf" -Path $Log)) {
						New-Item -ItemType "File" -Force -Path $Log | Out-Null
						log "Logging to `"$Log`"."
					}
					
					$Msg | Out-File @ofParams
				}
			}

			# Check if this particular message is supposed to be output to console
			if(-not $NoConsole) {

				# Check if we're allowing console output at all
				if(-not $NoConsoleOutput) {
					
					Write-Host $Msg @whParams
				}
			}
		}
	}

	function Log-Object {
		param(
			[Parameter(Mandatory=$true,Position=0)]
			[PSObject]$Object,
			
			[string]$Format = "Table",
			[int]$L = 0,
			[int]$V = 0,
			[switch]$NoTs,
			[switch]$E
		)
		if(!$NoTs) { $NoTs = $false }
		if(!$E) { $E = $false }

		switch($Format) {
			"List" { $string = ($object | Format-List | Out-String) }
			#Default { $string = ($object | Format-Table | Out-String) }
			Default { $string = ($object | Format-Table * -AutoSize -Wrap | Out-String) }
		}
		$string = $string.Trim()
		$lines = $string -split "`n"

		$params = @{
			L = $L
			V = $V
			NoTs = $NoTs
			E = $E
		}

		foreach($line in $lines) {
			$params["Msg"] = $line
			log @params
		}
	}
	
	function Get-Comps {
		log "Getting computer names from AD..."
		$comps = @()
		$ComputerNames | ForEach-Object {
			$query = $_
			$results = Get-ADComputer -Filter "name -like '$query'" -SearchBase $OUDN | Select -ExpandProperty name
			$comps += @($results)
		}
		
		if($comps) {
			$joinString = "`",`""
			$compsString = $comps -join $joinString
			log "Computers: `"$compsString`"." -L 1
		}
		else { log "No matching AD computer objects found!" -L 1 }
		$comps
	}
	
	function Get-Data($comps) {
		log "Retrieving data..."
		
		$data = $comps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
			$NoConsoleOutput = $using:NoConsoleOutput
			function log($msg) {
				if(-not $NoConsoleOutput) {
					$ts = Get-Date -Format "HH:mm:ss"
					$msg = "[$ts] $msg"
					Write-Host $msg
				}
			}
			
			function count($array) {
				$count = 0
				if($array) {
					# If we didn't check $array in the above if statement, this would return 1 if $array was $null
					# i.e. @().count = 0, @($null).count = 1
					$count = @($array).count
					# We can't simply do $array.count, because if it's null, that would throw an error due to trying to access a method on a null object
				}
				$count
			}
			
			function addm($property, $value, $object, $adObject = $false) {
				if($adObject) {
					$object | Add-Member -NotePropertyName $property -NotePropertyValue $value -Force
				}
				else {
					$object | Add-Member -NotePropertyName $property -NotePropertyValue $value
				}
				$object
			}
			
			function Get-ComputerSystemInfo($object) {
				try {
					$result = Get-CIMInstance -ClassName "Win32_ComputerSystem" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($result) {
							$object = addm "Make" $result.Manufacturer $object
							$object = addm "Model" $result.Model $object
							$object = addm "Memory" "$([math]::round($result.TotalPhysicalMemory / 1MB))MB" $object
						}
					}
					if($err) {
						$object = addm "Error_CompInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Get-OperatingSystemInfo($object) {
				try {
					$result = Get-CIMInstance -ClassName "Win32_OperatingSystem" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($result) {
							$object = addm "OS" $result.Version $object
						}
					}
					if($err) {
						$object = addm "Error_OsInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Get-SystemEnclosureInfo($object) {
				try {
					$result = Get-CIMInstance -ClassName "Win32_SystemEnclosure" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($result) {
							$object = addm "AssetTag" $result.SMBIOSAssetTag $object
						}
					}
					if($err) {
						$object = addm "Error_SysEncInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Get-BiosInfo($object) {
				try {
					$result = Get-CIMInstance -ClassName "Win32_BIOS" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($result) {
							$object = addm "Serial" $result.SerialNumber $object
							$object = addm "BIOS" $result.SMBIOSBIOSVersion $object
						}
					}
					if($err) {
						$object = addm "Error_BiosInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Get-TpmInfo($object) {
				try {
					$result = Get-CimInstance -ClassName "Win32_Tpm" -ComputerName $object.Name -Namespace "root\cimv2\security\microsofttpm" -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($result) {
							$object = addm "TPM" $result.ManufacturerVersion $object
						}
					}
					if($err) {
						$object = addm "Error_TpmInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Get-Ipv4($ips) {
				$ipv4 = "unknown"
				$ipv4Regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
				@($ips) | ForEach-Object {
					if($_ -match $ipv4Regex) { $ipv4 = $_ }
				}
				$ipv4
			}
			
			function Get-NetworkAdapterInfo($object) {
				
				# get-ciminstance win32_networkadapter | select name,macaddress,guid,status,networkaddresses,adaptertype,netconnectionid,netconnectionstatus,netenabled,physicaladapter | ft
					
				# get-ciminstance win32_networkadapterconfiguration | select description,dnshostname,dnsdomainsuffixsearchorder,ipaddress,ipenabled,settingid,macaddress | ft
					
				try {
					$adapterResults = Get-CimInstance -ClassName "Win32_NetworkAdapter" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
					$configResults = Get-CimInstance -ClassName "Win32_NetworkAdapterConfiguration" -ComputerName $object.Name -OperationTimeoutSec $CIMTimeoutSec -ErrorAction $errAction
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) {
						$err = "Unknown error"
					}
				}
				finally {
					if(-not $err) {
						if($adapterResults) {
							if($configResults) {
								$physicalAdapterResults = $adapterResults | Where { $_.PhysicalAdapter }
								$adapterData = $physicalAdapterResults | ForEach-Object {
									$adapterResult = $_
									$configResult = $configResults | Where { $_.SettingID -like $adapterResult.GUID }
									if($configResult) {
										$configResultCount = count $configResult
										if($configResultCount -eq 1) {
											$ips = $configResult | Select -ExpandProperty "IPAddress"
											$ipv4 = Get-Ipv4 $ips
											[PSCustomObject]@{
												"Mac" = $configResult | Select -ExpandProperty "MACAddress"
												"Ips" = $ips
												"Ipv4" = $ipv4
												"DnsHostname" = $configResult | Select -ExpandProperty "DNSHostName"
												"Name" = $configResult | Select -ExpandProperty "Description"
												"Gateway" = $configResult | Select -ExpandProperty "DefaultIPGateway"
												"DhcpEnabled" = $configResult | Select -ExpandProperty "DHCPEnabled"
												"DhcpServer" = $configResult | Select -ExpandProperty "DHCPServer"
												"DhcpLeaseObtained" = $configResult | Select -ExpandProperty "DHCPLeaseObtained"
											}
										}
										elseif($configResultCount -lt 1) { $err = "No configuration found for one or more physical adapters, or configuration info is invalid!" }
										else { $err = "Multiple configurations found for one or more physical adapters!" }
									}
									else { $err = "No configuration found for one or more physical adapters!" }
								}
								$object = addm "NetAdapters" $adapterData $object
							}
							else { $err = "No adapter configuration info returned!" }
						}
						else { $err = "No adapter info returned!" }
					}
					if($err) {
						$object = addm "Error_NetInfo" $err $object
						$object.Error = $true
					}
				}
				
				$object
			}
			
			function Do-Stuff {
				
				log "    Retrieving data for: `"$_`"..."
				
				$comp = $_
				$object = [PSCustomObject]@{
					"Name" = $comp
					"Error" = $false
				}
				
				$CIMTimeoutSec = $using:CimTimeoutSec
				$errAction = "Stop"
				
				$object = Get-ComputerSystemInfo $object
				$object = Get-OperatingSystemInfo $object
				$object = Get-SystemEnclosureInfo $object
				$object = Get-BiosInfo $object
				$object = Get-TpmInfo $object
				$object = Get-NetworkAdapterInfo $object
				
				log "    Done retrieving data for: `"$_`"."
		
				$object
			}
			
			Do-Stuff
		}
		
		log "Done retrieving data."
			
		$data
	}
	
	function Output-Csv($data) {
		log "-Csv was specified. Outputting gathered data to `"$Csv`"..."
		$data | Export-Csv -Path $Csv -NoTypeInformation -Encoding Ascii
		log "Done."
		
	}
	
	function Print-Data($data) {
		log "Data:"
		$printData = $data | Select Name,Error,Make,Model,Memory,OS,AssetTag,Serial,BIOS,TPM,@{Name="MAC";Expression={$_.NetAdapters.Mac}}
		Log-Object $printData -L 1
	}
	
	function Do-Stuff {
		$comps = Get-Comps
		if($comps) {
			$data = Get-Data $comps
			if($Csv) {
				Output-Csv $data
			}
			Print-Data $data
			if($PassThru) {
				$data
			}
		}
	}
	
	Do-Stuff
	log "EOF"
}