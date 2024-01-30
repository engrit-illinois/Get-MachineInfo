# Documentation home: https://github.com/engrit-illinois/Get-MachineInfo
function Get-MachineInfo {
	
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[string[]]$ComputerNames,
		
		[string]$OUDN = "OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu",
		
		[switch]$PassThru,
		
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
	
	function addm($property, $value, $object, $adObject = $false) {
		if($adObject) {
			$object | Add-Member -NotePropertyName $property -NotePropertyValue $value -Force
		}
		else {
			$object | Add-Member -NotePropertyName $property -NotePropertyValue $value
		}
		$object
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
		
		$f_addm = ${function:addm}.ToString()
		
		$objects = $comps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
			
			${function:addm} = $using:f_addm
			
			function Get-ScriptBlock {
				
				$scriptBlock = {
					
					$errAction = "Stop"
					
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
					
					function Get-ComputerSystemInfo($data) {
						try {
							$result = Get-CIMInstance -ClassName "Win32_ComputerSystem" -ErrorAction $errAction
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "Make" $result.Manufacturer $data
									$data = addm "Model" $result.Model $data
									$data = addm "Memory" "$([math]::round($result.TotalPhysicalMemory / 1MB))MB" $data
								}
							}
							if($err) {
								$data = addm "Error_CompInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-OperatingSystemInfo($data) {
						try {
							$result = Get-CIMInstance -ClassName "Win32_OperatingSystem" -ErrorAction $errAction
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "OsBuild" $result.Version $data
									$data = addm "OsInstalled" $result.InstallDate $data
									#$data = addm "NumUsers" $result.NumberOfUsers $data
									$data = addm "SystemTime" $result.LocalDateTime $data
									$data = addm "LastBoot" $result.LastBootUpTime $data
									$data = addm "OsArch" $result.OSArchitecture $data
								}
							}
							if($err) {
								$data = addm "Error_OsInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-OperatingSystemInfo2($data) {
						try {
							$result = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "OsRev" $result.UBR $data
									$data = addm "OsRelease" $result.DisplayVersion $data
									# Don't want to gather the full build number from here exclusively, because there's two ambiguous locations for the build number
									# https://stackoverflow.com/questions/37877599/hklm-software-microsoft-windows-nt-currentversion-whats-the-difference-between
								}
							}
							if($err) {
								$data = addm "Error_Os2Info" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-OfficeInfo($data) {
						try {
							$result = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction "SilentlyContinue"
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "OfficeVer" $result.ClientVersionToReport $data
								}
							}
							if($err) {
								$data = addm "Error_OfficeInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-ProfileInfo($data) {
						try {
							$result = Get-Item -Path "c:\users\*" | Measure-Object | Select -ExpandProperty "Count"
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "NumProfiles" $result $data
								}
							}
							if($err) {
								$data = addm "Error_ProfileInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-SystemEnclosureInfo($data) {
						try {
							$result = Get-CIMInstance -ClassName "Win32_SystemEnclosure" -ErrorAction $errAction
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "AssetTag" $result.SMBIOSAssetTag $data
								}
							}
							if($err) {
								$data = addm "Error_SysEncInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-BiosInfo($data) {
						try {
							$result = Get-CIMInstance -ClassName "Win32_BIOS" -ErrorAction $errAction
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "Serial" $result.SerialNumber $data
									$data = addm "BIOS" $result.SMBIOSBIOSVersion $data
								}
							}
							if($err) {
								$data = addm "Error_BiosInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-TpmInfo($data) {
						try {
							$result = Get-CimInstance -ClassName "Win32_Tpm" -Namespace "root\cimv2\security\microsofttpm" -ErrorAction $errAction
						}
						catch {
							$err = $_.Exception.Message
							if(-not $err) { $err = "Unknown error" }
						}
						finally {
							if(-not $err) {
								if($result) {
									$data = addm "TPM" $result.ManufacturerVersion $data
								}
							}
							if($err) {
								$data = addm "Error_TpmInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					function Get-NetworkAdapterInfo($data) {
						
						function Get-Ipv4($ips) {
							$ipv4 = "unknown"
							$ipv4Regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
							@($ips) | ForEach-Object {
								if($_ -match $ipv4Regex) { $ipv4 = $_ }
							}
							$ipv4
						}
						
						# get-ciminstance win32_networkadapter | select name,macaddress,guid,status,networkaddresses,adaptertype,netconnectionid,netconnectionstatus,netenabled,physicaladapter | ft
							
						# get-ciminstance win32_networkadapterconfiguration | select description,dnshostname,dnsdomainsuffixsearchorder,ipaddress,ipenabled,settingid,macaddress | ft
							
						try {
							$adapterResults = Get-CimInstance -ClassName "Win32_NetworkAdapter" -ErrorAction $errAction
							$configResults = Get-CimInstance -ClassName "Win32_NetworkAdapterConfiguration" -ErrorAction $errAction
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
										$filteredAdapterResults = $physicalAdapterResults | Where {$_.Name -notlike "*Cisco AnyConnect*" } | Where {$_.Name -notlike "*bluetooth*"}
										$adapterData = $filteredAdapterResults | ForEach-Object {
											$adapterResult = $_
											$configResult = $configResults | Where { $_.SettingID -like $adapterResult.GUID }
											if($configResult) {
												$configResultCount = count $configResult
												if($configResultCount -eq 1) {
													if($configResult.MACAddress) {
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
												}
												elseif($configResultCount -lt 1) { $err = "No configuration found for one or more physical adapters, or configuration info is invalid!" }
												else { $err = "Multiple configurations found for one or more physical adapters!" }
											}
											else { $err = "No configuration found for one or more physical adapters!" }
										}
										$data = addm "NetAdapters" $adapterData $data
									}
									else { $err = "No adapter configuration info returned!" }
								}
								else { $err = "No adapter info returned!" }
							}
							if($err) {
								$data = addm "Error_NetInfo" $err $data
								$data.Error_Data = $true
							}
						}
						
						$data
					}
					
					$data = [PSCustomObject]@{
						"Error_Data" = $false
					}
				
					$data = Get-ComputerSystemInfo $data
					$data = Get-OperatingSystemInfo $data
					$data = Get-OperatingSystemInfo2 $data
					$data = Get-OfficeInfo $data
					$data = Get-ProfileInfo $data
					$data = Get-SystemEnclosureInfo $data
					$data = Get-BiosInfo $data
					$data = Get-TpmInfo $data
					$data = Get-NetworkAdapterInfo $data
					
					$data
				}
				
				$scriptBlock
			}
			
			function Do-Stuff {
				
				#log "Retrieving data for: `"$comp`"..." -L 1 -V 1
				
				$object = [PSCustomObject]@{
					"Name" = $comp
					"Error" = $false
					"Error_Invoke" = $false
				}
				
				$scriptBlock = Get-ScriptBlock
				
				try {
					$data = Invoke-Command -ComputerName $comp -ScriptBlock $scriptBlock -ErrorAction "Stop"
				}
				catch {
					$err = $_.Exception.Message
					if(-not $err) { $err = "Unknown error" }
				}
				finally {
					if(-not $err) {
						if($data) {
							# Merge new data into existing object
							$dataMembers = $data | Get-Member -MemberType "NoteProperty"
							$dataMembers | ForEach-Object {
								$object = addm $_.Name $data.$($_.Name) $object
							}
							if($data.Error_Data) { $object.Error = $true }
						}
					}
					else {
						$object.Error_Invoke = $err
						$object.Error = $true
					}
				}
				
				#log "Done retrieving data for: `"$comp`"." -L 1 -V 1
		
				$object
			}
			
			$comp = $_
			
			Do-Stuff
		}
		
		log "Done retrieving data."
			
		$objects | Sort Name
	}
	
	# Not all objects will have all the properties we're interested in.
	# Format-Table and Export-Csv will ignore properties that don't exist in the first object of an array.
	# If the computer represented by the first object in $objects was unresponsive it will be missing most properties,
	# and thus so will the output from these cmdlets.
	# Here's a drop-in solution that avoids having to pre-populate every object with null values for every property:
	# https://stackoverflow.com/a/44429084/994622
	# https://stackoverflow.com/a/70484836/994622
	function Unify-Properties {
		$Names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
		$InputCollected = @($Input)
		$InputCollected.ForEach({ 
			foreach ($Name in $_.psobject.Properties.Name) { $Null = $Names.Add($Name) }
		})
		$InputCollected | Select-Object @($Names)
	}
	
	function Output-Csv($objects) {
		log "-Csv was specified. Outputting gathered data to `"$Csv`"..."
		$objects | Export-Csv -Path $Csv -NoTypeInformation -Encoding Ascii
		log "Done."
		
	}
	
	function Print-Data($objects) {
		# Concise string truncation: https://stackoverflow.com/a/30856340/994622
		$errorTruncation = 26
		
		$printObjects = $objects | Select `
			Name,`
			@{
				Name = "InvokeError"
				Expression = { "$($_.Error_Invoke)"[0..$errorTruncation] -join "" }
			}, `
			@{
				Name = "DataError"
				Expression = { "$($_.Error_Data)"[0..$errorTruncation] -join "" }
			}, `
			Make, `
			Model, `
			Memory, `
			OsRelease, `
			OsBuild, `
			OsRev, `
			OsArch, `
			SystemTime, `
			LastBoot, `
			OsInstalled, `
			OfficeVer, `
			#NumUsers, `
			NumProfiles, `
			AssetTag, `
			Serial, `
			BIOS, `
			TPM, `
			@{
				Name = "MAC"
				Expression = { $_.NetAdapters.Mac }
			},
			@{
				Name = "IPv4"
				Expression = { $_.NetAdapters.Ipv4 }
			}
		
		Write-Host ($printObjects | Format-Table * | Out-String)
	}
	
	function Do-Stuff {
		$comps = Get-Comps
		if($comps) {
			$objects = Get-Data $comps
			$objects = $objects | Unify-Properties
			if($Csv) {
				Output-Csv $objects
			}
			Print-Data $objects
			if($PassThru) {
				$objects
			}
		}
	}
	
	Do-Stuff
	log "EOF"
}