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
		#log "    Name,Error,Make,Model,Memory,Serial,BiosVersion" -NoLog
		
		$data = $comps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
			function log($msg) {
				$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
				$msg = "[$ts] $msg"
				Write-Host $msg
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
			
			#log "    $($object.Name),$($object.Make),$($object.Model),$($object.Memory),$($object.Serial),$($object.BIOS),$($object.TPM),$($object.Error)"
			
			$object
		}
		log "Done retrieving data."
			
		$data
	}
	
	function Output-Csv($data) {
		log "-Csv was specified. Outputting gathered data to `"$CSVPATH`"..."
		$data | Export-Csv -Path $CSVPATH -NoTypeInformation -Encoding Ascii
		log "Done."
		
	}
	
	$comps = Get-Comps
	$data = Get-Data $comps
	if($Csv) {
		Output-Csv $data
	}
	log "EOF"
	$data
}