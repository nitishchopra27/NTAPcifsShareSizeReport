#requires -version 4
<#
.SYNOPSIS
  <Overview of script>

.DESCRIPTION
  <Brief description of script>

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  <Inputs if any, otherwise state None>

.OUTPUTS
  <Outputs if any, otherwise state None>

.NOTES
  Version:        1.0
  Author:         <Name>
  Creation Date:  <Date>
  Purpose/Change: Initial script development

.EXAMPLE
  <Example explanation goes here>
  
  <Example goes here. Repeat this attribute for more than one example>
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------
[CmdletBinding()]
Param (
  [Parameter(Mandatory=$True,ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True,HelpMessage="Location of csv file")]
  [string[]]$settingsFilePath = (Read-Host "Location of Config File")
  # [Parameter(Mandatory=$True,ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True,HelpMessage="Cluster Name")]
  #[string[]]$prdClusters,
)
#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Import-Credentials{
   <#
   .SYNOPSIS
   This function decrypts registry key values.
   .DESCRIPTION
   Used Microsoft's DPAPI to decrypt binary values.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .EXAMPLE
   Import-Credentials -registryPath "HKLM\Software\Scripts" -registryValue "Value"
   .NOTES
   The example provided decryptes the value of the registry key "HKLM\Software\Scripts\Value"
   Credentials can only be decrypted by the same user account that was used to export them.
   See the Microsoft DPAPI documentation for further information
   .LINK
   http://msdn.microsoft.com/en-us/library/ms995355.aspx
   http://msdn.microsoft.com/en-us/library/system.security.cryptography.protecteddata.aspx
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryPath,
      [Parameter(Position=1,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryValue
   )
   #'---------------------------------------------------------------------------
   #'Decrypt value from binary registry key
   #'---------------------------------------------------------------------------
   $keyPath = "HKLM\$registryPath\$registryValue"
   Try{
      [void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
      $secret    = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath).GetValue($registryValue)
      $decrypted = [System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($secret, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
   }Catch{
      Write-Warning -Message $("Failed Reading Registry Key ""$keyPath"". Error " + $_.Exception.Message)
      $decrypted = ""
   }
   Return $decrypted;
}
function Check-LoadedModule {
  Param(
    [parameter(Mandatory = $true)]
    [string]$ModuleName
  )
  Begin {
    Write-Log -Message "*** Importing Module: $ModuleName"
  }
  Process {
    $LoadedModules = Get-Module | Select Name
    if ($LoadedModules -notlike "*$ModuleName*") {
      try {
        Import-Module -Name $ModuleName -ErrorAction Stop
      }
      catch {
        Write-Log -Message "Could not find the Module on this system. Error importing Module" -Severity Error
        Break
      }
    }
  }
  End {
    If ($?) {
      Write-Log -Message "Module $ModuleName is imported Successfully" -Severity Success
    }
  }
}
function Connect-Cluster {
  Param (
    [parameter(Mandatory = $true)]
    [string]$strgCluster
  )
  Begin {
    Write-Log -Message "*** Connecting to storage cluster $strgCluster"
  }  
  Process {  
    try {
      Add-NcCredential -Name $strgCluster -Credential $ControllerCredential
      Connect-nccontroller -Name $strgCluster -HTTPS -Timeout 600000 -ErrorAction Stop | Out-Null 
    }
    catch {
      Write-Log -Message "Failed Connecting to Cluster $strgCluster : $_." -Severity Error
      Break
    }
  }
  End {
    If ($?) {
      Write-Log -Message  "Connected to $strgCluster" -Severity Success
    }
  }
}
function Write-ErrMsg {
  [CmdletBinding()]
  Param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$msg
  )
  Process {
    $fg_color = "White"
    $bg_color = "Red"
    Write-host $msg -ForegroundColor $fg_color -BackgroundColor $bg_color
  }
}
function Write-Msg {
  [CmdletBinding()]
  Param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$msg
  )
  Process {
    $color = "yellow"
    Write-host ""
    Write-host $msg -foregroundcolor $color
    Write-host ""
  }
}
function Write-Log {
  [CmdletBinding()]
  Param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
 
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Information','Success','Error')]
    [string]$Severity = 'Information'
  )
  Process { 
    [pscustomobject]@{
    #"Time" = (Get-Date -f g);
    "Severity" = $Severity;
    "Message" = $Message;
    } | Export-Csv -Path $scriptLogPath -Append -NoTypeInformation
  }
}
function Create-Database {
  Param(
    [parameter(Mandatory = $true)]
    [array]$clusters,
    [parameter(Mandatory = $true)]
    [string]$fLocation
  )
  Begin {
    Write-Log -Message "*** Starting function Create-Database for $clusters" -Severity Information
  }
  Process {
        $db = @{
        "cluster" = @{};
        "vserver" = @{};
        "volume" = @{};
        "cifs_share" = @{};
    }
    $clusters | ForEach-Object {
    $cluster = $_
    Connect-Cluster -strgCluster $cluster
        
    # get cluster info
    try {
        $info = Get-NcCluster -EA Stop
    }
    catch {
       Write-Log -Message "Could not run Get-NcCluster: $_.Exception.Message" -Severity Error
    }
    $addr = $info.NcController.Address.IpAddressToString
    $newcluster = [PSCustomObject]@{
        "name" = $info.ClusterName;
        "location" = $info.ClusterLocation;
        "primary_address" = $addr;
        "serial_number" = $info.ClusterSerialNumber;
    }
    $db["cluster"][$cluster] = $newcluster
    Write-Log -Message "Collected information about the cluster" -Severity Success

    # get vserver info
        try {
            $vservers = Get-NcVserver -Query @{VserverType='data'}
        }
        catch {
            Write-Log -Message "Could not run Get-NcVserver for cluster: $_.Exception.Message" -Severity Error
        }
    
    $vservers | % {
	    $vserver = $_
        $vserverName = $vserver.VserverName
        $protos = $vserver.AllowedProtocols
	    $newvserver = [PSCustomObject]@{
            "name" = $vserver.VserverName;
            "type" = $vserver.VserverType;
            "comment" = $vserver.Comment;
            "admin_state" = $vserver.State;
            "nfs_allowed" = $([bool] ($protos -contains "nfs"));
            "cifs_allowed" = $([bool] ($protos -contains "cifs"));
            "operational_state" = $vserver.OperationalState;
	    }
        $db["vserver"][$vserverName] = $newvserver
        Write-Log -Message "Collected information about the Vserver : $vserverName " -Severity Success

        # get cifs shares info
        try {
            $cifsshares = Get-NcCifsShare -VserverContext $vserverName -ErrorAction Stop | ?{$_.cifsserver -notlike "*DR*" -and $_.path -ne '/'}
        }
        catch {
            Write-Log -Message "Could not run Get-NcCifsShare for $vserverName : $_.Exception.Message" -Severity Error
        }
        $cifsshares | % {
	        $share = $_
            $shareId = $vserverName+":"+$share.ShareName
            $cpath = $share.Path
            $cifsServer = $share.CifsServer
            [array]$cpathArray = $cpath.split("/")
            foreach ($cp in $cpathArray) { 
               if ($cp -like "*$cifsServer*") {
                  $cVolume = $cp
               } 
               else {
                  if ($cpathArray[1] -like 'vol'){
                    $cVolume = $cpathArray[2]
                  }
                  else {$cVolume = $cpathArray[1]}
               }
            }

	        $newshare = [PSCustomObject]@{
		        "name" = $share.ShareName;
		        "path" = $share.Path;
		        "comment" = $share.Comment;
                "shareVolume" = $cVolume;
                "vserver" = $share.CifsServer;
                "clusterName" = $info.ClusterName;
                "clusterLocation" = $fLocation;
	        }
	        $db["cifs_share"][$shareId] = $newshare
	    } # End of Get-NcCifsShare
        Write-Log -Message "Collected information about all the shares on Vserver : $vserverName" -Severity Success

        # get volumes info
        $svmrootvol1 = $vserverName+"_root"
        $svmrootvol2 = "rootvol"
        try {
            $volumeTemplate = Get-NcVol -Template
            Initialize-NcObjectProperty -Object $volumeTemplate -Name VolumeSpaceAttributes
            $volumes = Get-NcVol -VserverContext $vserverName -Attributes $volumeTemplate -Query @{VolumeStateAttributes=@{IsVserverRoot=$false}}
        }
        catch {
            Write-Log -Message "Could not run Get-NcVol for $vserverName : $_.Exception.Message" -Severity Error
        }
        $volumes | % {
            $vol = $_
            $volId = $vserverName+":"+$vol.Name
            $newvol = [PSCustomObject]@{
            "name" = $vol.Name;
            "state" = $vol.State;
            "Used"=[int64]($vol.VolumeSpaceAttributes.SizeUsed / 1GB);
            }
            $db["volume"][$volId] = $newvol
        } # End of Get-NcVol
        Write-Log -Message "Collected information about all the volumes on Vserver : $vserverName" -Severity Success

	} # End of Get-NcVserver
    
    } # End of $clusters array
    return $db
  } # End of Process loop
  End {
    If ($?) {
      Write-Log -Message "Data Collection for $clusters Completed Successfully"
    }
  }
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Any Global Declarations go here
[string]$reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
[String]$scriptPath     = $PSScriptRoot
[String]$logName        = "cifs_share_size_log.csv"
[String]$scriptLogP     = $scriptPath + "\Logs"
[String]$scriptLogPath  = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $logName
[String]$outName        = "cifs_share_size_details.csv"
[String]$outPath        = $scriptPath + "\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $outName
[string]$prddbLogFile   = "prddb-"+$pcluster+".json"
[string]$prddbLogPath   = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $prddbLogFile
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'
[String]$registryPath = "Software\NetApp\Scripts\Syslog";
[String]$username     = Import-Credentials -registryPath $registryPath -registryValue "Key"
[String]$password     = Import-Credentials -registryPath $registryPath -registryValue "Value"
$ssPassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$ControllerCredential = New-Object System.Management.Automation.PsCredential($username,$ssPassword)
#-----------------------------------------------------------[Execution]------------------------------------------------------------
# Create Log Directory
if ( -not (Test-Path $scriptLogP) ) { 
       Try{
          New-Item -Type directory -Path $scriptLogP -ErrorAction Stop | Out-Null
       }
       Catch{
          Exit -1;
       }
}
Write-Log -Message "*** Start Collecting NetApp Volume/Share Utilization details " -Severity Information
# Test for input file 
if (-not (Test-Path $settingsFilePath)) {
    Write-Log -Message "Script Configuration file with Parameters not found." -Severity Error
    Write-Log -Message "Exiting Script." -Severity Error
    exit
}
# Import contents of input csv file
try {
  $contents = Import-Csv -Path $settingsFilePath
  Write-Log -Message "Contents of $settingsFilePath are imported successfully" -Severity Success
}
catch {
  Write-Log -Message “Cannot Get Cluster HA Info: $_.” -Severity Error
  exit 
}
#Import Modules
Check-LoadedModule DataONTAP

# Traverse through the contents of the input file and collect Volume/Share Utilization
$contents | % {
  $prdclusters = $_.cluster
  $fileLocation = $_.location
  $ocumServer  = $_.ocumserver
  $opmServer   = $_.opmServer

Write-Log -Message "*** Collecting data from $prdClusters"
$prddb = Create-Database -cluster $prdClusters -fLocation $fileLocation
#$prddb | ConvertTo-Json -Depth 4 | Out-File $prddbLogPath -Append

 Write-Log -Message "*** Collate NetApp Volume/Share Utilization details in output file " -Severity Information
 $($prddb.cifs_share.keys) | % {
    $prshare = $_
    ($psvm, $pshare) = $prshare.split(":")
    
    $hostingVolume = $($prddb.cifs_share.$prshare.shareVolume)

    $dbVolumeLoc = $psvm+":"+$hostingVolume
    $props = [ordered]@{'clusterName' = $($prddb.cifs_share.$prshare.clusterName);
            'Location' = $($prddb.cifs_share.$prshare.clusterLocation);
            'cifsServerName' = $($prddb.cifs_share.$prshare.vserver);
            'cifsShareName' = $pshare;
            'cifsSharePath' = $($prddb.cifs_share.$prshare.path);
            'cifsShareComments' = $($prddb.cifs_share.$prshare.comment);
            'hostingVolume' = $($prddb.cifs_share.$prshare.shareVolume);
            'hostingVolumeUsedSize(GB)' = $($prddb.volume.$dbVolumeLoc.Used);
    }

    $obj = New-Object -TypeName PSObject -Property $props
    $obj | Export-Csv -Path $outPath -Append -NoTypeInformation
 }
 Write-Log -Message "FINISHED collecting NetApp Volume/Share Utilization details for cluster : $prdclusters " -Severity Success
}

Write-Log -Message "*** Sending Email " -Severity Information

[string[]]$recipients  = "nitish.chopra@lab.local" 

$htmlhead="<html>
            <style>
             BODY{font-family: Arial; font-size: 8pt;}
             H1{font-size: 16px;}
             H2{font-size: 14px;}
             H3{font-size: 12px;}
             TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
             TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
             TD{border: 1px solid black; padding: 5px; }
             td.pass{background: #7FFF00;}
             td.warn{background: #FFE600;}
             td.fail{background: #FF0000; color: #ffffff;}
             td.info{background: #85D4FF;}
             </style>
             <body>
             <h1 align=""Left"">NetApp Volume/Share Utilization</h1>
             <h3 align=""Left"">Generated: $reportime</h3>"
 
$summaryhtml = "<p>This report has an attachment which contains NetApp Volume/Share Utilization from Metro and Interstate site NetApp storage systems within Australia.</p>"
$htmltail = "</body>
             </html>" 
$htmlreport = $htmlhead + $summaryhtml + $htmltail

$splat = @{
  'to' = $recipients;
  'subject' = "NetApp Volume/Share Utilization - " + $reportime;
  'SmtpServer' = "appsmtp.lab.local";
  'from' = "Automated_Reports@lab.local";
  'body' = $htmlreport;
  'BodyAsHtml' = $true;
}
Send-MailMessage @splat -Encoding ([System.Text.Encoding]::UTF8) -Attachments $outPath

Write-Log -Message "*** Email Sent " -Severity Success