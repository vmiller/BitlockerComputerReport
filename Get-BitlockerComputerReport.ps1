######################################################################################################
#
# NAME: Get-BitlockerComputerReport.ps1
#
# AUTHOR: Vaughn Miller
#
# Based on this Technet Gallery Script : http://gallery.technet.microsoft.com/4231a8a1-cc60-4e07-a098-2844353186ad
#
# Requires the Quest ActiveRoles Management Shell for Active Directory
# Installer from Quest can be downloaded here : http://www.quest.com/powershell/activeroles-server.aspx 
#
#######################################################################################################

# Check to make sure the path has been specified otherwise display a message and exit the script
param([string]$CsvFilePath)
if (!$CsvFilePath) {
    Write-Host ""
    Write-Host "Path not not specified!"
    Write-Host "Please specify the path for the output as a parameter e.g. : "
    Write-Host ".\Get-BitlockerComputerReport.ps1 """c:\reports\BitlockerReport.csv""""
    Exit
    }

# Check to make sure the correct snapins are installed and loaded otherwise exit the script
$snaps1 = Get-PSSnapin -Registered
$snaps2 = Get-PSSnapin Quest* -ErrorAction SilentlyContinue
$questsnap = 0
foreach ($snap1 in $snaps1) {
    if ($snap1.name -eq "Quest.ActiveRoles.ADManagement") {
        write-host "Quest Snapin Registered"
        $questsnap = 1
        }
    }
if ($questsnap -eq 0) {
    Write-Host "Quest Snapin not Registered."
    Write-Host "Please install the Quest ActiveRoles Management Shell for Active Directory"
    Write-Host "Download from : http://www.quest.com/powershell/activeroles-server.aspx"
    Exit
}

if ($questsnap -eq 1) {
    foreach ($snap2 in $snaps2) {
        if($snap2.name -eq "Quest.ActiveRoles.ADManagement") {
            Write-Host "Quest Snapin already loaded"
            $questsnap = 2
            }
        }
    if ($questsnap -ne 2) {
        Write-Host "Loading Quest Snapin..."
        Add-PSSnapin Quest.ActiveRoles.ADManagement
        }
    }


################################################################################
# Start of the main script
#################################################################################
$SearchContainer = "DN=Computers,DC=example,DC=com"

write-host "Starting query..."


#Query Active Directory
$BitLockerEnabled = Get-QADObject -SizeLimit 0 -IncludedProperties Name,ParentContainer | Where-Object {$_.type -eq "msFVE-RecoveryInformation"} | Foreach-Object {Split-Path -Path $_.ParentContainer -Leaf} | Select-Object -Unique
$computers = Get-QADComputer -SearchRoot $SearchContainer -SizeLimit 0 -IncludedProperties Name,OperatingSystem,ModificationDate,ParentContainer,msTPM-OwnerInformation | Where-Object {$_.operatingsystem -like "Windows 7*" -or $_.operatingsystem -like "Windows Vista*"} | Sort-Object Name

#Create array to hold computer information
$export = @()


foreach ($computer in $computers)
  {
    #Create custom object for each computer
    $computerobj = New-Object -TypeName psobject
    
    #Add desired properties to custom object
    $computerobj | Add-Member -MemberType NoteProperty -Name Name -Value $computer.Name
    $computerobj | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $computer.operatingsystem
    $computerobj | Add-Member -MemberType NoteProperty -Name ModificationDate -Value $computer.ModificationDate
    $computerobj | Add-Member -MemberType NoteProperty -Name ParentContainer -Value $computer.ParentContainer
    
    #Set HasBitlockerRecoveryKey to true or false, based on matching against the computer-collection with BitLocker recovery information
    if ($computer.name -match ('(' + [string]::Join(')|(', $bitlockerenabled) + ')')) {
    $computerobj | Add-Member -MemberType NoteProperty -Name HasBitlockerRecoveryKey -Value $true
    }
    else
    {
    $computerobj | Add-Member -MemberType NoteProperty -Name HasBitlockerRecoveryKey -Value $false
    }
    
    #Set HasTPM-OwnerInformation to true or false, based on the msTPM-OwnerInformation on the computer object
     if ($computer."msTPM-OwnerInformation") {
    $computerobj | Add-Member -MemberType NoteProperty -Name HasTPM-OwnerInformation -Value $true
    }
    else
    {
    $computerobj | Add-Member -MemberType NoteProperty -Name HasTPM-OwnerInformation -Value $false
    }
    
#Add the computer object to the array with computer information
$export += $computerobj
  }

#Export the array with computer information to the user-specified path
$export | Export-Csv -Path $CsvFilePath -NoTypeInformation
