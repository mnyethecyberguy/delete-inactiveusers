<#
    .SYNOPSIS
    Script to query for inactive user objects in Active Directory and delete them.

    .DESCRIPTION
    Script to query for inactive user objects in Active Directory and delete them.

    .EXAMPLE

    .NOTES
    ###################################################################################################
    # Author: Michael Nye - https://github.com/mnyethecyberguy                                        #
    # Project: Delete-InactiveUsers - https://github.com/mnyethecyberguy/delete-inactiveusers         #
    # Module Dependencies: ActiveDirectory                                                            #
    # Permission level: Domain Admin                                                                  #
    # Powershell v5 or greater                                                                        #
    ###################################################################################################
#>

# ------------------- NOTES -----------------------------------------------
# 

# -------------------------------------------------------------------------

# ------------------- IMPORT AD MODULE (IF NEEDED) ------------------------
Import-Module ActiveDirectory


# ------------------- BEGIN USER DEFINED VARIABLES ------------------------
$SCRIPTNAME    	= "Delete-InactiveUsers"
$SCRIPTVERSION 	= "1.0"

# ------------------- END OF USER DEFINED VARIABLES -----------------------


# ------------------- BEGIN MAIN SCRIPT VARIABLES -------------------------
# Establish variable with date/time of script start
$Scriptstart = Get-Date -Format G

$strCurrDir 	= split-path $MyInvocation.MyCommand.Path
$strLogFolder 	= "$SCRIPTNAME -{0} {1}" -f ($_.name -replace ", ","-"),($Scriptstart -replace ":","-" -replace "/","-")
$strLogPath 	= "$strCurrDir\logs"

# Create log folder for run and logfile name
New-Item -Path $strLogPath -name $strLogFolder -itemtype "directory" -Force > $NULL
$LOGFILE 		= "$strLogPath\$strLogFolder\$SCRIPTNAME.log"


# error action preference must be set to stop for script to function properly, default setting is continue
$ErrorActionPreference = 'stop'

# Set date for inactivity.  Will be compared against whenCreated and lastLogonTimeStamp attributes.  Today minus 30 days.
$dateInactive = (Get-Date).AddDays(-30).ToFileTimeUtc()

# Set domain FQDN and searchbase to query
$strDomainFQDN = "my.domain.fqdn"
$strSearchBase = "ou=myou,dc=mydomain,dc=com"

# setup output file to export results
$csvInactiveUsers = "$strLogPath\$strLogFolder\$strDomainFQDN.csv"

# setup array to store results
$arrInactiveUsers      = @()

# Set list of user properties to pull
$strUserProperties = 'cn','lastLogonTimestamp','pwdLastSet','whenCreated','whenChanged','sAMAccountName','distinguishedName'

# Create ldap query.
# Requirements:
#   1) whenCreated > 30 days
#   2) and lastLogonTimeStamp = null
#   OR
#   1) whenCreated > 30 days
#   2) and lastLogonTimeStamp > 30 days
$queryLdap = '(|(&(whenCreated<=' + $dateInactive + ')(!lastLogonTimeStamp=*))(lastLogonTimeStamp<=' + $dateInactive + '))'


# ------------------- END MAIN SCRIPT VARIABLES ---------------------------


# ------------------- DEFINE FUNCTIONS - DO NOT MODIFY --------------------

Function Writelog ($LogText)
{
	$date = Get-Date -format G
	
    write-host "$date $LogText"
	write-host ""
	
    "$date $LogText" >> $LOGFILE
	"" >> $LOGFILE
}

Function genReports
{
	if ($arrInactiveUsers.Count -gt 0)
	{
		$arrInactiveUsers | Export-CSV -NoTypeInformation $csvInactiveUsers
	}
}

Function BeginScript () {
    Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** BEGIN SCRIPT AT $Scriptstart ****"
    Writelog "**** Script Name:     $SCRIPTNAME"
    Writelog "**** Script Version:  $SCRIPTVERSION"
    Writelog "-------------------------------------------------------------------------------------"

    $error.clear()
}

Function EndScript () {
	Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** SCRIPT RESULTS ****"
    Writelog "**** Results file: $csvInactiveUsers"
    Writelog "-------------------------------------------------------------------------------------"

    $Scriptfinish = Get-Date -Format G
	$span = New-TimeSpan $Scriptstart $Scriptfinish
	
  	Writelog "-------------------------------------------------------------------------------------"
  	Writelog "**** $SCRIPTNAME script COMPLETED at $Scriptfinish ****"
	Writelog $("**** Total Runtime: {0:00} hours, {1:00} minutes, and {2:00} seconds ****" -f $span.Hours,$span.Minutes,$span.Seconds)
	Writelog "-------------------------------------------------------------------------------------"
}

# ------------------- END OF FUNCTION DEFINITIONS -------------------------


# ------------------- SCRIPT MAIN - DO NOT MODIFY -------------------------

BeginScript

# Collect Inactive Users
Try
{
    $arrTmpInactiveUsers = Get-ADUser -Server $strDomainFQDN -SearchBase $strSearchBase -LDAPFilter $queryLdap -Properties $strUserProperties | Select-Object $strUserProperties
    Writelog "**** Successfully collected inactive users for the $strDomainFQDN domain - (count: $($arrTmpInactiveUsers.Count))"
    Writelog "-------------------------------------------------------------------------------------"

    
    ForEach ($user in $arrTmpInactiveUsers)
    {
        If ($null -ne $user.lastLogonTimestamp)
        {
            $lastLogon = [datetime]::FromFileTime($user.lastLogonTimestamp)

            $user | Add-Member -MemberType NoteProperty -Name LastLogonComputed -Value $lastLogon -Force
        }

        $arrInactiveUsers += $user

        $user | Remove-ADObject -Server $strDomainFQDN -Recursive -Confirm:$false

        Writelog "**** Deleted $($user.sAMAccountname)"

        $countSuccess++
    }
}
Catch
{
    Writelog "**** No inactive users found for the $strDomainFQDN domain"
    Writelog "-------------------------------------------------------------------------------------"
}


genReports

# ------------------- END OF SCRIPT MAIN ----------------------------------


# ------------------- CLEANUP ---------------------------------------------


# ------------------- SCRIPT END ------------------------------------------
$error.clear()

EndScript
