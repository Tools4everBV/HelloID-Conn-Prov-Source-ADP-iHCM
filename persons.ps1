########################################################################
# HelloID-Conn-Prov-Source-APD-iHCM-Persons
#
# Version: 1.0.0
########################################################################
# Initialize default value's
$config = $Configuration | ConvertFrom-Json

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#region functions
function Convert-ADPDate() {
    [CmdletBinding()]
    param(
        [string]
        $DateField
    )

    if (![string]::IsNullOrEmpty($datefield)) {
        [DateTime]::ParseExact($datefield, 'yyyy/MM/dd', $null).addhours(4)
    }
}

function Get-ADPAccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $ClientID,

        [Parameter(Mandatory)]
        [String]
        $ClientSecret,

        [X509Certificate]
        $Certificate
    )

    $headers = @{
        "content-type" = "application/x-www-form-urlencoded"
    }

    $body = @{
        client_id     = $ClientID
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }

    try {
        $splatRestMethodParameters = @{
            Uri         = 'https://accounts.eu.adp.com/auth/oauth/v2/token'
            Method      = 'POST'
            Headers     = $headers
            Body        = $body
            Certificate = $certificate
        }
        Invoke-RestMethod @splatRestMethodParameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Invoke-ADPRestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $Url,

        [Parameter(Mandatory)]
        [String]
        $Method,

        [Parameter(Mandatory)]
        [String]
        $AccessToken,

        [AllowNull()]
        [AllowEmptyString()]
        [String]
        $ProxyServer,

        [Parameter(Mandatory)]
        [X509Certificate]
        $Certificate
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept"        = "application/json"
    }

    if ([string]::IsNullOrEmpty($ProxyServer)) {
        $proxy = $null
    }
    else {
        $proxy = $ProxyServer
    }

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        $splatRestMethodParameters = @{
            Uri             = $Url
            Method          = $Method
            Headers         = $headers
            Proxy           = $proxy
            UseBasicParsing = $true
            Certificate     = $Certificate
            ContentType     = 'application/json;charset=utf-8'
        }
        Invoke-WebRequest @splatRestMethodParameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function ConvertTo-RawDataPersonObject {
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipeline
        )]
        [PSObject]
        $Workers
    )

    process {
        [System.Collections.Generic.List[object]]$listWorkers = @()
        foreach ($worker in $workers.workers) {

            [System.Collections.Generic.List[object]]$contracts = @()
            $workerObj = [PSCustomObject]@{
                ExternalId     = $worker.workerID.idValue
                DisplayName    = $worker.person.legalName.formattedName
                AssocciateOID  = $worker.associateOID
                WorkerID       = $worker.workerID.idValue
                Status         = $worker.workerStatus.statusCode.shortname


                BirthDate      = Convert-ADPdate $worker.person.birthDate
                BirthPlace     = $worker.person.birthPlace.cityName

                LastName       = $worker.person.legalName.familyName1
                FormattedName  = $worker.person.legalName.formattedName
                GivenName      = $worker.person.legalName.givenName
                Initials       = $worker.person.legalName.initials
                NickName       = $worker.person.legalName.nickName
                MiddleName     = $worker.person.legalName.middleName
                insertions     = $worker.person.legalName.familyName1prefix
                Salutation     = $worker.person.legalName.preferredSalutations.salutationCode.codeValue
                PrivateMail    = $worker.person.communication.emails.emailUri
                PrivateMobile  = $worker.person.communication.mobiles.formattedNumber
                PrivatePhone   = $worker.person.communication.landlines.formattedNumber
                BuildingNumber = $worker.person.otherPersonalAddresses.buildingNumber

                City           = $worker.person.otherPersonalAddresses.cityName
                County         = $worker.person.otherPersonalAddresses.countryCode
                ZipCode        = $worker.person.otherPersonalAddresses.postalCode
                streetName     = $worker.person.otherPersonalAddresses.streetName
                PrimaryAddress = $worker.person.otherPersonalAddresses.deliveryPoint

                #BusinessCommunication
                EmailAddress   = $worker.businessCommunication.emails.emailUri
                LandLine       = $worker.businessCommunication.landLines.formattedNumber
                Mobile         = $worker.businessCommunication.mobiles.formattedNumber
                Gender         = $worker.person.genderCode.codeValue
                Contracts      = $contracts
            }
            $assignmentNumber = 1
            if ($null -ne $worker.workAssignments) {

                foreach ($assignment in $worker.workAssignments) {
                    if ((Convert-ADPdate $assignment.terminationDate) -eq $null -or ((New-TimeSpan -Start (Get-date ) -End (Convert-ADPdate $assignment.terminationDate)).days -gt -90) ) {
                        $assignmentObj = [PSCustomObject]@{
                            ExternalID              = $worker.workerID.idValue + "-" + $assignmentNumber
                            PrimaryIndicator        = $assignment.primaryIndicator
                            StartDate               = Convert-ADPdate $assignment.jobCode.effectiveDate
                            EndDate                 = Convert-ADPdate $assignment.terminationDate
                            hireDate                = Convert-ADPdate $assignment.hireDate
                            DateOfLeaving           = Convert-ADPdate $assignment.expectedTerminationDate
                            WorkerTypeCode          = $assignment.workerTypeCode.shortName
                            WorkerTypeDescription   = $assignment.workerTypeCode.longName
                            Location                = $assignment.homeWorkLocation.address.countryCode
                            PayGroupCode            = $assignment.payrollGroupCode
                            EmployeeCode            = $assignment.payrollFileNumber
                            JobTitleCode            = $assignment.jobCode.codeValue
                            PersonalJobTitle        = $assignment.jobTitle
                            FTE                     = $assignment.fullTimeEquivalenceRatio
                            CostCentre              = $assignment.assignmentCostCenters.costCenterID
                            ManagerName             = $assignment.reportsTo.reportsToWorkerName.formattedName
                            ManagerType             = $assignment.reportsTo.reportsToRelationshipCode.shortName
                            ManagerID               = $assignment.reportsTo.workerID.idValue
                            HoursPerWeek            = $assignment.standardHours.hoursQuantity
                            HoursQuantity           = $assignment.standardHours.unitCode.longName
                            StandardHoursQuantity   = $assignment.standardHours.unitCode.shortName
                            OrganizationalUnitscode = $assignment.homeOrganizationalUnits.nameCode.codeValue[0]
                            OrganizationalUnitsname = $assignment.homeOrganizationalUnits.nameCode.shortName[0]
                        }
                        $contracts.Add($assignmentObj)
                    }
                    $assignmentNumber ++
                }
                $listWorkers.Add($workerObj)
            }
        }
        $listWorkers
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )

    process {
        $HttpErrorObj = @{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj['ErrorMessage'] = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToend()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.RequestUri), InvocationCommand: '$($HttpErrorObj.MyCommand)"
    }
}
#endregion

try {
    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $CertificatePassword)
        $accessToken = Get-ADPAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -Certificate $($config.Certificate)
    } catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            Write-Verbose "Could not retrieve ADP iHCM employees. Error: $errorMessage"
        } else {
            Write-Verbose "Could not retrieve ADP iHCM employees. Error: $($ex.Exception.Message)"
        }
    }

    $skip = 1
    $totalJsonCorrected = $null
    do {
        Write-Verbose -Verbose -Message "Reading information starting by record: $skip"
        $splatADPRestMethodParams = @{
            Url         = "$($config.BaseUrl)/hr/v2/workers?`$top=100&`$skip=" + $skip
            Method      = 'GET'
            AccessToken = $accessToken.access_token
            Certificate = $($config.Certificate)
        }

        $tempFile = $env:TEMP + "\wokerfile.txt"
        $jsonCorrected = (Invoke-ADPRestMethod @splatADPRestMethodParams).Content
        $jsonCorrected | Out-File $tempFile
        $totalJsonCorrected = $totalJsonCorrected + ((get-content -Path $tempFile -raw ) | ConvertFrom-Json | ConvertTo-RawDataPersonObject )
        Remove-Item -Path $tempFile -Confirm:$false -Force:$true
        $count = ($jsonCorrected | ConvertFrom-Json).workers.count
        $skip = $skip + 100
        Write-Verbose -Verbose -Message "numbers of found records: $count"
    }
    while ($count -gt 99)
    $totalJsonCorrected = $totalJsonCorrected | Where-Object { $_.AssocciateOID -ne $null }

    foreach ($person in $totalJsonCorrected) {
        Write-Output $person | ConvertTo-Json -Depth 100
    }
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorMessage = Resolve-HTTPError -Error $ex
        Write-Verbose "Could not retrieve ADP iHCM employees. Error: $errorMessage"
    } else {
        Write-Verbose "Could not retrieve ADP iHCM employees. Error: $($ex.Exception.Message)"
    }
}
