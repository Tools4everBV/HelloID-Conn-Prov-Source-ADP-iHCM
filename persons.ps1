#####################################################
# HelloID-Conn-Prov-SOURCE-ADP-iHCM-Persons
#
# Version: 1.0.5.4
#####################################################

function Convert-ADPdate() {
    [CmdletBinding()]
    param(
        [String]
        $datefield
    )
    if ([string]::IsNullOrEmpty($datefield)) { $null }
    else { [datetime]::ParseExact($datefield, 'yyyy/MM/dd', $null).addhours(4) }

}

#region External functions
function Get-ADPWorkers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $BaseUrl,

        [Parameter(Mandatory)]
        [String]
        $ClientID,

        [Parameter(Mandatory)]
        [String]
        $ClientSecret,

        [Parameter(Mandatory)]
        [String]
        $CertificatePath,

        [Parameter(Mandatory)]
        [String]
        $CertificatePassword,

        [String]
        $ProxyServer
    )

    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $CertificatePassword)
        $accessToken = Get-ADPAccessToken -ClientID $ClientID -ClientSecret $ClientSecret -Certificate $certificate
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            Write-Verbose "Could not retrieve ADP Workforce employees. Error: $errorMessage"
        }
        else {
            Write-Verbose "Could not retrieve ADP Workforce employees. Error: $($ex.Exception.Message)"
        }
    }

    try {
        $skip = 1
        $totalJsonCorrected = $null
        DO {
            write-verbose -verbose -message "Reading information starting by record: $skip"
            $splatADPRestMethodParams = @{
                Url         = "$BaseUrl/hr/v2/workers?`$top=100&`$skip=" + $skip
                #Url = "$BaseUrl/hr/v2/worker-demographics?`$top=100&`$skip=" + $skip
                Method      = 'GET'
                AccessToken = $accessToken.access_token
                ProxyServer = $ProxyServer
                Certificate = $certificate
            }
            #$jsonCorrected = [Text.Encoding]::UTF8.GetString([Text.Encoding]::GetEncoding(28591).GetBytes((Invoke-ADPRestMethod @splatADPRestMethodParams).Content))
            #$jsonCorrected = (Invoke-ADPRestMethod @splatADPRestMethodParams).content | % { [System.Text.RegularExpressions.Regex]::Unescape($_)} | % { [System.Text.RegularExpressions.Regex]::Unescape($_)}
            #$totalJsonCorrected = $totalJsonCorrected + ($jsonCorrected | ConvertFrom-Json | ConvertTo-RawDataPersonObject )
            $tempFile = $env:TEMP + "\wokerfile.txt"
            $jsonCorrected = (Invoke-ADPRestMethod @splatADPRestMethodParams).Content
            $jsonCorrected | out-file $tempFile
            $totalJsonCorrected = $totalJsonCorrected + ((get-content -Path $tempFile -raw ) | ConvertFrom-Json | ConvertTo-RawDataPersonObject )
            remove-item -Path $tempFile -confirm:$false -force:$true
            $count = ($jsonCorrected | ConvertFrom-Json).workers.count
            $skip = $skip + 100
            write-verbose -verbose -message "numbers of found records: $count"


        }
        while ($count -gt 99)
        $totalJsonCorrected = $totalJsonCorrected | Where-Object { $_.AssocciateOID -ne $null }
        foreach ($person in $totalJsonCorrected) {
            Write-Output $person | ConvertTo-Json -Depth 100
        }
        # $totalJsonCorrected | Out-GridView
        # $totalJsonCorrected | ConvertTo-Json -Depth 100 | out-file C:\Temp\EBN\TotalJsonCorrected.txt


    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            Write-Verbose "Could not retrieve ADP Workforce employees. Error: $errorMessage"
        }
        else {
            Write-Verbose "Could not retrieve ADP Workforce employees. Error: $($ex.Exception.Message)"
        }
        $PSItem
    }
}
#endregion

#region Internal functions
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
    <#
    .SYNOPSIS
    Converts the ADP Worker object to a raw data object
    .DESCRIPTION
    Converts the ADP Worker object to a [RawDataPersonObject] that can be imported into HelloID
    .PARAMETER Workers
    The list of Workers from ADP Workforce
    .OUTPUTS
    System.Object[]
    #>
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
            # only filled associateOID's
            #if([string]::IsNullOrWhiteSpace($worker.associateOID)){
            # continue
            #} else {

            [System.Collections.Generic.List[object]]$contracts = @()
            $workerObj = [PSCustomObject]@{
                ExternalId     = $worker.workerID.idValue
                DisplayName    = $worker.person.legalName.formattedName
                AssocciateOID  = $worker.associateOID
                WorkerID       = $worker.workerID.idValue
                Status         = $worker.workerStatus.statusCode.shortname


                BirthDate      = Convert-ADPdate $worker.person.birthDate
                BirthPlace     = $worker.person.birthPlace.cityName
                # MaritalStatus = $worker.person.maritalStatusCode.shortname

                # Personal
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
                # Addres = ($worker.person.otherPersonalAddresses.streetName + " " + $worker.person.otherPersonalAddresses.buildingNumber)
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
            # }
        }
        $listWorkers
    }
}

function Select-CustomFields {
    <#
    .SYNOPSIS
    Flattens the [worker.customFieldGroup] array object
    .DESCRIPTION
    Flattens the [worker.customFieldGroup] array
    .PARAMETER CustomFields
    The StringFields array containing the customFields for a worker or assignment
    .EXAMPLE
    PS C:\> $worker.customFieldGroup
    stringFields
    ------------
    {@{nameCode=; stringValue=Nikolai}, @{nameCode=; stringValue=}, @{nameCode=; stringValue=RTM}, @{nameCode=; stringValue=tiva}...}
    PS C:\> Select-CustomFields -CustomFields $worker.customFieldGroup
    partnerFamilyName1 : Nikolai
    partnerFamilyName1Prefix :
    partnerInitials : RTM
    naamSamenstelling : tiva
    samengesteldeNaam : NDS Burghout
    loginName :
    verwijzendWerknemernummer : P001
    leefvormCode :
    Returns a PSCustomObject containing the customFields from the [worker.customFieldGroup] object
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSObject]
        $CustomFields
    )

    $properties = @(
        foreach ($attribute in $CustomFields.stringFields) {
            @{ Name = "$($attribute.nameCode.codeValue)"; Expression = { "$($attribute.stringValue)" }.GetNewClosure() }
        }
    )
    $CustomFields | Select-Object -Property $properties
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
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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


#region Script

$connectionSettings = ConvertFrom-Json $configuration
$splatGetADPWorkers = @{
    BaseUrl             = $($connectionSettings.BaseUrl)
    ClientID            = $($connectionSettings.ClientID)
    ClientSecret        = $($connectionSettings.ClientSecret)
    CertificatePath     = $($connectionSettings.CertificatePath)
    CertificatePassword = $($connectionSettings.CertificatePassword)
    ProxyServer         = $($connectionSettings.ProxyServer)
}
<#
    $splatGetADPWorkers = @{
    BaseUrl = "https://api.eu.adp.com"
    ClientID = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    ClientSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    CertificatePath = "C:\iHCM\crt.pfx"
    CertificatePassword = "xxxxxxxxxxxxxxxxx"
    ProxyServer = ""
    }
    #>
Get-ADPWorkers @splatGetADPWorkers
#endregion
