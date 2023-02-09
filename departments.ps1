########################################################################
# HelloID-Conn-Prov-Source-APD-iHCM-Departments
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
function ConvertTo-RawDataDepartmentObject {
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipeline
        )]
        [PSObject]
        $Departments
    )
    process {
        [System.Collections.Generic.List[object]]$listDepartments = @()

        foreach ($department in $Departments.organizationDepartments) {

            [System.Collections.Generic.List[object]]$auxFieldObjects = @()

            foreach ($auxField in $department.auxilliaryFields) {

                $auxFieldObj = [PSCustomObject]@{
                    FieldName = $auxField.NameCode.codeValue
                    FieldCode = $auxField.stringValue
                }

                if ($auxField.NameCode.codeValue -eq 'manager') {
                    $managerId = $auxField.stringValue
                }

                $auxFieldObjects.Add($auxFieldObj)
            }

            $departmentObj = [PSCustomObject]@{
                ExternalId        = $department.departmentCode.codeValue
                Name              = $department.departmentCode.shortname
                DisplayName       = $department.departmentCode.shortname
                ParentExternalId  = $department.parentDepartmentCode.codeValue
                #ManagerExternalId = $auxFieldObjects[3].FieldCode
                ManagerExternalId = $managerId
            }
            $listDepartments.Add($departmentObj)
        }
        $listDepartments
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
        }
        Invoke-RestMethod @splatRestMethodParameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
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
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.RequestUri), InvocationCommand: '$($HttpErrorObj.MyCommand)"
    }
}
#endregion

try {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $CertificatePassword)
    $accessToken = Get-ADPAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -Certificate $($config.Certificate)
} catch [System.Net.WebException] {
    $webEx = $PSItem
    $errorObj = ($($webEx.ErrorDetails.Message) | ConvertFrom-Json).response
    $PSCmdlet.WriteWarning("Could not retrieve ADP Departments. Error: '$($errorObj.applicationCode.message)' Code: '$($errorObj.applicationCode.code)'")
} catch [System.Exception] {
    $ex = $PSItem
    $PSCmdlet.WriteWarning("Could not retrieve ADP Departments. Error: '$($ex.Exception.Message)'")
}

try {
    $splatADPRestMethodParams = @{
        Url         = "$($config.BaseUrl)/core/v1/organization-departments"
        Method      = 'GET'
        AccessToken = $accessToken.access_token
        ProxyServer = $ProxyServer
        Certificate = $($config.Certificate)
    }
    Invoke-ADPRestMethod @splatADPRestMethodParams | ConvertTo-RawDataDepartmentObject | ConvertTo-Json -Depth 100 | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }
} catch [System.Net.WebException] {
    $webEx = $PSItem
    $errorObj = ($($webEx.ErrorDetails.Message) | ConvertFrom-Json).response
    $PSCmdlet.WriteWarning("Could not retrieve ADP Departments. Error: '$($errorObj.applicationCode.message)' Code: '$($errorObj.applicationCode.code)'")
} catch [System.Exception] {
    $ex = $PSItem
    $PSCmdlet.WriteWarning("Could not retrieve ADP Departments. Error: '$($ex.Exception.Message)'")
}
