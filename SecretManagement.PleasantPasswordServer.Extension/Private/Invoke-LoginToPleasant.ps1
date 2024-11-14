function Invoke-LoginToPleasant
{

    <#
        .SYNOPSIS
         Login to Pleasant Password Server

        .DESCRIPTION
         Login to Pleasant Password Server

        .PARAMETER AdditionalParameters
         The following values need to be in there:
           ServerURL
           Port

        .EXAMPLE

           $var = @{
              ServerURL = "https://ppsdc1.pps.net"
              Port      = "10001"
           }

           Invoke-LoginToPleasant -AdditionalParameters $var

        .NOTES
           Author: Constantin Hager
           Date: 2020-12-31
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [Hashtable]
        $AdditionalParameters
    )

    # Check if a login token already exists and is not expired
    if ($null -ne $script:LoginToken){
            write-verbose "Existing login token found"
        if ((get-date) -lt $script:loginToken.expires){
            write-verbose "Login token is valid"
            return $Script:loginToken.access_token
        } else {
            write-verbose "Login token is expired"
        }
    }

    # Get a token if none already exists or it is expired
    write-verbose "Generating new login token"
    
    $PasswordServerURL = [string]::Concat($AdditionalParameters.ServerURL, ":", $AdditionalParameters.Port)

    $SecretFile = Get-SecretFile

    # Create OAuth2 token params
    $tokenParams = @{
        grant_type = 'password';
        username   = $SecretFile.UserName;
        password   = $SecretFile.GetNetworkCredential().password;
    }

    $splat = @{
        Uri         = "$PasswordServerURL/OAuth2/Token"
        Method      = "POST"
        Body        = $tokenParams
        ContentType = "application/x-www-form-urlencoded"
        ErrorAction = "SilentlyContinue"
    }

    # Authenticate to Pleasant Password Server
    write-verbose $Splat.uri
    $JSON = Invoke-WebRequest @splat

    if ($null -eq $JSON)
    {
        return $null
    }
    else
    {
        # Generate and store JSON token
        $script:loginToken = ConvertFrom-Json $JSON.Content
        $script:loginToken | Add-Member -MemberType NoteProperty -Name "expires" -value (get-date).AddSeconds($script:LoginToken.expires_in)

        return $script:loginToken.access_token
    }

}