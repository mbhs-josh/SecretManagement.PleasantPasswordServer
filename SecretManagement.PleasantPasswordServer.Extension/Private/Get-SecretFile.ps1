function Get-SecretFile
{
    $FilePath = Join-Path -Path $env:TEMP -ChildPath "PleasantCred.xml"

    if (Test-Path -Path $FilePath)
    {
        $Credential = Import-Clixml -Path $FilePath
        Write-Verbose "Credentials found for user '$($Credential.Username)'."
        return $Credential
    }
    else
    {
        throw "Credential File not found. Please import the module and run New-PleasantCredential to create the file."
    }
}