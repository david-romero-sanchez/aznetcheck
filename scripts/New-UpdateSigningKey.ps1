param(
    [string]$PrivateKeyPath = (Join-Path $HOME ".aznetcheck\update-signing-private.pem"),
    [string]$PublicKeyPath = (Join-Path $PSScriptRoot "..\src\AzNetCheck.Updater\Keys\update-signing-public.pem")
)

$ErrorActionPreference = "Stop"

if (Test-Path $PrivateKeyPath) {
    throw "Refusing to overwrite existing private key: $PrivateKeyPath"
}

$privateDirectory = Split-Path -Parent $PrivateKeyPath
New-Item -ItemType Directory -Path $privateDirectory -Force | Out-Null
$generatorProject = Join-Path $PSScriptRoot "UpdateKeyGenerator\UpdateKeyGenerator.csproj"
& dotnet run --project $generatorProject --configuration Release -- $PrivateKeyPath $PublicKeyPath
if ($LASTEXITCODE -ne 0) {
    throw "Key generation failed with exit code $LASTEXITCODE."
}

Write-Output "Private key written outside the repository to: $PrivateKeyPath"
Write-Output "Add the private key file contents as the GitHub Actions secret UPDATE_SIGNING_PRIVATE_KEY_PEM. Never commit or print the private key."