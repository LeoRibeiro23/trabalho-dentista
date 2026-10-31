$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js não encontrado. Instale o Node.js LTS e execute este script novamente."
    exit 1
}

if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    Write-Error "npm.cmd não encontrado. Reinstale o Node.js LTS incluindo o npm."
    exit 1
}

if (-not (Test-Path (Join-Path $PSScriptRoot "node_modules"))) {
    npm.cmd install
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Falha ao instalar dependências."
        exit $LASTEXITCODE
    }
}

$securePassword = Read-Host "Digite a senha do administrador (a senha configurada para admin@gmail.com)" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$exitCode = 1

try {
    $env:ADMIN_EMAIL = "admin@gmail.com"
    $env:ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    npm.cmd start
    $exitCode = $LASTEXITCODE
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    Remove-Item Env:\ADMIN_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:\ADMIN_EMAIL -ErrorAction SilentlyContinue
}

exit $exitCode
