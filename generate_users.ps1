param(
  [Parameter(Mandatory=$true)][string[]]$Users,     # e.g. -Users alice bob charlie
  [string]$OutDir = ".\credentials",
  [string]$Relay  = "http://127.0.0.1:8787",        # change to your domain later
  [string]$Tos    = "v1-2025-10-02"
)

New-Item -Force -ItemType Directory $OutDir | Out-Null

# map of user_id -> secret
$map = @{}
# also collect a pretty table for your notes
$issued = @()

foreach ($u in $Users) {
  $id = "u-" + ([guid]::NewGuid().ToString("N"))
  $secret = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))

  $map[$id] = $secret

  $cred = [ordered]@{
    relay_url     = $Relay
    tos_version   = $Tos
    client_id     = $id
    client_secret = $secret
  }
  $json = ($cred | ConvertTo-Json -Compress)
  $file = Join-Path $OutDir "$($id).json"
  Set-Content -Encoding ASCII -Path $file -Value $json

  $issued += [pscustomobject]@{ user=$u; client_id=$id; file=$file }
}

# emit .env fragment for server
$kv = $map.GetEnumerator() | ForEach-Object { '"{0}":"{1}"' -f $_.Key, $_.Value }
$envLine = "HMAC_CLIENTS_JSON={" + ($kv -join ",") + "}"
$envFile = ".\HMAC_CLIENTS_JSON.env.txt"
"# paste into server .env:`n$envLine`n" | Set-Content -Encoding ASCII -Path $envFile

Write-Host ""
Write-Host "Issued credentials:" -ForegroundColor Cyan
$issued | Format-Table -AutoSize

Write-Host ""
Write-Host "Wrote HMAC map to $envFile" -ForegroundColor Green
Write-Host "Credentials folder: $OutDir" -ForegroundColor Green
