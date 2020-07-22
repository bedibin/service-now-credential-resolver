# Secret Server is running with a self-signed certificate)
#[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
#netsh winhttp import proxy source=ie

# Secret Server uses an OAuth2 Password Grant Type
$oauth2_grant = Invoke-WebRequest -Method Post -Uri "https://tmg.secretservercloud.com/oauth2/token" -Body @{ 'username' = $env:TSS_USERNAME; 'password' = $env:TSS_PASSWORD; 'grant_type' = 'password'; }

Set-Content -Path oauth2_grant.json -Value $oauth2_grant
# utf8 (with BOM) yields a file that, when read with Apache Commons FileUtils.readFileToString, does not work as an access_token, so we omit the BOM
Set-Content -Path token.txt -Encoding utf8NoBOM -NoNewline -Value ($oauth2_grant | ConvertFrom-JSON).access_token
