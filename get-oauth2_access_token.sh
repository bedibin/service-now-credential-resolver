#!/usr/bin/env bash

tss_url=${TSS_URL:-"https://tmg.secretservercloud.com"}
tss_username=${TSS_USERNAME}
tss_password=${TSS_PASSWORD}

oauth2_grant=`curl -s --data "username=$tss_username&password=$tss_password&grant_type=password" $tss_url/oauth2/token`

echo $oauth2_grant >| ./oauth2_grant.json
echo $oauth2_grant | jq -r ".access_token" >| token.txt

