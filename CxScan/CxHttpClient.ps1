function login(){
    try{
        Write-Host "Logging into the Checkmarx service.";
        $body = @{username=$config.username;password=$config.password;grant_type='password';scope='sast_rest_api';client_id='resource_owner_client';client_secret='014DF517-39D1-4453-B7B3-9930C563627C'}

        return postRequest $AUTHENTICATION "application/x-www-form-urlencoded" $body 200 "authenticate" $false;
    }Catch {
       throw ("Failed to login: {0}" -f $_.Exception.Message)

    }
}

function getRequest($path, $contentType, $expectStatus, $failedMsg, $retry){
    $headers = @{}
    $headers.Add("Accept", $CONTENT_TYPE_APPLICATION_JSON);
    $headers.Add("cxOrigin", $config.cxOrigin)

    if ($config.token -ne $null) {
        $headers.Add("Authorization", $config.token.token_type + " " + $config.token.access_token)
    }
    if ($contentType -ne $null) {
        $headers.Add("Content-type", $contentType);
    }
    try{
        $fullPath = ($config.url + "/CxRestAPI/" + $path)
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($fullPath);
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
        $response = Invoke-RestMethod -Uri $fullPath -Method Get -Headers $headers -ContentType $contentType
        $servicePoint.CloseConnectionGroup("") |out-null;
        return $response;
    }catch{
        if ($retry -and $_.Exception.Response.StatusCode.value__ -eq 401) { #Token expired
            Write-Warning "Access token expired, requesting a new token";
            $config.token = $null;
            $config.token = login;
            return getRequest $path $contentType $expectStatus $failedMsg $false
        }
        if (!$failedMsg.Contains("project by name")){
            if ($_.Exception.Response -ne $null){
                Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
                Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
            }
            throw ("Failed to get {0}: {1}" -f $failedMsg, $_.Exception.Message)
        }
    }
}

function postRequest($path, $contentType, $body, $expectStatus, $failedMsg, $retry){
    $headers = @{}
    $headers.Add("cxOrigin", $config.cxOrigin)
    $headers.Add("Accept", $CONTENT_TYPE_APPLICATION_JSON);

    if ($config.token -ne $null) {
        $headers.Add("Authorization", $config.token.token_type + " " + $config.token.access_token)
    }
    if ($contentType -ne $null) {
        $headers.Add("Content-type", $contentType);
    }
    try{
        $fullPath = ($config.url + "/CxRestAPI/" + $path)
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($fullPath)
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
        $response = Invoke-RestMethod -Uri $fullPath -Method Post -Headers $headers -Body $body
        $servicePoint.CloseConnectionGroup($fullPath) |out-null;

        return $response;
    }catch{
         if ($retry-and $_.Exception.Response.StatusCode.value__ -eq 401) { #Token expired
            Write-Warning "Access token expired, requesting a new token";
            $config.token = $null;
            $config.token = login ;
            return postRequest $path $contentType $body $expectStatus $failedMsg $false;
         }
        if ($_.Exception.Response -ne $null){
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        }

        throw ("Failed to {0}: {1}" -f $failedMsg, $_.Exception.Message)
    }
}

function patchRequest($path, $contentType, $body, $expectStatus, $failedMsg, $retry){
    $headers = @{}
    #$headers.Add("Accept", $CONTENT_TYPE_APPLICATION_JSON);

    if ($config.token -ne $null) {
        $headers.Add("Authorization", $config.token.token_type + " " + $config.token.access_token)
    }
    if ($contentType -ne $null) {
        $headers.Add("Content-type", $contentType);
    }
    try{
        $fullPath = ($config.url + "/CxRestAPI/" + $path)
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($fullPath)
        $response = Invoke-RestMethod -Uri $fullPath -Method Patch -Headers $headers -Body $body -ContentType $contentType
        #validateResponse $response $expectStatus ("Failed to get " + $failedMsg);
        $servicePoint.CloseConnectionGroup("") |out-null;

        return $response;
    }catch{
         if ($retry-and $_.Exception.Response.StatusCode.value__ -eq 401) { #Token expired
            Write-Warning "Access token expired, requesting a new token";
            $config.token = $null;
            $config.token = login ;

            return patchRequest $path $contentType $body $expectStatus $failedMsg $false;
         }

        if ($_.Exception.Response -ne $null){
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        }
        throw ("Failed to update {0}: {1}" -f $failedMsg, $_.Exception.Message)
    }
}

function validateResponse($response, $status, $message){
    if ([string]::IsNullOrEmpty($response) -and $response.Count -eq 0 -and !$message.Contains("upload zip file") -and !$message.Contains("OSA vulnerabilities")){
            throw ("Failed to {0}: {1}" -f $messag, $_.Exception.Message)
    }
}


