function createSASTScan()  {

    write-host ("-----------------------------------Create CxSAST Scan:-----------------------------------"); 
    
    try {
            ($scanSettingResponse = getScanSetting $config.projectId) | out-null
            $scanSettingRequest = New-Object System.Object
            $scanSettingRequest | Add-Member -MemberType NoteProperty -Name projectId -Value $config.projectId;
            $scanSettingRequest | Add-Member -MemberType NoteProperty -Name presetId -Value $config.presetId
            $scanSettingRequest | Add-Member -MemberType NoteProperty -Name engineConfigurationId -Value $scanSettingResponse.engineConfiguration.Id;
            $scanSettingRequest | Add-Member -MemberType NoteProperty -Name postScanActionId -Value $scanSettingResponse.postScanAction
            $scanSettingRequest | Add-Member -MemberType NoteProperty -Name emailNotifications -Value $scanSettingResponse.emailNotifications;

            if ($config.engineConfigurationId -ne $null) {
                $scanSettingRequest.engineConfigurationId = $config.engineConfigurationId;
            }

            #Define createSASTScan settings
            (defineScanSetting $scanSettingRequest) | Out-null
            #uploadZipFile
            write-host "Uploading zip file";
            (uploadZipFile $config.zipFile $config.projectId)| out-null;

            #Start a new createSASTScan      
            $scanRequest = New-Object System.Object
            $scanRequest | Add-Member -MemberType NoteProperty -Name projectId -Value $config.projectId
            $scanRequest | Add-Member -MemberType NoteProperty -Name isIncremental -Value $config.isIncremental
            $scanRequest | Add-Member -MemberType NoteProperty -Name isPublic -Value $config.isPublic
            $scanRequest | Add-Member -MemberType NoteProperty -Name forceScan -Value $config.isForceScan
            $scanRequest | Add-Member -MemberType NoteProperty -Name comment -Value $config.scanComment

            write-host "Sending SAST scan request";
           
            return createScan $scanRequest
 } catch{
       throw ("Failed to create SAST scan: {0}" -f $_.Exception.Message)
    }

}

function getSASTResults($scanResults) {

    try {
        write-host "------------------------------------Get CxSAST Results:----------------------------------";
        $scanId = $scanResults.scanId;
        #wait for SAST scan to finish
       (waitForScanToFinish $scanId $config.scanTimeoutInMinutes) |out-null
        
        #retrieve SAST scan results
        write-host "Retrieving SAST scan results";
        ($statisticsResults = getScanStatistics $scanId) |out-null

        if($statisticsResults.highSeverity -eq $null)
        {
            throw("Failed to get scan statics");
        }
        $scanResults = addSASTResults  $statisticsResults   $scanResults;

        #SAST detailed report
       ($reportResponse = getScanReport $scanResults.scanId "XML" $CONTENT_TYPE_APPLICATION_XML_V1) | Out-Null
       ($scanResults = ResolveXMLReport $reportResponse $scanResults) | Out-Null

        printResultsToConsole $scanResults;

    } catch {
        throw("Failed to get SAST scan results: {0}" -f $_.Exception.Message)
    }
    return $scanResults;
}


#SAST web methods
function createNewProject($request){
    $json = $request| ConvertTo-Json -Compress 
    return postRequest $SAST_SCAN_PROJECT $CONTENT_TYPE_APPLICATION_JSON_V1 $json 201 ("create new project: " + $request.name) $true;
}

function getScanSetting($projectId) {
    return getRequest $SAST_GET_SCAN_SETTINGS.replace("{projectId}",$projectId) $CONTENT_TYPE_APPLICATION_JSON_V1 200 "Scan setting" $true;
}

function defineScanSetting($scanSetting) {
    $json = $scanSetting| ConvertTo-Json -Compress
    postRequest $SAST_UPDATE_SCAN_SETTINGS $CONTENT_TYPE_APPLICATION_JSON_V1 $json 200 "define scan setting" $true;
}

function uploadZipFile($zipFile, $projectId){
    try {
        $LF = "`r`n"
        $fileBin = [System.IO.File]::ReadAllBytes($zipFile)
          
        $enc = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
        $fileEnc = $enc.GetString($fileBin)
  
        $boundary = [System.Guid]::NewGuid().ToString()
        $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"zippedSource`"; filename=`" filename.zip`"",
                "Content-Type: application/octet-stream$LF",
        $fileEnc,
        "--$boundary--$LF"
        ) -join $LF

        $contentType = "multipart/form-data; boundary=`"$boundary`""
    }catch{
        Write-Host ("Failed to upload Zip: {0}" -f  $_.Exception.Message)
        return
    }   
   
    postRequest $SAST_ZIP_ATTACHMENTS.Replace("{projectId}",$projectId) $contentType $bodyLines 204 "upload zip file" $true;
}

function createScan($request){ 
    $json = $request| ConvertTo-Json -Compress 
    return postRequest $SAST_CREATE_SCAN $CONTENT_TYPE_APPLICATION_JSON_V1 $json 201 "create new SAST Scan" $true;
}

function getSASTScanStatus($scanId){
    return getRequest $SAST_QUEUE_SCAN_STATUS.replace("{scanId}",$scanId) $CONTENT_TYPE_APPLICATION_JSON_V1 200 "SAST scan status" $true;
}

function getScanStatistics($scanId) { 
    return getRequest $SAST_SCAN_RESULTS_STATISTICS.replace("{scanId}",$scanId) $CONTENT_TYPE_APPLICATION_JSON_V1 200 "SAST scan statistics" $true;
}


#SAST Helpers
function waitForScanToFinish($scanId, $scanTimeOut){
    $scanStart = [DateTime]::Now;    
    $scanStatus = getSASTScanStatus $scanId
    Write-Host "Waiting for CxSAST scan to finish."
    $elapsedTime = [timespan]::FromMinutes(0);
    $scanTimeoutInMin =  [timespan]::FromMinutes($scanTimeOut)

    while($scanStatus -ne $null -and
          $scanStatus.stage.value -ne "Finished"  -and
          $scanStatus.stage.value -ne "Failed"  -and
          $scanStatus.stage.value -ne "Canceled"  -and
          $scanStatus.stage.value -ne "Deleted"  -and
          $scanStatus.stageDetails -ne "Scan completed" -and
         ($scanTimeoutInMin -le 0 -or $elapsedTime -lt $scanTimeoutInMin))
    {     
        $elapsedTime = [DateTime]::Now.Subtract($scanStart).ToString().Split('.')[0]
        $prefix="";
        if ($scanStatus.TotalPercent -lt 10){ $prefix = " ";}
        write-host("Waiting for SAST scan results. Elapsed time: {0}. {1}{2}% processed. Status: {3}." -f $elapsedTime, $prefix, $scanStatus.TotalPercent, $scanStatus.stage.value);
       
        Start-Sleep -s 10 #get  status every 20 seconds
        $scanStatus = getSASTScanStatus $scanId
    }
      if ($scanStatus.stage.value -eq "Finished" -or  $scanStatus.stageDetails -eq "Scan completed" ) {
        write-host "SAST scan successfully finished.";
        return $scanStatus;
    } 

       if ($scanTimeOut -gt 0 -and $elapsedTime -ge $scanTimeoutInMin) {
        throw ("Waiting for CxSAST scan has reached the time limit. ({0} minutes)." -f $scanTimeout);
    }

    throw "SAST scan cannot be completed. status [" + $scanStatus.stage.value + "]."
}