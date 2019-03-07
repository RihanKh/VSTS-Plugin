
#OSA API
function createOSAScan() {
    write-host ("-----------------------------------Create CxOSA Scan:------------------------------------");

    #OSA FSA
    $tmpPath = [System.IO.Path]::GetTempPath();
    [System.Reflection.Assembly]::LoadFile("$PSScriptRoot/osaDll/CxOSA.dll") | out-null
    $pattern = generatePattern $config.osaFolderExclusions $config.osaFileExclusions

    $osaAgent = New-Object CxOSA.FSAgent($config.osaArchiveInclude, $pattern, $config.sourceLocation, $tmpPath, $config.debugMode);
    $osaDependenciesJson = $osaAgent.resolveOSADependencies();

    Write-Host "Sending OSA scan request";
    $osaScanRequest = New-Object System.Object
    $osaScanRequest | Add-Member -MemberType NoteProperty -Name ProjectId -Value $config.projectId;
    $osaScanRequest | Add-Member -MemberType NoteProperty -Name Origin -Value $config.cxOrigin
    $osaScanRequest | Add-Member -MemberType NoteProperty -Name HashedFilesList -Value $osaDependenciesJson

    return sendOSARequest $osaScanRequest;
}

function getOSAResults($scanResults){
    Write-Host "-------------------------------------Get CxOSA Results:-----------------------------------";
    $scanId = $scanResults.osaScanId;
    $osaScanStatus = waitForOSAToFinish $scanId;
    Write-Host "OSA scan finished successfully. Retrieving OSA scan results";

    Write-Host "Creating OSA reports";
    $osaLink = $OSA_LINK_FORMAT.Replace("{projectId}" , $config.projectId).Replace("{url}", $config.url);
    $osaSummaryResults = getOSAScanSummaryResults $scanId
    $osaLibraries = (getOSALibraries $scanId | ConvertTo-Json)
    $osaCVE = (getOSAVulnerabilities $scanId | ConvertTo-Json)

    $scanResults = AddOSAResults $scanResults $osaLink $osaSummaryResults $osaLibraries $osaCVE $osaScanStatus
    printOSAResultsToConsole $osaSummaryResults $osaLink

    return $scanResults;
}


#OSA web methods
function sendOSARequest($osaScanRequest) {
    $json = $osaScanRequest| ConvertTo-Json -Compress
    return postRequest $OSA_SCAN_PROJECT "application/json" $json 201 "create OSA scan" $true;
}

function getOSAScanSummaryResults($scanId){
    $relativePath = $OSA_SCAN_SUMMARY + $SCAN_ID_QUERY_PARAM + $scanId;
    return getRequest $relativePath $CONTENT_TYPE_APPLICATION_JSON_V1 200 "OSA scan summary results" $true;
}

function getOSALibraries($scanId){
    $relPath = $OSA_SCAN_LIBRARIES + $SCAN_ID_QUERY_PARAM + $scanId + $ITEM_PER_PAGE_QUERY_PARAM + $MAX_ITEMS;
    return getRequest $relPath $CONTENT_TYPE_APPLICATION_JSON_V1 200 "OSA libraries" $true;
}

function getOSAVulnerabilities($scanId){
    $relPath = $OSA_SCAN_VULNERABILITIES + $SCAN_ID_QUERY_PARAM + $scanId + $ITEM_PER_PAGE_QUERY_PARAM + $MAX_ITEMS;
    return getRequest $relPath $CONTENT_TYPE_APPLICATION_JSON_V1 200 "OSA vulnerabilities" $true;
}


function getOSAScanStatus($scanId) {
    $relPath = $OSA_SCAN_STATUS.replace("{scanId}", $scanId);
    return getRequest $relPath $CONTENT_TYPE_APPLICATION_JSON_V1 200 "OSA scan status" $true;
}

#OSA Helpers
function waitForOSAToFinish($scanId){
    $osaStart = [DateTime]::Now;
    $osaStatus = getOSAScanStatus $scanId
    Write-Host "Waiting for CxOSA scan to finish."
    $elapsedTime = 0;

    while($osaStatus.state.name -ne "Succeeded"  -and
          $osaStatus.state.name -ne "Failed")
    {
        Start-Sleep -s 10 # wait 10 seconds
        $elapsedTime = [DateTime]::Now.Subtract($osaStart).ToString().Split('.')[0]
        write-host("Waiting for OSA scan results. Elapsed time: {0}. Status: {1}." -f $elapsedTime, $osaStatus.state.name);

        $osaStatus = getOSAScanStatus $scanId
    }

    if ($osaStatus.state.name -eq "Succeeded") {
        write-host "OSA scan successfully finished.";
        return $osaStatus;
    }

    throw "OSA scan cannot be completed. status [" + $osaStatus.state.name + "].";#TODO
}