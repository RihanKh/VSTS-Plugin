function getScanReport($scanId, $reportType, $contentType) {
    $reportRequest = New-Object System.Object
    $reportRequest | Add-Member -MemberType NoteProperty -Name scanId -Value $scanId;
    $reportRequest | Add-Member -MemberType NoteProperty -Name reportType -Value $reportType;

    $createReportResponse = createScanReport $reportRequest;
    $reportId = $createReportResponse.reportId;
    waitForReportToFinish $reportId "XML" $reportTimeoutSec;
    $scanReport = getReport $reportId $contentType;
    return $scanReport;
}

function createScanReport($reportRequest){
    $json = $reportRequest| ConvertTo-Json -Compress ;
    return postRequest $SAST_CREATE_REPORT $CONTENT_TYPE_APPLICATION_JSON_V1 $json 202 ("to create " + $reportRequest.reportType + " scan report") $true;
}

function waitForReportToFinish($reportId, $reportType, $reportTimeoutSec){
    $startTime = [DateTime]::Now;    
    $reportStatus = getReportStatus $reportId
    Write-Host ("Waiting for server to generate {0} report." -f $reportType) 
    $elapsedTime = 0;

    while($reportStatus.status.value -ne "Deleted"  -and
          $reportStatus.status.value -ne "Failed"  -and
           $reportStatus.status.value -ne "Created"  -and
          ($reportTimeoutSec -le 0 -or $elapsedTime -lt $reportTimeoutSec))
    {
        Start-Sleep -s 5 # wait 5 seconds
        $elapsedTime = [DateTime]::Now.Subtract($startTime).Seconds;# .ToString().Split('.')[0]
  
        write-host("Waiting for server to generate {0} report. {1} seconds left to timeout" -f $reportType, ($reportTimeoutSec - $elapsedTime));
        $reportStatus = getReportStatus $reportId
    }

   if ($reportStatus.status.value -eq "Created") {
        write-host $reportType " report was created successfully.";
        return $reportStatus;
    } 

    throw $reportType + " report cannot be generated. status [" + $reportStatus.status.value + "].";
return $reportStatus;
}

function getReportStatus($reportId){
    return getRequest $SAST_GET_REPORT_STATUS.replace("{reportId}", $reportId) $CONTENT_TYPE_APPLICATION_JSON_V1 $null " report status" $true;
}

function getReport($reportId, $contentType){
    return getRequest $SAST_GET_REPORT.replace("{reportId}", $reportId) $contentType 200 (" scan report: " + $reportId) $true;
}

function ResolveXMLReport($responses, $scanResults){
    Foreach ($r in $responses)
    {
        if($r.toString().Contains("<CxXMLResults")){
            $cxReport =  $r.Substring($r.IndexOf("<CxXMLResults") );
            break;
        }
    }

    # Create file:
    $now = [DateTime]::Now.ToString("yyyyMMddHHmmss")
    $tmpXMLPath =  [System.IO.Path]::GetTempPath() +  $REPORT_NAME + "_" + $now + ".xml";
    $cxReport >>  $tmpXMLPath
    $xdoc = new-object System.Xml.XmlDocument
    $xmlFile = resolve-path($tmpXMLPath)
    $xdoc.load($xmlFile)
    [xml] $xdoc = get-content $tmpXMLPath
    $scanResults = SetScanDetailedReport $xdoc $scanResults;

    #Delete Temp File
    try{
       [System.IO.File]::Delete($tmpXMLPath);
    } catch {
        Write-Host ("An error occurred while deleting temp report file: {0}" -f  $_.Exception.Message)
    }

    return $scanResults
}

function SetScanDetailedReport($xdoc, $scanResults) {
    $jsonQuery=""

    ForEach($query In $xdoc.CxXMLResults.Query) {
        $jsonQuery +=  @{name=$query.name;severity= $query.Severity;resultLength=$query.Result.Length} | ConvertTo-Json -Compress
        $jsonQuery+=";";
    }

    $scanResults | Add-Member -MemberType NoteProperty -Name scanStart -Value $xdoc.CxXMLResults.ScanStart
    $scanResults | Add-Member -MemberType NoteProperty -Name scanTime -Value $xdoc.CxXMLResults.ScanTime;
    $scanResults | Add-Member -MemberType NoteProperty -Name locScanned -Value $xdoc.CxXMLResults.LinesOfCodeScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name queryList -Value $jsonQuery;
    $scanResults | Add-Member -MemberType NoteProperty -Name filesScanned -Value $xdoc.CxXMLResults.FilesScanned;

    return $scanResults
}