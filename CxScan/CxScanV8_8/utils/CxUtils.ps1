[bool] $global:exceededFirstTime = $false

function ResolveVal($val){
   if (-Not $val){
         return  "none"  ;
       }else{
         return $val;
       }
 }

 function ResolveString($val){

     if (-not ([string]::IsNullOrEmpty($val))){
         return $val;
     }else{
          return "none"
      }
 }

function initScanResults($config){
    $scanResults = New-Object System.Object
    $scanResults | Add-Member -MemberType NoteProperty -Name url -Value $config.url
    $scanResults | Add-Member -MemberType NoteProperty -Name syncMode -Value $config.isSyncMode
    $scanResults | Add-Member -MemberType NoteProperty -Name osaEnabled -Value $config.osaEnabled
    $scanResults | Add-Member -MemberType NoteProperty -Name buildFailed -Value $false

    return $scanResults;
}


function printConfiguration($config) {

    Write-Host " "
    Write-Host "-------------------------------Configurations:--------------------------------";
    Write-Host ("URL: {0}" -f $config.url)
    Write-Host ("Project name: {0}" -f $config.projectName)
    Write-Host ("Source location: {0}" -f $config.sourceLocation)
    Write-Host ("Full team path: {0}" -f $config.teamName)
    Write-Host ("Preset name: {0}" -f $config.presetName)
    Write-Host ("Scan timeout in minutes: {0}" -f $(ResolveString $config.scanTimeoutInMinutes))
    Write-Host ("Deny project creation: {0}" -f  $config.denyProject)

    Write-Host ("Is incremental scan: {0}" -f $config.isIncremental)
    Write-Host ("Folder exclusions: {0}" -f $(ResolveVal $config.folderExclusion))
    Write-Host ("File exclusions: {0}" -f $(ResolveVal $config.fileExtension))
    Write-Host ("Is synchronous scan: {0}" -f $config.isSyncMode)
    #Write-Host "Generate PDF report: " $config.generatePDFReport;

    Write-Host ("CxSAST thresholds enabled: {0}" -f $config.vulnerabilityThreshold)
    if ($vulnerabilityThreshold) {
        Write-Host ("CxSAST high threshold: {0}" -f $config.highThreshold)
        Write-Host ("CxSAST medium threshold: {0}" -f $config.mediumThreshold)
        Write-Host ("CxSAST low threshold: {0}" -f $config.lowThreshold)
    }
    Write-Host("CxOSA enabled: {0}"-f $config.osaEnabled);
    if ($config.osaEnabled) {
        Write-Host("CxOSA folder exclusions: {0}" -f $(ResolveVal $config.osaFolderExclusions));
        Write-Host("CxOSA include/exclude wildcard patterns: {0}" -f $(ResolveVal $config.osaFileExclusions));
        Write-Host("CxOSA archive extract extensions: {0}" -f $config.osaArchiveInclude);
        Write-Host("CxOSA thresholds enabled: {0}" -f $config.osaVulnerabilityThreshold);
        if ($osaVulnerabilityThreshold) {
            Write-Host("CxOSA high threshold: {0}" -f $config.osaHighThreshold);
            Write-Host("CxOSA medium threshold: {0}" -f $config.osaMediumThreshold);
            Write-Host("CxOSA low threshold: {0}" -f $config.osaLowThreshold);
        }
    }
        Write-Host "------------------------------------------------------------------------------"
}


function ResolveServiceURL($serviceUrl){
    $serviceUrl = $serviceUrl.TrimStart().TrimEnd()
    $serviceUrl = $serviceUrl.Replace('CxWebClient', '').trim()
    if ($serviceUrl.EndsWith('//')){
        $serviceUrl = $serviceUrl.Substring(0,$serviceUrl.Length -2)
    }
      if ($serviceUrl.EndsWith('/')){
        $serviceUrl = $serviceUrl.Substring(0,$serviceUrl.Length -1)
    }

    return $serviceUrl
}

function DeleteFile($fileName){
    try{
        [System.IO.File]::Delete($fileName)
    } catch {
        Write-Host ("An error occurred while deleting temp zip file: {0}. Error: {1}" -f $fileName, $_.Exception.Message)
    }
}

function IsSASTThresholdExceeded($scanResults){
    $scanType = "CxSAST"
    $highExceeded = isLevelThresholdExceeded $scanResults.highResults $scanResults.highThreshold "high" $scanType;
    $mediumExceeded = isLevelThresholdExceeded $scanResults.mediumResults $scanResults.mediumThreshold "medium" $scanType;
    $lowExceeded = isLevelThresholdExceeded $scanResults.lowResults $scanResults.lowThreshold "low" $scanType;
    return ($highExceeded -or $mediumExceeded -or $lowExceeded)
}

 function IsOSAThresholdExceeded($scanResults){
    $scanType = "CxOSA"
    $highExceeded = IsLevelThresholdExceeded $scanResults.osaHighResults $scanResults.osaHighThreshold "high" $scanType ;
    $mediumExceeded = IsLevelThresholdExceeded $scanResults.osaMediumResults $scanResults.osaMediumThreshold "medium" $scanType;
    $lowExceeded = IsLevelThresholdExceeded $scanResults.osaLowResults $scanResults.osaLowThreshold "low" $scanType;
    return ($highExceeded -or $mediumExceeded -or $lowExceeded)
 }

function IsLevelThresholdExceeded($result, $threshold, $severity, $scanType){
   try{
       if(-Not [string]::IsNullOrEmpty($threshold)){
            [Int]$thresholdNum = [convert]::ToInt32($threshold, 10)
           if ($thresholdNum -lt 0)
           {
                throw "Threshold must be 0 or greater";
           }
            [Int]$resultNum = [convert]::ToInt32($result, 10)
            if($resultNum -gt $thresholdNum){
                if (!$global:exceededFirstTime){
                    Write-Host ("##vso[task.logissue type=error;]********************************************")
                    Write-Host ("##vso[task.logissue type=error;] The Build Failed for the Following Reasons: ")
                    Write-Host ("##vso[task.logissue type=error;]********************************************")
                    $global:exceededFirstTime = $true;
                }
               Write-Host ("##vso[task.logissue type=error;]{0} {1} severity results are above threshold. Results: {2}. Threshold: {3}" -f $scanType, $severity, $resultNum, $thresholdNum)
               return $true
            }
        }
    }catch{
        Write-Warning("Invalid {0} {1} threshold. Error: {2}" -f $scanType, $severity ,$_.Exception.Message);
    }
    return $false;
}

function OnError($scanResults, $cxReportFile){
    if ([bool]($scanResults.PSobject.Properties.name -match "sastResultsReady")){
        $scanResults.sastResultsReady = $false
    }else {
        $scanResults | Add-Member -MemberType NoteProperty -Name sastResultsReady -Value $false
    }
    if ([bool]($scanResults.PSobject.Properties.name -match "osaFailed")){
        $scanResults.osaFailed = $true
    }else {
        $scanResults | Add-Member -MemberType NoteProperty -Name osaFailed -Value $true
    }
    $scanResults | ConvertTo-Json -Compress | Out-File $cxReportFile
    Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$cxReportFile"
}








