[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $CheckmarxService,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $projectName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $fullTeamName,
    $presetList,
    [String] $customPreset,
    [String] $incScan,
    [String] $sourceFolder,
    [String] $folderExclusion,
    [String] $fileExtension,
    [String] $syncMode,
    [String] $vulnerabilityThreshold,
    [String] $high,
    [String] $medium,
    [String] $low,
    [String] $scanTimeout,
    [String] $denyProject,
    [String] $comment,
    [String] $osaEnabled,
    [String] $osaFileExclusions,
    [String] $osaFolderExclusions,
    [String] $osaArchiveInclude,
    [String] $osaVulnerabilityThreshold,
    [String] $osaHigh,
    [String] $osaMedium,
    [String] $osaLow
)

import-module "Microsoft.TeamFoundation.DistributedTask.Task.Common"
import-module "Microsoft.TeamFoundation.DistributedTask.Task.Internal"
import-module "Microsoft.TeamFoundation.DistributedTask.Task.TestResults"
.$PSScriptRoot/utils/CxZipUtils.ps1
.$PSScriptRoot/utils/CxUtils.ps1
.$PSScriptRoot/CxRestClient.ps1
.$PSScriptRoot/CxHttpClient.ps1

.$PSScriptRoot/CxSAST/sastClient.ps1
.$PSScriptRoot/CxSAST/sastParams.ps1
.$PSScriptRoot/CxSAST/sastReports.ps1
.$PSScriptRoot/CxSAST/sastUtils.ps1

.$PSScriptRoot/CxOSA/osaClient.ps1
.$PSScriptRoot/CxOSA/osaParams.ps1
.$PSScriptRoot/CxOSA/osaUtils.ps1


function createConfig(){
    $config = New-Object System.Object
    $config | Add-Member -MemberType NoteProperty -Name sastEnabled -Value $true
    $config | Add-Member -MemberType NoteProperty -Name url -Value $serviceUrl
    $config | Add-Member -MemberType NoteProperty -Name username -Value $username
    $config | Add-Member -MemberType NoteProperty -Name password -Value $password
    $config | Add-Member -MemberType NoteProperty -Name cxOrigin -Value "VSTS"
    $config | Add-Member -MemberType NoteProperty -Name projectName -Value $projectName
    $config | Add-Member -MemberType NoteProperty -Name teamId -Value $null
    if (!$fullTeamName.StartsWith("\")){
        $fullTeamName =  "\$fullTeamName"
    }
    $config | Add-Member -MemberType NoteProperty -Name teamName -Value $fullTeamName.trim();
    $config | Add-Member -MemberType NoteProperty -Name isPublic -Value $true
    $config | Add-Member -MemberType NoteProperty -Name sourceLocation -Value $sourceLocation
    $config | Add-Member -MemberType NoteProperty -Name isIncremental -Value ([System.Convert]::ToBoolean($incScan));
    $config | Add-Member -MemberType NoteProperty -Name isSyncMode -Value ([System.Convert]::ToBoolean($syncMode));
    $config | Add-Member -MemberType NoteProperty -Name isForceScan -Value $false
    $config | Add-Member -MemberType NoteProperty -Name zipFile -Value $null
    $config | Add-Member -MemberType NoteProperty -Name presetId -Value $null
    if (-not [string]::IsNullOrEmpty($customPreset)){
      $presetName = $customPreset.trim();
    }else{
      $presetName = $presetList.trim()
    }
    $config | Add-Member -MemberType NoteProperty -Name presetName -Value $presetName
    if ( [string]::IsNullOrEmpty($scanTimeout)){
        $scanTimeout = -1;
    }
    $config | Add-Member -MemberType NoteProperty -Name scanTimeoutInMinutes -Value $scanTimeout
    $config | Add-Member -MemberType NoteProperty -Name scanComment -Value $comment
    $config | Add-Member -MemberType NoteProperty -Name denyProject -Value $denyProject
    $config | Add-Member -MemberType NoteProperty -Name folderExclusion -Value $folderExclusion
    $config | Add-Member -MemberType NoteProperty -Name fileExtension -Value $fileExtension
    $config | Add-Member -MemberType NoteProperty -Name vulnerabilityThreshold -Value $vulnerabilityThreshold
    $config | Add-Member -MemberType NoteProperty -Name highThreshold -Value $high
    $config | Add-Member -MemberType NoteProperty -Name mediumThreshold -Value $medium
    $config | Add-Member -MemberType NoteProperty -Name lowThreshold -Value $low

    $config | Add-Member -MemberType NoteProperty -Name osaEnabled -Value ([System.Convert]::ToBoolean($osaEnabled))
    $config | Add-Member -MemberType NoteProperty -Name osaFileExclusions -Value $osaFileExclusions
    $config | Add-Member -MemberType NoteProperty -Name osaFolderExclusions -Value $osaFolderExclusions
    $config | Add-Member -MemberType NoteProperty -Name osaArchiveInclude -Value $osaArchiveInclude
    $config | Add-Member -MemberType NoteProperty -Name osaVulnerabilityThreshold -Value $osaVulnerabilityThreshold
    $config | Add-Member -MemberType NoteProperty -Name osaHighThreshold -Value $osaHigh
    $config | Add-Member -MemberType NoteProperty -Name osaMediumThreshold -Value $osaMedium
    $config | Add-Member -MemberType NoteProperty -Name osaLowThreshold -Value $osaLow

    $config | Add-Member -MemberType NoteProperty -Name token -Value $null
    $config | Add-Member -MemberType NoteProperty -Name projectId -Value $null
    $config | Add-Member -MemberType NoteProperty -Name createSASTResponse -Value $null
    $config | Add-Member -MemberType NoteProperty -Name debugMode -Value $env:SYSTEM_DEBUG;

    return $config;
}


Write-Host "                                       "
Write-Host
          "         CxCxCxCxCxCxCxCxCxCxCxCx           `n" +
          "        CxCxCxCxCxCxCxCxCxCxCxCxCx`         `n" +
          "       CxCxCxCxCxCxCxCxCxCxCxCxCxCx`        `n" +
          "      CxCxCx                CxCxCxCx        `n" +
          "      CxCxCx                CxCxCxCx`       `n" +
          "      CxCxCx  CxCxCx      CxCxCxCxC         `n" +
          "      CxCxCx  xCxCxCx  .CxCxCxCxCx          `n" +
          "      CxCxCx   xCxCxCxCxCxCxCxCx            `n"  +
          "      CxCxCx    xCxCxCxCxCxCx               `n"  +
          "      CxCxCx     CxCxCxCxCx   CxCxCx        `n"  +
          "      CxCxCx       xCxCxC     CxCxCx        `n"  +
          "      CxCxCx                 CxCxCx         `n"  +
          "       CxCxCxCxCxCxCxCxCxCxCxCxCxCx         `n"  +
          "        CxCxCxCxCxCxCxCxCxCxCxCxCx          `n"  +
          "          CxCxCxCxCxCxCxCxCxCxCx            `n"  +
          "                                            `n" +
          "            C H E C K M A R X               `n"
Write-Host "                                               "
Write-Host "Starting Checkmarx scan"

try{
        #------- Resolve Params ------#
    [boolean]$vulnerabilityThreshold = [System.Convert]::ToBoolean($vulnerabilityThreshold);
    [boolean]$osaVulnerabilityThreshold = [System.Convert]::ToBoolean($osaVulnerabilityThreshold);
    $errorMessage ="";
    $tmpPath = [System.IO.Path]::GetTempPath()
    $tmpFolder =[System.IO.Path]::Combine($tmpPath,"cx_temp",$env:BUILD_DEFINITIONNAME, $env:BUILD_BUILDNUMBER);

    if (!(Test-Path($tmpFolder))) {
        Write-Host ("Build specific checkmarx reports folder created at: {0}" -f $tmpFolder)
        New-Item -ItemType directory -Path $tmpFolder | Out-Null
    }
    $cxReportFile = Join-Path $tmpFolder "cxreport.json"
    $serviceEndpoint = Get-ServiceEndpoint -Context $distributedTaskContext -Name $CheckmarxService
    if (!$serviceEndpoint){
        OnError $scanResults $cxReportFile
        throw "Connected Service with name '$CheckmarxService' could not be found.  Ensure that this Connected Service was successfully provisioned using the services tab in the Admin UI."
    }
    $authScheme = $serviceEndpoint.Authorization.Scheme
    if ($authScheme -ne 'UserNamePassword'){
        OnError $scanResults $cxReportFile
        throw "The authorization scheme $authScheme is not supported for a CX server."
    }

    $sourceLocation = ([String]$env:BUILD_SOURCESDIRECTORY).trim()
    $serviceUrl = ResolveServiceURL ([string]$serviceEndpoint.Url)  #Url to cx server
    $username = [string]$serviceEndpoint.Authorization.Parameters.UserName  # cx user
    $password = [string]$serviceEndpoint.Authorization.Parameters.Password # cx user pwd

    write-host 'Entering CxScanner ......' -foregroundcolor "green"
    $config = createConfig ;
    printConfiguration $config;
    $scanResults = initScanResults $config
        #------- Init CxREST Client ------#
    initRestClient $config

        #------- Create OSA Scan ------#
    if ($config.osaEnabled){
        try{
                $scanResults | Add-Member -MemberType NoteProperty -Name osaFailed -Value $false
                $scanResults | Add-Member -MemberType NoteProperty -Name osaScanId -Value $null
                $scanResults | Add-Member -MemberType NoteProperty -Name osaProjectSummaryLink -Value $null
                $scanResults | Add-Member -MemberType NoteProperty -Name osaThresholdEnabled -Value $config.osaVulnerabilityThreshold
                if($config.osaVulnerabilityThreshold){
                     $scanResults | Add-Member -MemberType NoteProperty -Name osaHighThreshold -Value $osaHigh
                     $scanResults | Add-Member -MemberType NoteProperty -Name osaMediumThreshold -Value $osaMedium
                     $scanResults | Add-Member -MemberType NoteProperty -Name osaLowThreshold -Value $osaLow
                }

                $osaScan = createOSAScan
                $osaLink =  ("{0}/CxWebClient/SPA/#/viewer/project/{1}"-f $config.url, $config.projectId);
                Write-Host "OSA scan created successfully. Link to project state: $osaLink";
                $scanResults.osaScanId = $osaScan.scanId;
                $scanResults.osaProjectSummaryLink = $osaLink
            }Catch {
                $scanResults.osaFailed = $true;
                $osaFailedMessage = ("Failed to create OSA scan : {0}" -f $_.Exception.Message);
                Write-Error $osaFailedMessage;
              }
    }

            #------- Create SAST Scan ------#
    if ($config.sastEnabled){
        $scanResults | Add-Member -MemberType NoteProperty -Name sastResultsReady -Value $false
        $scanResults | Add-Member -MemberType NoteProperty -Name scanId -Value $null
        $scanResults | Add-Member -MemberType NoteProperty -Name thresholdEnabled -Value $config.vulnerabilityThreshold
        if($config.vulnerabilityThreshold){
            $scanResults | Add-Member -MemberType NoteProperty -Name highThreshold -Value $config.highThreshold
            $scanResults | Add-Member -MemberType NoteProperty -Name mediumThreshold -Value $config.mediumThreshold
            $scanResults | Add-Member -MemberType NoteProperty -Name lowThreshold -Value $config.lowThreshold
        }

        #Create Zip File
        Write-Host "Zipping sources";
        $zipFilename = ZipSource $folderExclusion $fileExtension $sourceLocation
        if(!(Test-Path -Path $zipfilename)){
            OnError $scanResults $cxReportFile
            Write-Host "Zip file is empty: no source to scan"
            Write-Host "##vso[task.complete result=Skipped;]"
            Exit
        }
        $config.zipFile = $zipFileName

        $createSASTResponse = createSASTScan
        $scanResults.scanId =  $createSASTResponse.id;
        write-host ("SAST scan created successfully. CxLink to project state:{0} " -f $LINK_FORMAT.Replace("{projectId}" , $config.projectId).Replace("{url}", $config.url));

        #Delete Zip File
        DeleteFile $zipFilename
    }

        #------ Asynchronous MODE ------#
    if(!$config.isSyncMode){
        Write-host "Running in Asynchronous mode. Not waiting for scan to finish";
        if ($scanResults.buildFailed -eq $true){
            return OnError $scanResults $cxReportFile
        }
        $scanResults | ConvertTo-Json -Compress | Out-File $cxReportFile
        Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$cxReportFile"
        Exit;
    }

        #------- SAST Results ------#
    if ($config.sastEnabled){
        $scanResults = getSASTResults $scanResults
    }
        #--------- OSA Results ---------#
    if ($config.osaEnabled -and !$scanResults.osaFailed) {
        try{
            $scanResults = getOSAResults $scanResults
        }Catch {
          $scanResults.osaFailed = $true
          $osaFailedMessage = ("Failed to retrieve OSA scan results: {0}" -f $_.Exception.Message)
          Write-Error $osaFailedMessage;
        }
    }

     #------- Create Summary Report ------#

    $cxReportFile = Join-Path $tmpFolder "cxreport.json"
    $scanResults | ConvertTo-Json -Compress | Out-File $cxReportFile
    Write-Host "Generated Checkmarx summary results"
    Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$cxReportFile"

    #------- Is Build failed by threshold? ------#
    [bool]$thresholdExceeded=$false
    [bool]$osaThresholdExceeded=$false
    if($config.vulnerabilityThreshold){
        $thresholdExceeded = IsSASTThresholdExceeded $scanResults
    }
    if ($config.osaEnabled){
        if ($scanResults.osaFailed){
            if (!$global:exceededFirstTime){
                Write-Host ("##vso[task.logissue type=error;]********************************************")
                Write-Host ("##vso[task.logissue type=error;] The Build Failed for the Following Reasons: ")
                Write-Host ("##vso[task.logissue type=error;]********************************************")
                $global:exceededFirstTime = $true;
            }
            Write-Host ("##vso[task.logissue type=error;]{0}" -f $osaFailedMessage);
        }ElseIf ($osaVulnerabilityThreshold){
            $osaThresholdExceeded = IsOSAThresholdExceeded $scanResults
        }

    }


    if($thresholdExceeded -or $osaThresholdExceeded -or $scanResults.osaFailed){
        $scanResults.buildFailed = $true;
        if ($thresholdExceeded){  $errorMessage += "CxSAST threshold exceeded."}
        if ($osaThresholdExceeded){  $errorMessage += " CxOSA threshold exceeded"}
        if ($scanResults.osaFailed){  $errorMessage += " " + $osaFailedMessage}
        Write-Host "##vso[task.complete result=Failed;] Build Failed due to: $errorMessage"
    }
}catch {
    $errorMessage = ("Scan cannot be completed: {0}." -f $_.Exception.Message)
    $scanResults.buildFailed = $true;
    OnError $scanResults $cxReportFile
    Write-Host "##vso[task.complete result=Failed;]$errorMessage"
    throw $errorMessage
 }

if (-not $scanResults.buildFailed ){
    Write-Host "##vso[task.complete result=Succeeded;]Scan completed successfully"
}