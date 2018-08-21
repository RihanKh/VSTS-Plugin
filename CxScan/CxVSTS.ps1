[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $CheckmarxService,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $projectName,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $fullTeamName,
    $presetList,
    [String] $customPreset,
    [String] $incScan,
    [String] $fsois,
    [String] $sourceFolder,
    [String] $folderExclusion,
    [String] $fileExtension,
    [String] $syncMode,
    [String] $vulnerabilityThreshold,
    [String] $high,
    [String] $medium,
    [String] $low,
    [String] $scanTimeout,
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
.$PSScriptRoot/CxZipUtils.ps1
.$PSScriptRoot/CxUtils.ps1
.$PSScriptRoot/CxReports/CxReport.ps1
.$PSScriptRoot/CxFolderPattern.ps1
.$PSScriptRoot/CxScanResults.ps1

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

$presetName;
$scanStart;
$presetId;
$OsaClient;
[boolean]$osaFailed = $false;
[boolean]$osaEnabled = [System.Convert]::ToBoolean($osaEnabled);
[boolean]$vulnerabilityThreshold = [System.Convert]::ToBoolean($vulnerabilityThreshold);
[boolean]$syncMode = [System.Convert]::ToBoolean($syncMode);
[boolean]$incScan = [System.Convert]::ToBoolean($incScan);
[boolean]$osaVulnerabilityThreshold = [System.Convert]::ToBoolean($osaVulnerabilityThreshold);

$osaFailedMessage = "";
$debugMode =  $env:SYSTEM_DEBUG;

$serviceEndpoint = Get-ServiceEndpoint -Context $distributedTaskContext -Name $CheckmarxService
$errorMessage ="";
$buildFailed = $false;
$scanResults = New-Object System.Object
$scanResults | Add-Member -MemberType NoteProperty -Name syncMode -Value $syncMode
$tmpPath = [System.IO.Path]::GetTempPath()
$tmpFolder =[System.IO.Path]::Combine($tmpPath,"cx_temp", $env:BUILD_DEFINITIONNAME, $env:BUILD_BUILDNUMBER)
if (!(Test-Path($tmpFolder))) {
    Write-Host ("Build specific checkmarx reports folder created at: {0}" -f $tmpFolder)
    New-Item -ItemType directory -Path $tmpFolder | Out-Null
}
$cxReportFile = Join-Path $tmpFolder "cxreport.json"

if (!$serviceEndpoint){
    OnSASTError $scanResults $cxReportFile
    throw "Connected Service with name '$CheckmarxService' could not be found.  Ensure that this Connected Service was successfully provisioned using the services tab in the Admin UI."
}
$authScheme = $serviceEndpoint.Authorization.Scheme
if ($authScheme -ne 'UserNamePassword'){
    OnSASTError $scanResults $cxReportFile
	throw "The authorization scheme $authScheme is not supported for a CX server."
}

$ErrorActionPreference = "Stop"
$reportPath = [String]$env:COMMON_TESTRESULTSDIRECTORY
$sourceLocation = [String]$env:BUILD_SOURCESDIRECTORY
$sourceLocation = $sourceLocation.trim()
$serviceUrl = [string]$serviceEndpoint.Url  #Url to cx server
$serviceUrl = ResolveServiceURL $serviceUrl
$user = [string]$serviceEndpoint.Authorization.Parameters.UserName  # cx user
$password = [string]$serviceEndpoint.Authorization.Parameters.Password # cx user pwd

write-host 'Entering CxScanner ......' -foregroundcolor "green"

$resolverUrlExtension = 'Cxwebinterface/CxWSResolver.asmx?wsdl'
$resolverUrl = $serviceUrl + $resolverUrlExtension


    Write-Host " "
    Write-Host "-------------------------------Configurations:--------------------------------";
    Write-Host ("URL: {0}" -f $serviceUrl)
    Write-Host ("Project name: {0}" -f $projectName)
    Write-Host ("Source location: {0}" -f $sourceLocation)
    Write-Host ("Scan timeout in minutes: {0}" -f $(ResolveString $scanTimeout))
    Write-Host ("Full team path: {0}" -f $fullTeamName)
    if (-not ([string]::IsNullOrEmpty($customPreset))){
      Write-Host ("Custom preset name: {0}" -f $customPreset)
    }else{
      Write-Host ("Preset name: {0}" -f $presetList)
    }

    Write-Host ("Is incremental scan: {0}" -f $incScan)
    Write-Host ("Folder exclusions: {0}" -f $(ResolveVal $folderExclusion))
    Write-Host ("File exclusions: {0}" -f $(ResolveVal $fileExtension))
    Write-Host ("Is synchronous scan: {0}" -f $syncMode)
    #Write-Host "Generate PDF report: " $generatePDFReport;

    Write-Host ("CxSAST thresholds enabled: {0}" -f $vulnerabilityThreshold)
    if ($vulnerabilityThreshold) {
     Write-Host ("CxSAST high threshold: {0}" -f $high)
     Write-Host ("CxSAST medium threshold: {0}" -f $medium)
     Write-Host ("CxSAST low threshold: {0}" -f $low)
    }


#todo "[No Threshold]"
    Write-Host("CxOSA enabled: {0}"-f $osaEnabled);
    if ($osaEnabled) {
        Write-Host("CxOSA folder exclusions: {0}" -f $(ResolveVal $osaFolderExclusions));
        Write-Host("CxOSA include/exclude wildcard patterns: {0}" -f $(ResolveVal $osaFileExclusions));
        Write-Host("CxOSA archive extract extensions: {0}" -f $osaArchiveInclude);
        Write-Host("CxOSA thresholds enabled: {0}" -f $osaVulnerabilityThreshold);
        if ($osaVulnerabilityThreshold) {
            Write-Host("CxOSA high threshold: {0}" -f $osaHigh);
            Write-Host("CxOSA medium threshold: {0}" -f $osaMedium);
           Write-Host("CxOSA low threshold: {0}" -f $osaLow);
        }
    }


    Write-Host " "
	Write-Host "----------------------------Create CxSAST Scan:-------------------------------"

write-host "Connecting to Checkmarx at: $resolverUrl ....." -foregroundcolor "green"

$resolver = $null
try {

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    $resolver = New-WebServiceProxy -Uri $resolverUrl -UseDefaultCredential
    $resolver.Timeout = 600000
} catch {
    OnSASTError $scanResults $cxReportFile
    write-host "Could not resolve Checkmarx service URL. Service might be down or a wrong URL was supplied." -foregroundcolor "red"
    Write-Error $_.Exception
    Exit
}

if (!$resolver){
    OnSASTError $scanResults $cxReportFile
    write-host "Could not resolve service URL. Service might be down or a wrong URL was supplied." -foregroundcolor "red"
    Exit
}

$webServiceAddressObject = $resolver.GetWebServiceUrl('SDK' ,1)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
$proxy = New-WebServiceProxy -Uri $webServiceAddressObject.ServiceURL -UseDefaultCredential #-Namespace CxSDK
$proxy.Timeout = 600000

if (!$proxy){
    write-host  "Could not find Checkmarx SDK service URL" -foregroundcolor "red"
    OnSASTError $scanResults $cxReportFile
    Exit
}

$namespace = $proxy.GetType().Namespace

$credentialsType = ($namespace + '.Credentials')
$credentials = New-Object ($credentialsType)
$credentials.User = $user
$credentials.Pass = $password

write-host  "Logging into the Checkmarx service." -foregroundcolor "green"
$loginResponse = $proxy.Login($credentials, 1033)

If(-Not $loginResponse.IsSuccesfull){
    OnSASTError $scanResults $cxReportFile
    Write-Host ("##vso[task.logissue type=error;]An Error occurred while logging in: {0}" -f $loginResponse.ErrorMessage)
    Write-Host "##vso[task.complete result=Failed;]DONE"
    Exit
}

$sessionId = $loginResponse.SessionId

#Init the parameters for Scan web nethod
$CliScanArgsType = ($namespace + '.CliScanArgs')
$CliScanArgs = New-Object ($CliScanArgsType)

$ProjectSettingsType = ($namespace  + '.ProjectSettings')
$CliScanArgs.PrjSettings =  New-Object ($ProjectSettingsType)

$SourceCodeSettingsType = ($namespace  + '.SourceCodeSettings')
$CliScanArgs.SrcCodeSettings = New-Object ($SourceCodeSettingsType)

$LocalCodeContainerType = ($namespace  + '.LocalCodeContainer')
$CliScanArgs.SrcCodeSettings.PackagedCode =  New-Object ($LocalCodeContainerType)

$SourceFilterPatternsType = ($namespace  + '.SourceFilterPatterns')
$CliScanArgs.SrcCodeSettings.SourceFilterLists =  New-Object ($SourceFilterPatternsType)
$CliScanArgs.SrcCodeSettings.SourceFilterLists.ExcludeFilesPatterns = $null
$CliScanArgs.SrcCodeSettings.SourceFilterLists.ExcludeFoldersPatterns = $null

$CliScanArgs.IsPrivateScan = 0

if($incScan){
	$CliScanArgs.IsIncremental = 1
	if(!([string]::IsNullOrEmpty($fsois))){
		[Int]$fsois = [convert]::ToInt32($fsois, 10)
		#write-host "todo: add scans count environment variable"
	}
}

$CliScanArgs.Comment = "Scan triggered by CxVSTS"
$CliScanArgs.IgnoreScanWithUnchangedCode = 0
$CliScanArgs.ClientOrigin = "SDK"

$fullTeamName = $fullTeamName -replace ' ','#@!'
$fullTeamName = $fullTeamName -replace '\\',' '
$fullTeamName = $fullTeamName -replace '/',' '
$fullTeamName = $fullTeamName -replace '(^\s+|\s+$)','' -replace '\s+','\\'
$fullTeamName = $fullTeamName -replace '#@!',' '
$fullTeamName = $fullTeamName -replace '\\\s+','\\'
$fullTeamName = $fullTeamName -replace '\s+\\','\\'
$fullTeamName = $fullTeamName -replace '\\+','\\'
#Write-Host ("Full team path: {0}" -f $fullTeamName)
$CliScanArgs.PrjSettings.ProjectName = $fullTeamName + "\\" + $projectName


if(-not ([string]::IsNullOrEmpty($customPreset))){

	$presetList = $proxy.GetPresetList($sessionId)
	$presets = New-Object 'System.Collections.Generic.Dictionary[String,String]'

	if ($presetList.IsSuccesfull -ne "True" ) {
		Write-Host ("##vso[task.logissue type=error;]Failed to retrieve preset list: {0}" -f $presetList.ErrorMessage)
		Write-Host "##vso[task.complete result=Failed;]DONE"
		Exit
	}

	$presets = $presetList.PresetList;

	foreach ($_preset in $presets.GetEnumerator()) {
		if ($_preset[0].PresetName -eq  $customPreset.Trim()){
			$PresetId = $_preset[0].ID;
			$presetName = $_preset[0].PresetName;
		}

	}

	#The preset was not found
	 if ($presetId -eq $null){
	    OnSASTError $scanResults $cxReportFile
        Write-Host "##vso[task.logissue type=error;]The selected custom preset [$customPreset] does not exist. Please fix and re-run the scan";
        Write-Host "##vso[task.complete result=Failed;]DONE"
        Exit
	}
}
else {
	$presetName = $presetList;
	switch ($presetName){
		"Checkmarx Default"          {$presetId = 36}
		"All"                        {$presetId = 1 }
		"Android"                    {$presetId = 9 }
		"Apple Secure Coding Guide"  {$presetId = 19}
		"Default"                    {$presetId = 7 }
		"Default 2014"               {$presetId = 17}
		"Empty preset"               {$presetId = 6 }
		"Error handling"             {$presetId = 2 }
		"FISMA"                      {$presetId = 39}
		"High and Medium"            {$presetId = 3 }
		"High and Medium and Low"    {$presetId = 13}
		"HIPAA"                      {$presetId = 12}
		"JSSEC"                      {$presetId = 20}
		"MISRA_C"                    {$presetId = 10}
		"MISRA_CPP"                  {$presetId = 11}
		"Mobile"                     {$presetId = 14}
		"NIST"                       {$presetId = 40}
		"OWASP Mobile TOP 10 - 2016" {$presetId = 37}
		"OWASP TOP 10 - 2010"        {$presetId = 4 }
		"OWASP TOP 10 - 2013"        {$presetId = 15}
		"OWASP TOP 10 - 2017"        {$presetId = 42}
		"PCI"                        {$presetId = 5 }
		"SANS top 25"                {$presetId = 8 }
		"STIG"                       {$presetId = 38}
		"WordPress"                  {$presetId = 16}
		"XS"                         {$presetId = 35}
		"XSS and SQLi only"          {$presetId = 41}
        }
}

    #Create Zip File
     $zipfilename = ZipSource $folderExclusion $fileExtension $sourceLocation
    if(!(Test-Path -Path $zipfilename)){
        OnSASTError $scanResults $cxReportFile
        Write-Host "Zip file is empty: no source to scan"
        Write-Host "##vso[task.complete result=Skipped;]"
        Exit
    }

    $CliScanArgs.PrjSettings.PresetID = $presetId
    $CliScanArgs.PrjSettings.IsPublic = 1 # true
    $CliScanArgs.PrjSettings.Owner = $user
	$CliScanArgs.SrcCodeSettings.PackagedCode.ZippedFile = [System.IO.File]::ReadAllBytes($zipfilename)
	$CliScanArgs.SrcCodeSettings.PackagedCode.FileName = $zipfilename

    write-host "Sending SAST scan request" -foregroundcolor "green"


    try {
        $scanResponse = $proxy.Scan($sessionId,$CliScanArgs)
        $scanStart = [DateTime]::Now
    } catch {
        DeleteFile $zipfilename
        OnSASTError $scanResults $cxReportFile
        write-host "Fail to init Checkmarx scan." -foregroundcolor "red"
        Write-Host ("##vso[task.logissue type=error;]An error occurred while scanning: {0}" -f  $_.Exception.Message)
        Write-Host "##vso[task.complete result=Failed;]DONE"
        Exit
    }

    #Delete Zip File
    DeleteFile $zipfilename

    If(-Not $scanResponse.IsSuccesfull)	{
		Write-Host ("##vso[task.logissue type=error;]An error occurred while scanning: {0}" -f $scanResponse.ErrorMessage)
        Write-Host "##vso[task.complete result=Failed;]DONE"
		Exit
    }
    [String]$projectID = $scanResponse.ProjectID
    $summaryLink = ("{0}/CxWebClient/portal#/projectState/{1}/Summary" -f $serviceUrl, $projectID)
    Write-Host "Scan created successfully. Link to project state: $summaryLink"


     #------- Create OSA Scan ------#
    if ($osaEnabled) {
        try{
	        Write-Host "-----------------------------Create CxOSA Scan:-------------------------------"
            $scanResults | Add-Member -MemberType NoteProperty -Name osaFailed -Value $false
	        [System.Reflection.Assembly]::LoadFile("$PSScriptRoot/osaDll/OsaClient.dll")
	        [System.Reflection.Assembly]::LoadFile("$PSScriptRoot/osaDll/System.Net.Http.Formatting.dll")
            $pattern = GeneratePattern $osaFolderExclusions $osaFileExclusions
            Write-debug ("OSA exclude pattern {0}" -f $pattern);
            $tmpPath = [System.IO.Path]::GetTempPath();
            $OsaClient = New-Object CxOsa.CxRestClient $user , $password, $serviceUrl, $scanResponse.ProjectID,$sourceLocation, $tmpPath, $pattern, $osaArchiveInclude, $debugMode;
            $osaScan = $OsaClient.runOSAScan();
        }Catch {
            Write-Host ("##vso[task.logissue type=error;]Failed to create OSA scan : {0}" -f $_.Exception.Message)
            $osaFailed = $true;
            $scanResults.osaFailed = $osaFailed;
            $osaFailedMessage = ("Failed to create OSA scan : {0}" -f $_.Exception.Message);
            $buildFailed = $true
         }
	 }

     #------ Asynchronous MODE ------#
	if(!$syncMode){
	    Write-host "Running in Asynchronous mode. Not waiting for scan to finish";
        $scanResults | ConvertTo-Json -Compress | Out-File $cxReportFile
        Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$cxReportFile"
		Exit;
	}

	#------- SAST Results ------#
	Write-host "-----------------------------Get CxSAST Results:------------------------------"

	$scanStatusResponse = $proxy.GetStatusOfSingleScan($sessionId,$scanResponse.RunId)
	If(-Not $scanStatusResponse.IsSuccesfull) {
	    OnSASTError $scanResults $cxReportFile
		Write-Host ("##vso[task.logissue type=error;]Scan failed: {0}" -f $scanStatusResponse.ErrorMessage)
		Write-Host "##vso[task.complete result=Failed;]Scan failed"
		Exit
	}

	Write-Host "Waiting for CxSAST scan to finish.";
	while($scanStatusResponse.IsSuccesfull -ne 0 -and
		  $scanStatusResponse.CurrentStatus -ne "Finished"  -and
		  $scanStatusResponse.CurrentStatus -ne "Failed"  -and
		  $scanStatusResponse.CurrentStatus -ne "Canceled"  -and
		  $scanStatusResponse.CurrentStatus -ne "Deleted")
    {
	   $timeLeft = [DateTime]::Now.Subtract($scanStart).ToString().Split('.')[0]
	   $prefix="";
	   if ($scanStatusResponse.TotalPercent -lt 10){ $prefix = " ";}
	   write-host("Waiting for results. Elapsed time: {0}. {1}{2}% processed. Status: {3}." -f $timeLeft, $prefix, $scanStatusResponse.TotalPercent, $scanStatusResponse.CurrentStatus);
	   $scanStatusResponse = $proxy.GetStatusOfSingleScan($sessionId,$scanResponse.RunId)
	   Start-Sleep -s 20 # wait 20 seconds
	}

    Write-Host "Scan finished status: " $scanStatusResponse.CurrentStatus;

	If($scanStatusResponse.IsSuccesfull -ne 0 -and $scanStatusResponse.CurrentStatus -eq "Finished")
	{
		Write-Host "Scan finished successfully. Retrieving SAST scan results"
		[String]$scanId = $scanStatusResponse.ScanId
        $scanDataResponse = $proxy.GetProjectScannedDisplayData($sessionId)
        if (-not $scanDataResponse.IsSuccesfull) {
            OnSASTError $scanResults $cxReportFile
            Write-Host ("##vso[task.logissue type=error;]Fail to get scan data: {0}" -f $scanDataResponse.ErrorMessage)
            Write-Host "##vso[task.complete result=Failed;]Fail to get scan data"
            Exit
        }

        $resultLink =  ("{0}/CxWebClient/ViewerMain.aspx?scanId={1}&ProjectID={2}"-f $serviceUrl,$scanId, $projectID)
        $scanResults = AddSASTResults $vulnerabilityThreshold $high $medium $low $summaryLink $resultLink $osaEnabled $scanDataResponse.ProjectScannedList $projectID
        PrintScanResults $scanResults

        #----- SAST detailed report ----------#
        Write-Host "Creating Checkmarx reports"
        $cxReport = createReport $scanId "XML"
        $scanResults = ResolveXMLReport $scanResults $cxReport


      #  if ([System.Convert]::ToBoolean($generatePDFReport)) {
       #     CreatePDFReport $scanId
       # }

        #--------- OSA Results ---------#
        if ($osaEnabled -and !$osaFailed) {
            try{
               	Write-host "-----------------------------Get CxOSA Results:-------------------------------"
                $osaSummaryResults = $OsaClient.retrieveOsaResults()
                $osaProjectSummaryLink =  ("{0}/CxWebClient/portal#/projectState/{1}/OSA"-f $serviceUrl, $projectID);
                $scanResults = AddOSAResults $scanResults $osaSummaryResults $osaProjectSummaryLink $osaVulnerabilityThreshold $osaHigh $osaMedium $osaLow $osaFailed
                PrintOSAResults $osaSummaryResults $osaProjectSummaryLink

            }Catch {
                 Write-Host ("##vso[task.logissue type=error;]Fail to retrieve CxOSA results : {0}" -f $_.Exception.Message)
                 $osaFailed = $true;
                 $scanResults.osaFailed = $osaFailed
                 $osaFailedMessage = ("Failed to create OSA scan : {0}" -f $_.Exception.Message)
            }
        }

        $cxReportFile = Join-Path $tmpFolder "cxreport.json"
        $scanResults | ConvertTo-Json -Compress | Out-File $cxReportFile
        Write-Host "##vso[task.addattachment type=cxReport;name=cxReport;]$cxReportFile"
        Write-Host "INFO: Generated Checkmarx summary results" #todo

		[bool]$thresholdExceeded=$false
		[bool]$osaThresholdExceeded=$false
		if($vulnerabilityThreshold){
            $thresholdExceeded = IsSASTThresholdExceeded $scanResults
		}
        if (!$osaFailed -and $osaEnabled -and $osaVulnerabilityThreshold) {
            $osaThresholdExceeded = IsOSAThresholdExceeded $scanResults
        }

		if($thresholdExceeded -or $osaThresholdExceeded -or $osaFailed){
		    $buildFailed = $true;
            if ($thresholdExceeded){  $errorMessage += "CxSAST threshold exceeded."}
            if ($osaThresholdExceeded){  $errorMessage += " CxOSA threshold exceeded"}
            if ($osaFailed){  $errorMessage += " " + $osaFailedMessage}
            Write-Host "##vso[task.complete result=Failed;]Build Failed due to: $errorMessage"
        }

	}
	Else {
	    OnSASTError $scanResults $cxReportFile
	    $errorMessage = ("Scan cannot be completed. Status [{0}].  Stage message: [{1}]" -f $scanStatusResponse.CurrentStatus, $scanStatusResponse.StageMessage)
		Write-Host "##vso[task.logissue type=error;]$errorMessage"
		Write-Host "##vso[task.complete result=Failed;]$errorMessage"
		$buildFailed = $true;
	}

	write-host "Logging out....." -foregroundcolor "green"
	$loginResponse = $proxy.Logout($sessionId)
	if (-not $buildFailed ){
	    Write-Host "##vso[task.complete result=Succeeded;]Scan completed successfully"
    }
