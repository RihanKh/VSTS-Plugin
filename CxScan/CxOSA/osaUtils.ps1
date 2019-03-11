function writeToOsaListToTemp($osaDependenciesJson, $tempDir) {
        try {
        $filePath = Join-Path $tempDir $"CxOSAFileList.json"
        New-Item -ItemType File $filePath
        $osaDependenciesJson | Out-File -filepath $filePath 
        Write-Host "OSA file list saved to file: [$filePath ]";

        } catch {
            Write-Host "Failed to write OSA file list to temp directory:  $_.Exception.Message";
        }

    }


function printOSAResultsToConsole($results, $osaLink) {
    Write-Host "----------------------------Checkmarx Scan Results(CxOSA):-------------------------------";
    Write-Host ""
    Write-Host "------------------------"
    Write-Host "Vulnerabilities Summary:"
    Write-Host "------------------------"
    Write-Host "OSA high severity results: " $results.totalHighVulnerabilities;
    Write-Host "OSA medium severity results: " $results.totalMediumVulnerabilities;
    Write-Host "OSA low severity results: " $results.totalLowVulnerabilities;
    Write-Host "Vulnerability score: " $results.vulnerabilityScore;
    Write-Host "";
    Write-Host "-----------------------";
    Write-Host "Libraries Scan Results:";
    Write-Host "-----------------------";
    Write-Host "Open-source libraries: " $results.totalLibraries;
    Write-Host "Vulnerable and outdated: " $results.vulnerableAndOutdated;
    Write-Host "Vulnerable and updated:  " $results.vulnerableAndUpdated;
    Write-Host "Non-vulnerable libraries: " $results.nonVulnerableLibraries;
    Write-Host "";
    Write-Host "OSA scan results location: " $osaLink;
    Write-Host "-----------------------------------------------------------------------------------------";
}

function  ProcessExcludedFolders($folderExclusions) {
    if ( [string]::IsNullOrEmpty($folderExclusions)) {
        return "";
    }
    $result = "";
    [array]$patterns =  $folderExclusions.split(",")| Foreach-Object {
                                                        if( !([string]::IsNullOrEmpty($_))){
                                                            $result += "!**/" + $_.Trim() + "/**,"

                                                        }

    $result = $result.Substring(0 ,$result.LastIndexOf(","));                                                 }
    Write-Host ("Exclude folders converted to: {0}" -f $result);
    return $result;
  }


  function ProcessExcludedFiles($fileExclusions) {
    $pattern = "";
    $result = "";

    $fileExclusions.split(",")| Foreach-Object {
                                if( -not ([string]::IsNullOrEmpty($_.Trim()))){
                                    $pattern+= $_.Trim()
                                    $pattern +=","
                                }
                            }

    $pattern = $pattern.Substring(0 ,$pattern.LastIndexOf(","));
    $pattern.Split(",") | Foreach-Object {$result += $_.Replace("*", "**/*");
                                          $result +=","}
    $result = $result.Substring(0 ,$result.LastIndexOf(","));
    Write-Host ("Excluded files converted to: {0}" -f $result);

    return $result
  }


function generatePattern($folderExclusions, $filterPattern)
{
    $excludeFoldersPattern = ProcessExcludedFolders $folderExclusions;

    if ([string]::IsNullOrEmpty($filterPattern) -and [string]::IsNullOrEmpty($excludeFoldersPattern)) {
        return "";
    } Elseif ((-not [string]::IsNullOrEmpty($filterPattern)) -and [string]::IsNullOrEmpty($excludeFoldersPattern))
    {
        return $filterPattern;
    }
    elseif  ([string]::IsNullOrEmpty($filterPattern) -and  -not  [string]::IsNullOrEmpty($excludeFoldersPattern))
     {
        return $excludeFoldersPattern;
    } else {
        return $filterPattern + "," + $excludeFoldersPattern;
    }
}

function AddOSAResults($scanResults, $osaLink, $osaSummaryResultsm,  $osaLibraries, $osaCVE, $osaScanStatus){
    $scanResults.osaFailed = $false;
    $scanResults | Add-Member -MemberType NoteProperty -Name osaStartTime -Value $osaScanStatus.startAnalyzeTime
    $scanResults | Add-Member -MemberType NoteProperty -Name osaEndTime -Value $osaScanStatus.endAnalyzeTime

    $scanResults | Add-Member -MemberType NoteProperty -Name osaHighResults -Value $osaSummaryResults.totalHighVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaMediumResults -Value $osaSummaryResults.totalMediumVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLowResults -Value $osaSummaryResults.totalLowVulnerabilities
    $scanResults | Add-Member -MemberType NoteProperty -Name osaSummaryResultsLink -Value $osaLink

    $osaTotalVulnerableLibs = $osaSummaryResults.highVulnerabilityLibraries + $osaSummaryResults.mediumVulnerabilityLibraries + $osaSummaryResults.lowVulnerabilityLibraries

    $scanResults | Add-Member -MemberType NoteProperty -Name osaVulnerableLibraries -Value $osaTotalVulnerableLibs
    $scanResults | Add-Member -MemberType NoteProperty -Name osaOkLibraries -Value $osaSummaryResults.nonVulnerableLibraries
    $scanResults | Add-Member -MemberType NoteProperty -Name osaCveList -Value $osaCVE 
    $scanResults | Add-Member -MemberType NoteProperty -Name osaLibraries -Value $osaLibraries

    return $scanResults
}

