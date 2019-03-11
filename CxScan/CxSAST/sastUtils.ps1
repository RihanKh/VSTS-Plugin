$newHighCount = 0;
$newMediumCount = 0;
$newLowCount = 0;
$newInfoCount = 0;

function addSASTResults($results, $scanResults){
    $scanResults | Add-Member -MemberType NoteProperty -Name highResults -Value $results.highSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name mediumResults -Value $results.mediumSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name lowResults -Value $results.lowSeverity;
    $scanResults | Add-Member -MemberType NoteProperty -Name infoResults -Value $results.infoSeverity;

    $sastScanLink = ("{0}/CxWebClient/ViewerMain.aspx?scanId={1}&ProjectID={2}" -f $config.url, $scanResults.scanId, $config.projectId);
    $scanResults | Add-Member -MemberType NoteProperty -Name sastScanResultsLink -Value $sastScanLink

    $sastProjectLink = ("{0}/CxWebClient/portal#/projectState/{1}/Summary" -f $config.url, $config.projectId);
    $scanResults | Add-Member -MemberType NoteProperty -Name sastSummaryResultsLink -Value $sastProjectLink;
   
    $scanResults.sastResultsReady = $true;

    return $scanResults;
}

function setScanDetailedReport($reportObj,  $scanResults){   
    $XMLResults = $reportObj.CxXMLResults

    $jsonQuery=""
    ForEach($query In $xdoc.CxXMLResults.Query) {
        $jsonQuery +=  @{name=$query.name;severity= $query.Severity;resultLength=$query.Result.Length} | ConvertTo-Json -Compress
        $jsonQuery+=";";
    }

    $scanResults | Add-Member -MemberType NoteProperty -Name scanStart -Value $XMLResults.scanStart;
    $scanResults | Add-Member -MemberType NoteProperty -Name scanTime -Value $XMLResults.scanTime;
    $scanResults | Add-Member -MemberType NoteProperty -Name locScanned -Value $XMLResults.linesOfCodeScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name filesScanned -Value $XMLResults.filesScanned;
    $scanResults | Add-Member -MemberType NoteProperty -Name riskLevel -Value $XMLResults.RiskLevelScore
    $scanResults | Add-Member -MemberType NoteProperty -Name projectId -Value $XMLResults.ProjectId

        foreach ($query in $XMLResults.Query) {
            $qResult = $query.result;
            if ([string]::IsNullOrEmpty($qResult.count)){
                if ("False".equals($qResult.falsePositive) -and "New".equals($qResult.status)) {
                    switch ($qResult.severity )
                    {
                        High {$newHighCount++;break}
                        Medium {$newMediumCount++; break}
                        Low {$newLowCount++; break}
                        Info{$newInfoCount++;break}
                    }
                } 
            }else{
                For ($i=0; $i -le $qResult.count; $i++) {
                    $result = $qResult[$i];
                    if ("True".equals($result.falsePositive)) {
                        $qResult = [System.Collections.ArrayList]$qResult
                        $qResult.RemoveAt($i)
                    } elseif ("New".equals($result.status)){
                        switch ($result.severity )
                        {
                            High {$newHighCount++;break}
                            Medium {$newMediumCount++; break}
                            Low {$newLowCount++; break}
                            Info{$newInfoCount++;break}
                        }
                    }
                }
            }
        }
        $scanResults | Add-Member -MemberType NoteProperty -Name newHighCount -Value $newHighCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newMediumCount -Value $newMediumCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newLowCount -Value $newLowCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name newInfoCount -Value $newInfoCount;
        $scanResults | Add-Member -MemberType NoteProperty -Name queryList -Value $jsonQuery;

        return $scanResults;
}

function printResultsToConsole($scanResults) {
    $highNew= "";
    $mediumNew= "";
    $lowNew= "";
    $infoNew= "";

    if ($scanResults.newHighCount -gt 0){$highNew =  (" ({0} new)" -f $scanResults.newHighCount)}
    if ($scanResults.newMediumCount -gt 0){$mediumNew =  (" ({0} new)" -f $scanResults.newMediumCount)}
    if ($scanResults.newLowCount -gt 0){$lowNew =  (" ({0} new)" -f $scanResults.newLowCount)}
    if ($scanResults.newInfoCount -gt 0){$infoNew =  (" ({0} new)" -f $scanResults.newInfoCount)}


    Write-Host "----------------------------Checkmarx Scan Results(CxSAST):-------------------------------";
    Write-Host "High severity results: " $scanResults.highResults $highNew;
    Write-Host "Medium severity results: " $scanResults.mediumResults $mediumNew;
    Write-Host "Low severity results: " $scanResults.lowResults $lowNew;
    Write-Host "Info severity results: " $scanResults.infoResults $infoNew;
    Write-Host "";
    Write-Host "Scan results location: " $scanResults.sastScanResultsLink;
    Write-Host "------------------------------------------------------------------------------------------\n";
}

