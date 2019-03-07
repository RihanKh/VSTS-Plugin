function CheckFile($dir, $exFolders){
  $bool = $true
  foreach ($folder in $exFolders){

    if ($dir -like [IO.Path]::Combine('*', $folder,'*')){
        $bool = $false
     }
   }

   return $bool;
}


function ZipSource($folderExclusion, $fileExtension, $sourceLocation, $debugMode){

   $filesStr = ""
   $foldersStr = ""

    if(!([string]::IsNullOrEmpty($fileExtension))){
        $filesStr = $fileExtension
    }
    if(!([string]::IsNullOrEmpty($folderExclusion))){
        $foldersStr = $folderExclusion
    }
    try{
       [array]$allFiles = $filesStr.Split(",") | Foreach-Object { if( !([string]::IsNullOrEmpty($_))){ $_.Trim() }}

       $exFiles = $allFiles| Foreach-Object { if (!([string]::IsNullOrEmpty($_)) -and  $_.ToString().StartsWith('!') )
                                                 { "$_".Replace("!","") }
                                            }
       $exFiles = $exFiles | Foreach-Object { if ($_.ToString().StartsWith('.')){ "*$_" } Else {"$_"} }


       $incFiles = $allFiles| Foreach-Object { if (!([string]::IsNullOrEmpty($_)) -and -not $_.ToString().StartsWith('!') )
                                                   { "$_" }
                                             }
       $incFiles = $incFiles | Foreach-Object { if ($_.ToString().StartsWith('.')){ "*$_" } Else {"$_"} }


     }  catch {
       write-host ("Failed to parse files extensions: {0}" -f $_.Exception.Message)
      [array]$exFiles = @();
      [array]$incFiles = @();
     }
    try{
         [array]$exFolders = $foldersStr.Split(",") | Foreach-Object{ if( !([string]::IsNullOrEmpty($_))){ $_.Trim()}}
    } catch {
       write-host ("Failed to parse folder exclusions: {0}" -f $_.Exception.Message)
      [array]$exFolders = @();
    }

    $zipfilename = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
    Add-Type -Assembly System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipArchive] $arch = [System.IO.Compression.ZipFile]::Open($zipfilename,[System.IO.Compression.ZipArchiveMode]::Update)

    $numOfFiles = 0;
    write-host "Zipping workspace: " $sourceLocation -foregroundcolor "green"
    Get-ChildItem $sourceLocation -Recurse -Exclude $exFiles -Include $incFiles |
    Foreach-Object {
        if(!(([IO.FileInfo]$_.FullName).Attributes -eq "Directory") -and (CheckFile $_.FullName $exFolders) ){
            $loc = $_.FullName.Substring($sourceLocation.length + 1)
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($arch, $_.FullName, $loc, $compressionLevel) | Out-Null
           write-host "Zipping: $_"
            ++$numOfFiles;
         }

    }
    write-host  "Zipping complete with $numOfFiles files."
    write-host  "Temporary file with zipped sources was created at: $zipfilename"
    $arch.Dispose()

    return $zipfilename
}

#folder Pattern

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


function GeneratePattern($folderExclusions, $filterPattern)
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