echo $pwd
$originaldir = (pwd).path
echo $(tree)

echo 'Downloading the releases file...'
Invoke-WebRequest -Uri https://api.github.com/repos/itsignacioportal/hacker-scoper/releases/latest -OutFile $env:TEMP\releases.json

echo 'Installing jq...'
choco install jq

echo 'Parsing latest version tag from JSON...'
$version = type $env:TEMP\releases.json | C:\ProgramData\chocolatey\bin\jq.exe '.tag_name'
$version = $version -replace '"',''

echo 'Parsing download URL from JSON...'
$cmdOutput = type $env:TEMP\releases.json | C:\ProgramData\chocolatey\bin\jq.exe '.assets[11].browser_download_url'

echo 'Downloading the windows_32-bit file...'
$cmdOutput = $cmdOutput -replace '"',''
Invoke-WebRequest -Uri $cmdOutput -OutFile choco\hacker-scoper\tools\hacker-scoper_$($version)_windows_32-bit.zip

echo 'Parsing download URL from JSON...'
$cmdOutput = type $env:TEMP\releases.json | C:\ProgramData\chocolatey\bin\jq.exe '.assets[12].browser_download_url'

echo 'Downloading the windows_64-bit file...'
$cmdOutput = $cmdOutput -replace '"',''
Invoke-WebRequest -Uri $cmdOutput -OutFile choco\hacker-scoper\tools\hacker-scoper_$($version)_windows_64-bit.zip


echo 'Preparing Chocolatey package installer...'
Copy-Item choco\chocolateyinstall_template.ps1 choco\hacker-scoper\tools\chocolateyinstall.ps1
$filePath = "choco\hacker-scoper\tools\chocolateyinstall.ps1"
(Get-Content $filePath).Replace("VERSIONHERE",$version) | Set-Content $filePath

echo 'Preparing Chocolatey nuspec file...'
Copy-Item choco\hacker-scoper_template.nuspec choco\hacker-scoper\hacker-scoper.nuspec
$filePath = "choco\hacker-scoper\hacker-scoper.nuspec"
$version = $version -replace 'v',''
(Get-Content $filePath).Replace("VERSIONHERE",$version) | Set-Content $filePath

cd choco\hacker-scoper
echo "We're in '$pwd'"
tree /F