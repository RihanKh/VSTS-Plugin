pushd %~dp0..\CxScan

call tsc

set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=https://89selfsigned.dm.cx
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=admin@cx
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=Cx123456!
set BUILD_SOURCESDIRECTORY=C:\Checkmarx\SourceCodeExamples\BookStore_Small_CLI
set INPUT_PROJECTNAME=VstsTest
set INPUT_FULLTEAMNAME=\CxServer
set INPUT_DENYPROJECT=false
set INPUT_INCSCAN=true
set INPUT_COMMENT=Greetings from TypeScript
set ENDPOINT_AUTH_SCHEME_endpointId=UsernamePassword
set BUILD_DEFINITIONNAME=builddef
set BUILD_BUILDNUMBER=23
set INPUT_SYNCMODE=true
set INPUT_ENABLEPOLICYVIOLATIONS=true
set INPUT_PRESET=Checkmarx Default

set INPUT_VULNERABILITYTHRESHOLD=true
set INPUT_HIGH=
set INPUT_MEDIUM=
set INPUT_LOW=

node target\index.js

popd