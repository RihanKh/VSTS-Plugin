pushd %~dp0..\CxScan\CxScanV20

call tsc

set INPUT_CheckmarxService=endpointId
set ENDPOINT_URL_endpointId=http://10.32.0.11
set ENDPOINT_AUTH_PARAMETER_endpointId_USERNAME=admin@cx
set ENDPOINT_AUTH_PARAMETER_endpointId_PASSWORD=Cx123456!
set BUILD_SOURCESDIRECTORY=C:\Users\MuhammedS\Downloads\BookStore_Small_CLI
set INPUT_ENABLESASTSCAN=true
set INPUT_PROJECTNAME=adurun
set INPUT_FULLTEAMNAME=\CxServer
set INPUT_DENYPROJECT=false
set INPUT_COMMENT=Greetings from TypeScript
set ENDPOINT_AUTH_SCHEME_endpointId=UsernamePassword
set BUILD_DEFINITIONNAME=builddef
set BUILD_BUILDNUMBER=23
set INPUT_SYNCMODE=true
set INPUT_ENABLEPOLICYVIOLATIONS=true
set INPUT_PRESET=All
set INPUT_SCANTYPE = Incremental Scan
set INPUT_VULNERABILITYTHRESHOLD=false
set INPUT_HIGH=1
set INPUT_MEDIUM=1
set INPUT_LOW=1
set ENDPOINT

set INPUT_ENABLEDEPENDENCYSCAN=false
set INPUT_dependencyServerURL=endpointIdSCA
set ENDPOINT_URL_endpointIdSCA=https://eu.api-sca.checkmarx.net
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_USERNAME=admin
set ENDPOINT_AUTH_PARAMETER_endpointIdSCA_PASSWORD=Plugins1!
set ENDPOINT_AUTH_SCHEME_endpointIdSCA=UsernamePassword
set INPUT_DEPENDENCYACCESSCONTROLURL=https://eu.platform.checkmarx.net
set INPUT_DEPENDENCYWEBAPPURL=https://eu.sca.checkmarx.net
set INPUT_DEPENDENCYTENANT=PluginTests
set Endpoint
node target\index.js

popd