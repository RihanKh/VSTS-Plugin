$SAST_ENGINE_CONFIG = "sast/engineConfigurations";
$SAST_UPDATE_SCAN_SETTINGS = "sast/scanSettings"; #Update preset and configuration
$SAST_GET_SCAN_SETTINGS = "sast/scanSettings/{projectId}"; #Update preset and configuration
$SAST_CREATE_SCAN = "sast/scans"; #Run a new Scan
$SAST_SCAN = "sast/scans/{scanId}"; 
$SAST_SCAN_QUEUE = "sast/scansQueue";
$SAST_QUEUE_SCAN_STATUS = "sast/scansQueue/{scanId}";
$SAST_SCAN_RESULTS = "sast/scans/{scanId}";
$SAST_SCAN_PROJECT = "projects"; #Create new project (default preset and configuration)
$SAST_GET_PROJECT = "projects?projectname={name}&teamid={teamId}"; # Get  project
$SAST_PROJECT_BY_ID = "projects/{projectId}"; #GetProjectConfiguration
$SAST_ZIP_ATTACHMENTS = "projects/{projectId}/sourceCode/attachments";#Attach ZIP file 
$SAST_CREATE_REPORT = "reports/sastScan/"; #Create new report (get ID)
$SAST_GET_REPORT_STATUS = "reports/sastScan/{reportId}/status"; #Get report status
$SAST_GET_REPORT = "reports/sastScan/{reportId}"; #Get report status    
$SAST_SCAN_RESULTS_STATISTICS = "sast/scans/{scanId}/resultsStatistics";
$MAX_ZIP_SIZE_BYTES = 209715200;
$TEMP_FILE_NAME_TO_ZIP = "zippedSource";
$LINK_FORMAT = "{url}/CxWebClient/portal#/projectState/{projectId}/Summary";
$CONTENT_TYPE_APPLICATION_JSON = "application/json";
$CONTENT_TYPE_APPLICATION_JSON_V1 = "application/json;v=1.0";
$CONTENT_TYPE_APPLICATION_XML_V1 = "application/xml;v=1.0";
$CONTENT_TYPE_APPLICATION_PDF_V1 = "application/pdf;v=1.0";
$reportTimeoutSec = 500;