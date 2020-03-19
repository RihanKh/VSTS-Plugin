import {ScanConfig} from "../../dto/scanConfig";
import {HttpClient} from "./httpClient";
import Zipper from "../zipper";
import {TaskSkippedError} from "../../dto/taskSkippedError";
import {ScanResults} from "../../dto/scanResults";
import {SastClient} from "./sastClient";
import * as url from "url";
import {ArmClient} from "./armClient";
import {UpdateScanSettingsRequest} from "../../dto/api/updateScanSettingsRequest";
import {Logger} from "../logger";
import {ReportingClient} from "./reportingClient";
import {ScanSummaryEvaluator} from "../scanSummaryEvaluator";
import {FilePathFilter} from "../filePathFilter";
import {FileUtil} from "../fileUtil";
import {TeamApiClient} from "./teamApiClient";
import {ScanSummary} from "../../dto/scanSummary";
import {ThresholdError} from "../../dto/thresholdError";

/**
 * High-level CX API client that uses specialized clients internally.
 */
export class CxClient {
    private httpClient: HttpClient | any;
    private sastClient: SastClient | any;
    private armClient: ArmClient | any;

    private teamId = 0;
    private projectId = 0;
    private presetId = 0;
    private isPolicyEnforcementSupported = false;

    private config: ScanConfig | any;

    constructor(private readonly log: Logger) {
    }

    async scan(config: ScanConfig): Promise<ScanResults> {
        this.config = config;

        this.log.info('Initializing Cx client');
        await this.initClients();
        await this.initDynamicFields();

        let result: ScanResults = await this.createSASTScan();
        if (config.isSyncMode) {
            result = await this.getSASTResults(result);
        } else {
            this.log.info('Running in Asynchronous mode. Not waiting for scan to finish.');
        }
        return result;
    }

    private async initClients() {
        const baseUrl = url.resolve(this.config.serverUrl, 'CxRestAPI/');
        this.httpClient = new HttpClient(baseUrl, this.log);
        await this.httpClient.login(this.config.username, this.config.password);

        this.sastClient = new SastClient(this.config, this.httpClient, this.log);

        this.armClient = new ArmClient(this.httpClient, this.log);
        if (this.config.enablePolicyViolations) {
            await this.armClient.init();
        }
    }

    private async createSASTScan(): Promise<ScanResults> {
        this.log.info('-----------------------------------Create CxSAST Scan:-----------------------------------');
        await this.updateScanSettings();
        await this.uploadSourceCode();

        const scanResult = new ScanResults(this.config);
        scanResult.scanId = await this.sastClient.createScan(this.projectId);

        const projectStateUrl = url.resolve(this.config.serverUrl, `CxWebClient/portal#/projectState/${this.projectId}/Summary`);
        this.log.info(`SAST scan created successfully. CxLink to project state: ${projectStateUrl}`);

        return scanResult;
    }

    private delay(ms: number) {
        this.log.debug("Activating delay for: " + ms);
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async getSASTResults(result: ScanResults): Promise<ScanResults> {
        this.log.info('------------------------------------Get CxSAST Results:----------------------------------');
        this.log.info('Retrieving SAST scan results');

        await this.sastClient.waitForScanToFinish();

        await this.addStatisticsToScanResults(result);
        await this.addPolicyViolationsToScanResults(result);

        this.printStatistics(result);

        await this.addDetailedReportToScanResults(result);

        const evaluator = new ScanSummaryEvaluator(this.config, this.log, this.isPolicyEnforcementSupported);
        const summary = evaluator.getScanSummary(result);

        this.logPolicyCheckSummary(summary.policyCheck);

        if (summary.hasErrors()) {
            result.buildFailed = true;
            this.logBuildFailure(summary);
        }

        return result;
    }

    private async getOrCreateProject(): Promise<number> {
        let projectId = await this.getCurrentProjectId();
        if (projectId) {
            this.log.debug(`Resolved project ID: ${projectId}`);
        } else {
            this.log.info('Project not found, creating a new one.');

            if (this.config.denyProject) {
                throw Error(
                    `Creation of the new project [${this.config.projectName}] is not authorized. Please use an existing project.` +
                    " You can enable the creation of new projects by disabling the Deny new Checkmarx projects creation checkbox in the Checkmarx plugin global settings.");
            }

            projectId = await this.createNewProject();
        }

        return projectId;
    }

    private async uploadSourceCode(): Promise<void> {
        const tempFilename = FileUtil.generateTempFileName({prefix: 'cxsrc-', postfix: '.zip'});
        this.log.info(`Zipping source code at ${this.config.sourceLocation} into file ${tempFilename}`);

        const filter = new FilePathFilter(this.config.fileExtension, this.config.folderExclusion);

        const zipper = new Zipper(this.log, filter);
        const zipResult = await zipper.zipDirectory(this.config.sourceLocation, tempFilename);

        if (zipResult.fileCount === 0) {
            throw new TaskSkippedError('Zip file is empty: no source to scan');
        }

        this.log.info(`Uploading the zipped source code.`);
        const urlPath = `projects/${this.projectId}/sourceCode/attachments`;
        await this.httpClient.postMultipartRequest(urlPath,
            {id: this.projectId},
            {zippedSource: tempFilename});
    }

    private async getCurrentProjectId(): Promise<number> {
        this.log.info(`Resolving project: ${this.config.projectName}`);
        let result;
        const encodedName = encodeURIComponent(this.config.projectName);
        const path = `projects?projectname=${encodedName}&teamid=${this.teamId}`;
        try {
            const projects = await this.httpClient.getRequest(path, {suppressWarnings: true});
            if (projects && projects.length) {
                result = projects[0].id;
            }
        } catch (err) {
            const isExpectedError = err.response && err.response.notFound;
            if (!isExpectedError) {
                throw err;
            }
        }
        return result;
    }

    private async createNewProject(): Promise<number> {
        const request = {
            name: this.config.projectName,
            owningTeam: this.teamId,
            isPublic: this.config.isPublic
        };

        const newProject = await this.httpClient.postRequest('projects', request);
        this.log.debug(`Created new project, ID: ${newProject.id}`);

        return newProject.id;
    }

    private async updateScanSettings() {
        const settingsResponse = await this.sastClient.getScanSettings(this.projectId);

        const configurationId = settingsResponse &&
            settingsResponse.engineConfiguration &&
            settingsResponse.engineConfiguration.id;

        const request: UpdateScanSettingsRequest = {
            projectId: this.projectId,
            presetId: this.presetId,
            engineConfigurationId: configurationId || 0
        };

        await this.sastClient.updateScanSettings(request);
    }

    private async addPolicyViolationsToScanResults(result: ScanResults) {
        if (!this.config.enablePolicyViolations) {
            return;
        }

        if (!this.isPolicyEnforcementSupported) {
            this.log.warning('Policy enforcement is not supported by the current Checkmarx server version.');
            return;
        }

        await this.armClient.waitForArmToFinish(this.projectId);

        const projectViolations = await this.armClient.getProjectViolations(this.projectId, 'SAST');
        for (const policy of projectViolations) {
            result.sastPolicies.push(policy.policyName);
            for (const violation of policy.violations) {
                result.sastViolations.push({
                    libraryName: violation.source,
                    policyName: policy.policyName,
                    ruleName: violation.ruleName,
                    detectionDate: (new Date(violation.firstDetectionDateByArm)).toLocaleDateString()
                });
            }
        }
    }

    private async addStatisticsToScanResults(result: ScanResults) {
        const statistics = await this.sastClient.getScanStatistics(result.scanId);
        result.highResults = statistics.highSeverity;
        result.mediumResults = statistics.mediumSeverity;
        result.lowResults = statistics.lowSeverity;
        result.infoResults = statistics.infoSeverity;

        const sastScanPath = `CxWebClient/ViewerMain.aspx?scanId=${result.scanId}&ProjectID=${this.projectId}`;
        result.sastScanResultsLink = url.resolve(this.config.serverUrl, sastScanPath);

        const sastProjectLink = `CxWebClient/portal#/projectState/${this.projectId}/Summary`;
        result.sastSummaryResultsLink = url.resolve(this.config.serverUrl, sastProjectLink);

        result.sastResultsReady = true;
    }

    private async addDetailedReportToScanResults(result: ScanResults) {
        const client = new ReportingClient(this.httpClient, this.log);
        let reportXml;

        for (let i = 1; i < 25; i++) {
            try {
                reportXml = await client.generateReport(result.scanId);
                if (typeof reportXml !== 'undefined' && reportXml !== null) {
                    break;
                }
                await this.delay(5555);
            } catch (e) {
                this.log.warning('Failed to generate report on attempt number: ' + i);
                await this.delay(15555);
            }
        }

        const doc = reportXml.CxXMLResults;
        result.scanStart = doc.$.ScanStart;
        result.scanTime = doc.$.ScanTime;
        result.locScanned = doc.$.LinesOfCodeScanned;
        result.filesScanned = doc.$.FilesScanned;
        result.queryList = CxClient.toJsonQueries(doc.Query);

        // TODO: PowerShell code also adds properties such as newHighCount, but they are not used in the UI.
    }

    private printStatistics(result: ScanResults) {
        this.log.info(`----------------------------Checkmarx Scan Results(CxSAST):-------------------------------
High severity results: ${result.highResults}
Medium severity results: ${result.mediumResults}
Low severity results: ${result.lowResults}
Info severity results: ${result.infoResults}

Scan results location:  ${result.sastScanResultsLink}
------------------------------------------------------------------------------------------
`);
    }

    private static toJsonQueries(queries: any[] | undefined) {
        const SEPARATOR = ';';

        // queries can be undefined if no vulnerabilities were found.
        return (queries || []).map(query =>
            JSON.stringify({
                name: query.$.name,
                severity: query.$.Severity,
                resultLength: query.Result.length
            })
        ).join(SEPARATOR);
    }

    private async getVersionInfo() {
        let versionInfo = null;
        try {
            versionInfo = await this.httpClient.getRequest('system/version', {suppressWarnings: true});
            this.log.info(`Checkmarx server version [${versionInfo.version}]. Hotfix [${versionInfo.hotFix}].`);
        } catch (e) {
            versionInfo = null;
            this.log.info('Checkmarx server version is lower than 9.0.');
        }
        return versionInfo;
    }

    private async initDynamicFields() {
        const versionInfo = await this.getVersionInfo();
        this.isPolicyEnforcementSupported = !!versionInfo;

        this.presetId = await this.sastClient.getPresetIdByName(this.config.presetName);

        const teamApiClient = new TeamApiClient(this.httpClient, this.log);
        this.teamId = await teamApiClient.getTeamIdByName(this.config.teamName);

        this.projectId = await this.getOrCreateProject();
    }

    private logBuildFailure(failure: ScanSummary) {
        this.log.error(
            `********************************************
The Build Failed for the Following Reasons:
********************************************`);
        this.logPolicyCheckError(failure.policyCheck);
        this.logThresholdErrors(failure.thresholdErrors);
    }

    private logPolicyCheckSummary(policyCheck: { wasPerformed: boolean; violatedPolicyNames: string[] }) {
        if (policyCheck.wasPerformed) {
            this.log.info(
                `-----------------------------------------------------------------------------------------
Policy Management:
--------------------`);
            if (policyCheck.violatedPolicyNames.length) {
                this.log.info('Project policy status: violated');

                const names = policyCheck.violatedPolicyNames.join(', ');
                this.log.info(`SAST violated policies names: ${names}`);
            } else {
                this.log.info('Project policy status: compliant');
            }
            this.log.info('-----------------------------------------------------------------------------------------');
        }
    }

    private logThresholdErrors(thresholdErrors: ThresholdError[]) {
        if (thresholdErrors.length) {
            this.log.error('Exceeded CxSAST Vulnerability Threshold.');
            for (const error of thresholdErrors) {
                this.log.error(`SAST ${error.severity} severity results are above threshold. Results: ${error.actualViolationCount}. Threshold: ${error.threshold}`);
            }
        }
    }

    private logPolicyCheckError(policyCheck: { violatedPolicyNames: string[] }) {
        if (policyCheck.violatedPolicyNames.length) {
            this.log.error('Project policy status: violated');
        }
    }
}