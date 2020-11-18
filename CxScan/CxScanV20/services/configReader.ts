import taskLib = require('azure-pipelines-task-lib/task');
import {Logger, ScaConfig, ScanConfig, SourceLocationType, TeamApiClient} from "@checkmarx/cx-common-js-client";
import {SastConfig} from "@checkmarx/cx-common-js-client/dist/dto/sastConfig";

export class ConfigReader {
    constructor(private readonly log: Logger) {
    }

    private static getNumericInput(name: string): number | undefined {
        const rawValue = taskLib.getInput(name, false);
        let result;
        if (typeof rawValue !== 'undefined') {
            if (rawValue == null) {
                result = NaN;
            } else {
                result = +rawValue;
            }
        }
        return result;
    }

    readConfig(): ScanConfig {
        const SUPPORTED_AUTH_SCHEME = 'UsernamePassword';

        this.log.debug('Reading configuration.');

        const sastEnabled = taskLib.getBoolInput('enableSastScan', false);
        const dependencyScanEnabled = taskLib.getBoolInput('enableDependencyScan', false);

        let endpointId;
        let authScheme;
        let sastServerUrl;
        let sastUsername;
        let sastPassword;

        if (sastEnabled) {
            endpointId = taskLib.getInput('CheckmarxService', false) || '';
            authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false) || undefined;
            if (authScheme !== SUPPORTED_AUTH_SCHEME) {
                throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
            }
            sastServerUrl = taskLib.getEndpointUrl(endpointId, false) || '';
            sastUsername = taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '';
            sastPassword = taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '';
        }

        let endpointIdSCA;
        let authSchemeSCA;
        let scaServerUrl;
        let scaUsername;
        let scaPassword;

        if (dependencyScanEnabled) {
            endpointIdSCA = taskLib.getInput('dependencyServerURL', false) || '';
            authSchemeSCA = taskLib.getEndpointAuthorizationScheme(endpointIdSCA, false) || undefined;
            if (authSchemeSCA !== SUPPORTED_AUTH_SCHEME) {
                throw Error(`The authorization scheme ${authSchemeSCA} is not supported for a CX server.`);
            }
            scaServerUrl = taskLib.getEndpointUrl(endpointIdSCA, false) || '';
            scaUsername = taskLib.getEndpointAuthorizationParameter(endpointIdSCA, 'username', false) || '';
            scaPassword = taskLib.getEndpointAuthorizationParameter(endpointIdSCA, 'password', false) || '';
        }

        //TODO: remove SCA stuff from comment once its decided to use SCA in VSTS.

        const sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
            throw Error('Sources directory is not provided.');
        }

        const rawTeamName = taskLib.getInput('fullTeamName', false) || '';

        let presetName;
        const customPreset = taskLib.getInput('customPreset', false) || '';
        if (customPreset) {
            presetName = customPreset;
        } else {
            presetName = taskLib.getInput('preset', false) || '';
        }

        const scanType = taskLib.getInput('scanType', false) || '';
        const isIncremental = (scanType === 'Incremental Scan');

        let rawTimeout = taskLib.getInput('scanTimeout', false) as any;
        let scanTimeoutInMinutes = +rawTimeout;
        const scaResult: ScaConfig = {
            accessControlUrl: taskLib.getInput('dependencyAccessControlURL', false) || '',
            apiUrl: scaServerUrl || '',
            username: scaUsername || '',
            password: scaPassword || '',
            tenant: taskLib.getInput('dependencyTenant', false) || '',
            webAppUrl: taskLib.getInput('dependencyWebAppURL', false) || '',
            dependencyFileExtension: taskLib.getInput('dependencyFileExtension', false) || '',
            dependencyFolderExclusion: taskLib.getInput('dependencyFolderExclusion', false) || '',
            sourceLocationType: SourceLocationType.LOCAL_DIRECTORY,
            vulnerabilityThreshold: taskLib.getBoolInput('scaVulnerabilityThreshold', false) || false,
            highThreshold: ConfigReader.getNumericInput('scaHigh'),
            mediumThreshold: ConfigReader.getNumericInput('scaMedium'),
            lowThreshold: ConfigReader.getNumericInput('scaLow')

        };
        const sastResult: SastConfig = {
            serverUrl: sastServerUrl || '',
            username: sastUsername || '',
            password: sastPassword || '',
            teamName: TeamApiClient.normalizeTeamName(rawTeamName) || '',
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            isIncremental: isIncremental,
            presetName,
            scanTimeoutInMinutes: scanTimeoutInMinutes || undefined,
            comment: taskLib.getInput('comment', false) || '',
            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false) || false,
            vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false) || false,
            highThreshold: ConfigReader.getNumericInput('high'),
            mediumThreshold: ConfigReader.getNumericInput('medium'),
            lowThreshold: ConfigReader.getNumericInput('low'),
            forceScan: !isIncremental,
            isPublic: true
        };

        const result: ScanConfig = {
            enableSastScan: taskLib.getBoolInput('enableSastScan', false),
            enableDependencyScan: taskLib.getBoolInput('enableDependencyScan', false),
            scaConfig: scaResult,
            sastConfig: sastResult,
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            sourceLocation,
            cxOrigin: 'VSTS',
            projectName: taskLib.getInput('projectName', false) || '',
        };
        this.format(result);
        this.formatSCA(result);

        return result;
    }

    private format(config: ScanConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);
        if (config.enableSastScan && config.sastConfig != null) {
            this.log.info(`
-------------------------------CxSAST Configurations:--------------------------------
URL: ${config.sastConfig.serverUrl}
Project name: ${config.projectName}
Source location: ${config.sourceLocation}
Full team path: ${config.sastConfig.teamName}
Scan type : ${taskLib.getInput('scanType', false)}
Preset name: ${config.sastConfig.presetName}
Scan timeout in minutes: ${config.sastConfig.scanTimeoutInMinutes}
Deny project creation: ${config.sastConfig.denyProject}
Force scan: ${config.sastConfig.forceScan}
Is incremental scan: ${config.sastConfig.isIncremental}
Folder exclusions: ${formatOptionalString(config.sastConfig.folderExclusion)}
Include/Exclude Wildcard Patterns: ${formatOptionalString(config.sastConfig.fileExtension)}
Is synchronous scan: ${config.isSyncMode}

CxSAST thresholds enabled: ${config.sastConfig.vulnerabilityThreshold}`);
            if (config.sastConfig.vulnerabilityThreshold) {
                this.log.info(`CxSAST high threshold: ${formatOptionalNumber(config.sastConfig.highThreshold)}`);
                this.log.info(`CxSAST medium threshold: ${formatOptionalNumber(config.sastConfig.mediumThreshold)}`);
                this.log.info(`CxSAST low threshold: ${formatOptionalNumber(config.sastConfig.lowThreshold)}`);
            }

            this.log.info(`Enable Project Policy Enforcement: ${config.sastConfig.enablePolicyViolations}`);
            this.log.info('------------------------------------------------------------------------------');
        }
    }

    private formatSCA(config: ScanConfig): void {
        if (config.enableDependencyScan && config.scaConfig != null) {
            this.log.info(`
-------------------------------SCA Configurations:--------------------------------
AccessControl: ${config.scaConfig.accessControlUrl}
ApiURL: ${config.scaConfig.apiUrl}
WebAppUrl: ${config.scaConfig.webAppUrl}
Account: ${config.scaConfig.tenant}
Include/Exclude Wildcard Patterns: ${config.scaConfig.dependencyFileExtension}
Folder Exclusion: ${config.scaConfig.dependencyFolderExclusion}
Vulnerability Threshold: ${config.scaConfig.vulnerabilityThreshold}
`);
            if (config.scaConfig.vulnerabilityThreshold) {
                this.log.info(`High Threshold: ${config.scaConfig.highThreshold}
Medium Threshold: ${config.scaConfig.mediumThreshold}
Low Threshold: ${config.scaConfig.lowThreshold}`)
            }
            this.log.info('------------------------------------------------------------------------------');
        }
    }

}