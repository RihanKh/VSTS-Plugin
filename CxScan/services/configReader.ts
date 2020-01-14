import {ScanConfig} from "../dto/scanConfig";
import {Logger} from "./logger";
import taskLib = require('azure-pipelines-task-lib/task');
import {TeamApiClient} from "./clients/teamApiClient";

export class ConfigReader {
    constructor(private readonly log: Logger) {
    }

    readConfig(): ScanConfig {
        const SUPPORTED_AUTH_SCHEME = 'UsernamePassword';

        this.log.debug('Reading configuration.');

        const endpointId = taskLib.getInput('CheckmarxService', true) || '';

        const sourceLocation = taskLib.getVariable('Build.SourcesDirectory');
        if (typeof sourceLocation === 'undefined') {
            throw Error('Sources directory is not provided.');
        }

        const authScheme = taskLib.getEndpointAuthorizationScheme(endpointId, false);
        if (authScheme !== SUPPORTED_AUTH_SCHEME) {
            throw Error(`The authorization scheme ${authScheme} is not supported for a CX server.`);
        }

        const rawTeamName = taskLib.getInput('fullTeamName', true);

        let presetName;
        const customPreset = taskLib.getInput('customPreset', false);
        if (customPreset) {
            presetName = customPreset;
        } else {
            presetName = taskLib.getInput('preset', true) || '';
        }

        let rawTimeout = taskLib.getInput('scanTimeout', false) as any;
        let scanTimeoutInMinutes = +rawTimeout;

        const result: ScanConfig = {
            serverUrl: taskLib.getEndpointUrl(endpointId, false),
            username: taskLib.getEndpointAuthorizationParameter(endpointId, 'username', false) || '',
            password: taskLib.getEndpointAuthorizationParameter(endpointId, 'password', false) || '',

            sourceLocation,
            projectName: taskLib.getInput('projectName', true) || '',
            teamName: TeamApiClient.normalizeTeamName(rawTeamName),
            denyProject: taskLib.getBoolInput('denyProject', false),
            folderExclusion: taskLib.getInput('folderExclusion', false) || '',
            fileExtension: taskLib.getInput('fileExtension', false) || '',
            isIncremental: taskLib.getBoolInput('incScan', true),
            isSyncMode: taskLib.getBoolInput('syncMode', false),
            presetName,
            scanTimeoutInMinutes: scanTimeoutInMinutes || undefined,
            comment: taskLib.getInput('comment', false) || '',

            enablePolicyViolations: taskLib.getBoolInput('enablePolicyViolations', false),
            vulnerabilityThreshold: taskLib.getBoolInput('vulnerabilityThreshold', false),
            highThreshold: ConfigReader.getNumericInput('high'),
            mediumThreshold: ConfigReader.getNumericInput('medium'),
            lowThreshold: ConfigReader.getNumericInput('low'),

            forceScan: false,
            isPublic: true
        };

        this.format(result);

        return result;
    }

    private static getNumericInput(name: string): number | undefined {
        const rawValue = taskLib.getInput(name, false);
        let result;
        if (typeof rawValue !== 'undefined') {
            if (rawValue == null) 
            {
                result = NaN;
            }
            else {
                result = +rawValue;
            }
        }
        return result;
    }

    private format(config: ScanConfig): void {
        const formatOptionalString = (input: string) => input || 'none';
        const formatOptionalNumber = (input: number | undefined) => (typeof input === 'undefined' ? 'none' : input);

        this.log.info(`
-------------------------------Configurations:--------------------------------
URL: ${config.serverUrl}
Project name: ${config.projectName}
Source location: ${config.sourceLocation}
Full team path: ${config.teamName}
Preset name: ${config.presetName}
Scan timeout in minutes: ${config.scanTimeoutInMinutes}
Deny project creation: ${config.denyProject}

Is incremental scan: ${config.isIncremental}
Folder exclusions: ${formatOptionalString(config.folderExclusion)}
File exclusions: ${formatOptionalString(config.fileExtension)}
Is synchronous scan: ${config.isSyncMode}

CxSAST thresholds enabled: ${config.vulnerabilityThreshold}`);

        if (config.vulnerabilityThreshold) {
            this.log.info(`CxSAST high threshold: ${formatOptionalNumber(config.highThreshold)}`);
            this.log.info(`CxSAST medium threshold: ${formatOptionalNumber(config.mediumThreshold)}`);
            this.log.info(`CxSAST low threshold: ${formatOptionalNumber(config.lowThreshold)}`);
        }

        this.log.info(`Enable Project Policy Enforcement: ${config.enablePolicyViolations}`);
        this.log.info('------------------------------------------------------------------------------');
    }
}