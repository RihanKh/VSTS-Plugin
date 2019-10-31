import {HttpClient} from "./httpClient";
import {ArmStatus} from "../dto/armStatus";
import {Stopwatch} from "./stopwatch";
import {ScanProvider} from "../dto/scanProvider";
import {Waiter} from "./waiter";
import {PolicyViolationGroup} from "../dto/policyViolationGroup";
import {Logger} from "./logger";
import {PollingSettings} from "../dto/pollingSettings";

/**
 * Works with policy-related APIs.
 */
export class ArmClient {
    private static readonly pollingSettings: PollingSettings = {
        intervalSeconds: 10,
        masterTimeoutMinutes: 20
    };

    private readonly stopwatch = new Stopwatch();

    private readonly generalHttpClient: HttpClient;

    private armHttpClient: HttpClient | null = null;

    constructor(httpClient: HttpClient, private readonly log: Logger) {
        this.generalHttpClient = httpClient;
    }

    async init() {
        this.log.info('Resolving CxARM URL.');
        const response = await this.generalHttpClient.getRequest('Configurations/Portal');
        this.armHttpClient = new HttpClient(response.cxARMPolicyURL, this.log, this.generalHttpClient.accessToken);
    }

    async waitForArmToFinish(projectId: number) {
        this.stopwatch.start();

        this.log.info('Waiting for server to retrieve policy violations.');
        let lastStatus = ArmStatus.None;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish<ArmStatus>(
                () => this.checkIfPolicyVerificationCompleted(projectId),
                this.logWaitingProgress,
                ArmClient.pollingSettings
            );
        } catch (e) {
            throw Error(`Waiting for server to retrieve policy violations has reached the time limit. (${ArmClient.pollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus !== ArmStatus.Finished) {
            throw Error(`Generation of scan report [id=${projectId}] failed.`);
        }
    }

    getProjectViolations(projectId: number, provider: ScanProvider): Promise<PolicyViolationGroup[]> {
        const path = `/cxarm/policymanager/projects/${projectId}/violations?provider=${provider}`;
        if (!this.armHttpClient) {
            throw Error('The client was not initialized.');
        }

        return this.armHttpClient.getRequest(path);
    }

    private async checkIfPolicyVerificationCompleted(projectId: number) {
        const path = `sast/projects/${projectId}/publisher/policyFindings/status`;
        const statusResponse = await this.generalHttpClient.getRequest(path) as { status: ArmStatus };
        const {status} = statusResponse;

        const isCompleted =
            status === ArmStatus.Finished ||
            status === ArmStatus.Failed ||
            status === ArmStatus.None;

        if (isCompleted) {
            return Promise.resolve(status);
        } else {
            return Promise.reject(status);
        }
    };

    private logWaitingProgress = (armStatus: ArmStatus) => {
        this.log.info(`Waiting for server to retrieve policy violations. Elapsed time: ${this.stopwatch.getElapsedString()}. Status: ${armStatus}`)
    };
}