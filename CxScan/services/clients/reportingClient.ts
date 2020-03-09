import {HttpClient} from "./httpClient";
import {Logger} from "../logger";
import {Waiter} from "../waiter";
import {ReportStatus} from "../../dto/api/reportStatus";
import {PollingSettings} from "../../dto/pollingSettings";
import {Stopwatch} from "../stopwatch";
import * as xml2js from "xml2js";

/**
 * Uses Cx API to generate and download XMl reports.
 */
export class ReportingClient {
    private static readonly REPORT_TYPE = 'XML';

    private static readonly pollingSettings: PollingSettings = {
        intervalSeconds: 5,
        masterTimeoutMinutes: 8
    };

    private readonly stopwatch = new Stopwatch();

    constructor(private readonly httpClient: HttpClient, private readonly log: Logger) {
    }

    async generateReport(scanId: number) {
        const reportId = await this.startReportGeneration(scanId);
        await this.waitForReportGenerationToFinish(reportId);
        return this.getReport(reportId);
    }

    private async startReportGeneration(scanId: number) {
        await this.delay(5555);
        const request = {
            scanId: scanId,
            reportType: ReportingClient.REPORT_TYPE
        };
        const response = await this.httpClient.postRequest('reports/sastScan', request);
        return response.reportId;
    }

    private async waitForReportGenerationToFinish(reportId: number) {
        this.stopwatch.start();

        this.log.info(`Waiting for server to generate ${ReportingClient.REPORT_TYPE} report.`);
        let lastStatus: ReportStatus;
        try {
            const waiter = new Waiter();
            lastStatus = await waiter.waitForTaskToFinish(
                () => this.checkIfReportIsCompleted(reportId),
                this.logWaitingProgress,
                ReportingClient.pollingSettings
            );
        } catch (e) {
            throw Error(`Waiting for ${ReportingClient.REPORT_TYPE} report generation has reached the time limit (${ReportingClient.pollingSettings.masterTimeoutMinutes} minutes).`);
        }

        if (lastStatus === ReportStatus.Created) {
            this.log.info(`${ReportingClient.REPORT_TYPE} report was created successfully.`);
        } else {
            throw Error(`${ReportingClient.REPORT_TYPE} report cannot be generated. Status [${lastStatus}].`);
        }
    }

    private async getReport(reportId: number) {
        const reportBytes = await this.httpClient.getRequest(`reports/sastScan/${reportId}`) as Uint8Array;
        const reportBuffer = new Buffer(reportBytes);
        return xml2js.parseStringPromise(reportBuffer);
    }

    private delay(ms: number) {
        this.log.debug("Activating delay for: " + ms);
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async checkIfReportIsCompleted(reportId: number) {
        const path = `reports/sastScan/${reportId}/status`;
        let time = new Date();
        await this.delay(5555);
        let response = await this.httpClient.getRequest(path);
        let status = response.status.value;

        if (status === ReportStatus.Failed) {
            this.log.warning("Failed on first report status request");
            for (let i = 1; i < 5; i++) {
                await this.delay(5555);
                response = await this.httpClient.getRequest(path);
                status = response.status.value;
                time = new Date();
                this.log.warning("Time " + time.getHours() + ":" + time.getMinutes() + ":" + time.getSeconds() + ": Scan status of request number: " + (i + 1) + ": [" + status + "], requested path: + " + path);
                if (status !== ReportStatus.Failed) {
                    break;
                }
            }
        }

        const isCompleted =
            status === ReportStatus.Deleted ||
            status === ReportStatus.Failed ||
            status === ReportStatus.Created;

        if (isCompleted) {
            return Promise.resolve(status);
        } else {
            return Promise.reject(status);
        }
    }

    private logWaitingProgress = () => {
        const timeout = ReportingClient.pollingSettings.masterTimeoutMinutes as number;
        let secondsLeft = timeout * 60 - this.stopwatch.getElapsedSeconds();
        if (secondsLeft < 0) {
            secondsLeft = 0;
        }
        this.log.info(`Waiting for server to generate ${ReportingClient.REPORT_TYPE} report. ${secondsLeft} seconds left to timeout.`);
    };
}