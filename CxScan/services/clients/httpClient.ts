import * as url from 'url';
import * as request from 'superagent';
import {Logger} from "../logger";

interface InternalRequestOptions extends RequestOptions {
    method: 'put' | 'post' | 'get';
    singlePostData?: object;
    multipartPostData?: {
        fields: { [fieldName: string]: any },

        // Key: attachment field name.
        // Value: path of the file to attach.
        attachments: { [fieldName: string]: string }
    };
    retry: boolean;
}

interface RequestOptions {
    baseUrlOverride?: string;
    suppressWarnings?: boolean;
}

/**
 * Implements low-level API request logic.
 */
export class HttpClient {
    accessToken: string = '';

    private username = '';
    private password = '';

    constructor(private readonly baseUrl: string, private readonly log: Logger) {
    }

    login(username: string, password: string) {
        this.log.info('Logging into the Checkmarx service.');
        this.username = username;
        this.password = password;
        return this.loginWithStoredCredentials();
    }

    getRequest(relativePath: string, options?: RequestOptions): Promise<any> {
        const internalOptions: InternalRequestOptions = {retry: true, method: 'get'};
        return this.sendRequest(relativePath, Object.assign(internalOptions, options));
    }

    postRequest(relativePath: string, data: object): Promise<any> {
        return this.sendRequest(relativePath, {singlePostData: data, retry: true, method: 'post'});
    }

    putRequest(relativePath: string, data: object): Promise<any> {
        return this.sendRequest(relativePath, {singlePostData: data, retry: true, method: 'put'});
    }

    postMultipartRequest(relativePath: string,
                         fields: { [fieldName: string]: any },
                         attachments: { [fieldName: string]: string }) {
        return this.sendRequest(relativePath, {
            method: 'post',
            multipartPostData: {
                fields,
                attachments
            },
            retry: true
        });
    }

    private sendRequest(relativePath: string, options: InternalRequestOptions): Promise<any> {
        const effectiveBaseUrl = options.baseUrlOverride || this.baseUrl;
        const fullUrl = url.resolve(effectiveBaseUrl, relativePath);

        this.log.debug(`Sending ${options.method.toUpperCase()} request to ${fullUrl}`);

        let result = request[options.method](fullUrl)
            .auth(this.accessToken, {type: 'bearer'})
            .accept('json');

        result = HttpClient.includePostData(result, options);

        return result.then(
            (response: request.Response) => response.body,
            async (err: any) => this.handleHttpError(options, err, relativePath, fullUrl)
        );
    }

    private async handleHttpError(options: InternalRequestOptions, err: any, relativePath: string, fullUrl: string) {
        const canRetry = options.retry && err && err.response && err.response.unauthorized;
        if (canRetry) {
            this.log.warning('Access token expired, requesting a new token');
            await this.loginWithStoredCredentials();

            const optionsClone = Object.assign({}, options);
            // Avoid infinite recursion.
            optionsClone.retry = false;
            return this.sendRequest(relativePath, optionsClone);
        } else {
            const message = `${options.method.toUpperCase()} request failed to ${fullUrl}`;
            const logMethod = options.suppressWarnings ? 'debug' : 'warning';
            this.log[logMethod](message);
            return Promise.reject(err);
        }
    }

    private static includePostData(result: request.SuperAgentRequest, options: InternalRequestOptions) {
        if (options.singlePostData) {
            result = result.send(options.singlePostData);
        } else if (options.multipartPostData) {
            const {fields, attachments} = options.multipartPostData;
            result = result.field(fields);
            for (const prop in attachments) {
                result = result.attach(prop, attachments[prop]);
            }
        }
        return result;
    }

    private loginWithStoredCredentials() {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
        const fullUrl = url.resolve(this.baseUrl, 'auth/identity/connect/token');
        return request
            .post(fullUrl)
            .type('form')
            .send({
                userName: this.username,
                password: this.password,
                grant_type: 'password',
                scope: 'sast_rest_api',
                client_id: 'resource_owner_client',
                client_secret: '014DF517-39D1-4453-B7B3-9930C563627C'
            })
            .then(
                (response: request.Response) => {
                    this.accessToken = response.body.access_token;
                },
                (err: any) => {
                    const status = err && err.response ? (err.response as request.Response).status : 'n/a';
                    const message = err && err.message ? err.message : 'n/a';
                    this.log.error(`POST request failed to ${fullUrl}. HTTP status: ${status}, message: ${message}`);
                    throw Error('Login failed');
                }
            );
    }
}
