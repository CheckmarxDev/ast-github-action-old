const fetch = require('node-fetch');
const { stringify } = require('querystring');
const { wrapError, timeout, handleResponse } = require('./utils');
const { format } = require('url');

const DEFAULT_TIMEOUT = 5 * 1000;

class Ast {
    #config;
    #token;
    #tokenExpiration;

    async _getToken() {
        // TODO: Use the refresh token instead of generating new token
        if (this.#token && Date.now() < this.#tokenExpiration) {
            return this.#token;
        }

        const credentialsPayload = stringify({
            grant_type: 'client_credentials',
            client_id: this.#config.astAccessKeyId,
            client_secret: this.#config.astAccessKeySecret,
        });

        try {
            const requestTokenDate = Date.now();
            const res = await fetch(this.#config.astAuthenticationUri, {
                method: 'POST',
                body: credentialsPayload,
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                },
                timeout: DEFAULT_TIMEOUT,
            }).then(handleResponse);

            this.#tokenExpiration = requestTokenDate + res.expires_in;
            this.#token = res.access_token;
            return this.#token;
        } catch (e) {
            throw wrapError(e, 'Failed to get ast token')
        }
    }

    async _getAstRequestInit(headers, body, method, timeout) {
        const defaultRequestInit =  {
            headers: {
                Authorization: await this._getToken(),
                'User-Agent': 'ast-github-action/0.1 (+https://github.com/CheckmarxDev/ast-github-action)',
            },
            timeout: DEFAULT_TIMEOUT
        };

        const o = Object.assign({}, defaultRequestInit);
        if (headers) {
            Object.assign(o.headers, headers);
        }

        if (body) {
            o.headers['content-type'] = 'application/json';
            Object.assign(o, { body: JSON.stringify(body) });
        }

        if (method) {
            Object.assign(o, { method })
        }


        if (typeof timeout !== 'undefined') {
            Object.assign(o, { timeout });
        }

        return o;
    }

    configure(config) {
        this.#config = config;
    }

    async createScan(projectID) {
        const scan = {
            config: [{
                type: 'sast',
                value: {
                    incremental: 'true',
                    presetName: 'Checkmarx Default',
                }
            }],
            project: {
                id: projectID,
                type: 'git',
                handler: {
                    repoUrl: this.#config.githubRepoUrl,
                    branch: this.#config.githubBranch,
                }
            },
        };

        if (this.#config.githubRepoToken) {
            scan.project.handler.credentials = {
                type: 'JWT',
                value: this.#config.githubRepoToken,
            }
        }

        try {
            return await fetch(
                this.#config.astScansURI,
                await this._getAstRequestInit({ Accept: 'version=1.1' }, scan, 'POST')
            ).then(handleResponse);
        } catch(e) {
            throw wrapError(e, `Failed to create scan ${JSON.stringify(scan, null, 2)}`);
        }
    }

    async getScanByID(scanID) {
        try {
            return await fetch(
                `${this.#config.astScansURI}/${scanID}`,
                await this._getAstRequestInit({ Accept: 'version=1.1' })
            ).then(handleResponse);
        } catch(e) {
            throw wrapError(e, 'Failed to get scan');
        }
    }

    async waitForScanToComplete(scanID, timeoutMS = 120 * 1000, intervalMS = 1000) {
        let interval;
        return timeout(() => {
            return new Promise((resolve, reject) => {
                interval = setInterval(async () => {
                    try {
                        const scan = await this.getScanByID(scanID);
                        if (scan.status === 'Completed') {
                            resolve();
                        }

                        if (['Failed', 'Canceled '].includes(scan.status)) {
                            reject(new Error(`Scan was ${scan.status}`));
                        }
                    } catch(e) {
                        reject(e);
                    }
                }, intervalMS)
            });
        }, timeoutMS)
            .catch(e => Promise.reject(wrapError(e, 'Scan was not completed')))
            .finally(() => clearInterval(interval));
    }

    async getResultsByScanID(scanID) {
        const url = format({
            host: this.#config.astResultsURI,
            query:  {
                'scan-id': scanID
            }
        });

        try {
            return await fetch(url, await this._getAstRequestInit()).then(handleResponse);
        } catch (e) {
            throw wrapError(e, 'Failed to get results');
        }
    }
}

const ast = new Ast();
module.exports = {
    init(config) {
        ast.configure(config);
        return ast;
    }
};
