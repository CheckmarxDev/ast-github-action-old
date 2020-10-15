const core = require('@actions/core');
const github = require('@actions/github');
const { init } = require('./ast');
const { joinURLs, wrapError } = require('./utils');

const exitWithError = (e) => {
    console.error(e);
    core.setFailed(e);
    process.exit(core.ExitCode.Failure);
};

core.debug(JSON.stringify(github, null, 2));
const context = {
    githubRepo: github.context.payload.repository.full_name,
    githubRepoUrl: github.context.payload.repository.clone_url,
    repo: github.context.repo,
};

switch (github.context.eventName) {
case 'pull_request':
    context.githubCommitHash = github.context.payload.pull_request.head.sha;
    context.githubBranch = github.context.payload.pull_request.head.ref;
    break;
case 'push':
    context.githubCommitHash = github.context.sha;
    context.githubBranch = github.context.ref.substring(github.context.ref.lastIndexOf('/'));
    break;
default:
    exitWithError(new Error('Currently the action support pull_request and push events only'));
}

const inputs = {
    astUri: core.getInput('ast_uri', { required: true }),
    astAccessKeyId: core.getInput('ast_access_key_id', { required: true }),
    astAccessKeySecret: core.getInput('ast_access_key_secret', { required: true }),
    scaUser: core.getInput('sca_user', { required: true }),
    scaPassword: core.getInput('sca_password', { required: true }),
    githubRepoToken: core.getInput('github_repo_token', { required: true }),
    actionScanCompleteTimeoutSecs: core.getInput('action_scan_complete_timeout_secs', { required: true }),
    highResultsThreshold: core.getInput('high_results_threshold', { required: true }),
    mediumResultsThreshold: core.getInput('medium_results_threshold', { required: true }),
    lowResultsThreshold: core.getInput('low_results_threshold', { required: true }),
};

const constants = {
    astAuthenticationUri : joinURLs(inputs.astUri, 'auth/realms/organization/protocol/openid-connect/token'),
    astScansURI: joinURLs(inputs.astUri, 'api/scans'),
    astResultsURI: joinURLs(inputs.astUri, 'api/results'),
    astCargoResultsURI: joinURLs(inputs.astUri, 'api/cargo/results'),
    astMashupResultsURI: joinURLs(inputs.astUri, 'api/results-mesh/results'),
    astIceResultsURI: joinURLs(inputs.astUri, 'api/ice/results'),
    astScanSummaryURI: joinURLs(inputs.astUri, 'api/scan-summary'),
    SCAResultsURI: 'https://api-sca.checkmarx.net/risk-management',
};

const config = Object.assign({}, context, inputs, constants);
const ast = init(config);

async function createScan() {
    // FIXME remove the replace once the slash would not interrupt the delete project
    const projectID = context.githubRepo.replace('/', '-') + " " + context.githubCommitHash.substring(0, 7);
;
    const scan = await ast.createScan(projectID);
    core.info(`Scan #${scan.id} created`);

    const start = Date.now();
    await ast.waitForScanToComplete(scan.id, inputs.actionScanCompleteTimeoutSecs * 1000);
    core.info(`Scan #${scan.id} completed after ${Date.now() - start} ms`);

    const [scanSummary, results, cargoResults, iceResults, scaResults, mashupResults] = await Promise.all([
        ast.getScanSummaryByScanID(scan.id),
        ast.getResultsByScanID(scan.id, 50), // 50 is the annotation limit in github
        ast.getCargoResultsByScanID(scan.id), // 50 is the annotation limit in github
        ast.getIceResultsByScanID(scan.id), 
        ast.getScaResultsByScanID(projectID),
        ast.getMashupResultsByScanID(scan.id), 
    ]);
    core.setOutput('results', results);
    core.info(`cargoResults total ${cargoResults.length}`);
    core.info(`iceResults total ${iceResults.length}`);
    core.info(`scaResults total ${scaResults.length}`);


    return {
        scanID: scan.id,
        results: results.results,
        cargoResults: cargoResults,
        iceResults: iceResults,
        resultsSASTCount: results.totalCount,
        resultsCargoCount: cargoResults.length,
        resultsIceCount: iceResults.length,
        resultsURI: joinURLs(inputs.astUri, `#/projects/${projectID}/results`),
        resultsSeverityCounters: scanSummary.severityCounters,
        scaResults: scaResults,
        resultsSCACount: scaResults.length,
        mashupResults: mashupResults,
        resultsMashupCount:mashupResults.length
    };
}

function getReportResources() {
    // TODO: Change to get from the server
    return {
        highIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/high.svg',
        mediumIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/medium.svg',
        lowIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/low.svg',
        infoIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/info.svg',
        linkIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/link.svg',
        logoIcon: 'https://github-actions-pics.s3.us-east-2.amazonaws.com/logo.svg',
    };
}

async function writeScanReport({ scanID, results, cargoResults, iceResults, resultsSASTCount, resultsCargoCount,resultsIceCount, resultsURI, resultsSeverityCounters, scaResults, resultsSCACount, mashupResults, resultsMashupCount}) {
    const startDate = new Date().toISOString();
    const sastResultsBySeverity = resultsSeverityCounters.reduce((a, r) => {
        a[r.severity] = r.counter;
        return a;
    }, { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

    const cargoLResults = cargoResults.filter(function(x) {
        return x.severity == 'Low';
    }).length
    const cargoMResults = cargoResults.filter(function(x) {
        return x.severity == 'Medium';
    }).length
    const cargoHResults = cargoResults.filter(function(x) {
        return x.severity == 'High';
    }).length

    const iceLResults = iceResults.filter(function(x) {
        return x.severity == 'LOW';
    }).length
    const iceMResults = iceResults.filter(function(x) {
        return x.severity == 'MEDIUM';
    }).length
    const iceHResults = iceResults.filter(function(x) {
        return x.severity == 'HIGH';
    }).length

    const scaLResults = scaResults.filter(function(x) {
        return x.severity == 'Low';
    }).length
    const scaMResults = scaResults.filter(function(x) {
        return x.severity == 'Medium';
    }).length
    const scaHResults = scaResults.filter(function(x) {
        return x.severity == 'High';
    }).length

    
    const mashupLResults = mashupResults.filter(function(x) {
        return x.severity == 'LOW';
    }).length
    const mashupMResults = mashupResults.filter(function(x) {
        return x.severity == 'MEDIUM';
    }).length
    const mashupHResults = mashupResults.filter(function(x) {
        return x.severity == 'HIGH';
    }).length

    let hTotal=sastResultsBySeverity.HIGH + cargoHResults + iceHResults + scaHResults + mashupHResults;
    let mTotal=sastResultsBySeverity.MEDIUM + cargoMResults + iceMResults + scaMResults + mashupMResults;
    let lTotal=sastResultsBySeverity.LOW + cargoLResults + iceLResults + scaLResults + mashupLResults;

    core.info(`hTotal #${hTotal}`);
    core.info(`mTotal #${mTotal}`);
    core.info(`lTotal #${lTotal}`);



    let succeed = true;
    let violations = 0;
    if (inputs.highResultsThreshold > -1 && hTotal > inputs.highResultsThreshold) {
        succeed = false;
        violations += hTotal - inputs.highResultsThreshold;
    }

    if (inputs.mediumResultsThreshold > -1 && mTotal > inputs.mediumResultsThreshold) {
        succeed = false;
        violations += mTotal - inputs.mediumResultsThreshold;
    }

    if (inputs.lowResultsThreshold > -1 && lTotal > inputs.lowResultsThreshold) {
        succeed = false;
        violations += lTotal - inputs.lowResultsThreshold;
    }

    const title = `AST Scan ID #${scanID}`;
    const resources = getReportResources();
    const successHead = `:heavy_check_mark: **Checkmarx scan passed**`;
    const failureHead = `:x: **Checkmarx scan found the following issues:**
- **${violations} Policy Violations**`;
    const summary =
        `![](${resources.logoIcon}) <br><br> \
${succeed ? successHead : failureHead}`;
    const text = `**${resultsSASTCount + resultsCargoCount + resultsIceCount} Vulnerabilities**<br>
    <table style="width:100%">
<tr>
    <th>SAST</th>
    <th>SCA</th>
    <th>Container</th> 
    <th>IaC</th>
    <th>Mashup</th>
  </tr>
<tr>
<td>
${resultsSASTCount} Vulnerabilities 
</td>
<td>
${resultsSCACount} Vulnerabilities 
</td>
<td>
${resultsCargoCount} Vulnerabilities 
</td>
<td>
${resultsIceCount} Vulnerabilities 
</td>  
<td>
${resultsMashupCount} Vulnerabilities 
</td> 
</tr>

<tr>
<td>
<img  src='${resources.highIcon}'/>${sastResultsBySeverity.HIGH} High 
</td>
<td>
<img  src='${resources.highIcon}'/>${scaHResults} High 
</td>
<td>
<img  src='${resources.highIcon}'/>${cargoHResults} High </br>
</td>
<td>
<img  src='${resources.highIcon}'/>${iceHResults} High </br>
</td>  
<td>
<img  src='${resources.highIcon}'/>${mashupHResults} High </br>
</td>  
</tr>

<tr>
<td>
<img  src='${resources.mediumIcon}'/>${sastResultsBySeverity.MEDIUM} Medium 
</td>
<td>
<img  src='${resources.mediumIcon}'/>${scaMResults} Medium 
</td>
<td>
<img  src='${resources.mediumIcon}'/>${cargoMResults} Medium </br>
</td>
<td>
<img  src='${resources.mediumIcon}'/>${iceMResults} Medium </br>
</td>  
<td>
<img  src='${resources.mediumIcon}'/>${mashupMResults} Medium </br>
</td>  
</tr>

<tr>
<td>
<img  src='${resources.lowIcon}'/>${sastResultsBySeverity.LOW} Low 
</td>
<td>
<img  src='${resources.lowIcon}'/>${scaLResults} Low 
</td>
<td>
<img  src='${resources.lowIcon}'/>${cargoLResults} Low </br>
</td>
<td>
<img  src='${resources.lowIcon}'/>${iceLResults} Low </br>
</td>
<td>
<img  src='${resources.lowIcon}'/>${mashupLResults} Low </br>
</td>   
</tr>

<tr>
<td>
<img  src='${resources.infoIcon}'/>${sastResultsBySeverity.INFO} Info 
</td>
<td>
<img  src='${resources.infoIcon}'/>0 Info 
</td>
<td>
<img  src='${resources.infoIcon}'/>0 Info </br>
</td>
<td>
<img  src='${resources.infoIcon}'/>0 Info </br>
</td> 
<td>
<img  src='${resources.infoIcon}'/>0 Info </br>
</td> 
</tr>

</table>


[<img align='left' src='${resources.linkIcon}'/>View more details on Checkmarx AST](${resultsURI})`;
   


    const annotations = results.map(r => {
        const startNode = r.nodes[0];
        return {
            path: startNode.fileName.substring(1),
            start_line: startNode.methodLine,
            end_line: startNode.line,
            annotation_level: r.severity === 'INFO' ?  'notice' : 'warning',
            title: r.queryName,
            message: `${r.severity} & ${r.status} (source node)`,
        }
    });

    const octokit  = github.getOctokit(inputs.githubRepoToken);
    try {
        await octokit.checks.create({
            ...context.repo,
            name: 'Checkmarx scan results',
            head_sha: context.githubCommitHash,
            status: 'in_progress',
            started_at: startDate,
            completed_at: new Date().toISOString(),
            conclusion: succeed ? 'success' : 'failure',
            output: {
                title,
                summary,
                text,
                // text: 'Roses are Red, <br> Violets are Blue <br><br> Sql Injection on line 32.<br><br> :heart: :rose:',
                annotations,
            },
            actions: []
        });
    } catch (e) {
        throw wrapError(e, 'Failed to report scan results');
    }

    if (!succeed) {
        throw new Error(`Found ${violations} Policy Violations`);
    }
}

createScan()
    .then(writeScanReport)
    .then(() => process.exit(core.ExitCode.Success))
    .catch(exitWithError);
