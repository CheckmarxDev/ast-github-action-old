const { init } = require('../src/ast');

const ast = init({
    astUri: '',
    astAuthenticationUri: '',
    astAccessKeyId: '',
    astAccessKeySecret: '',
    scaUser: '',
    scaPassword: '',
    astScansURI: '',
    astResultsURI: '',
    astScanSummaryURI: '',
    githubRepoToken: '',
    githubRepo: '',
    githubRepoUrl: '',
    githubBranch: '',
});

ast.getResultsByScanID('')
    .then(results => console.log(JSON.stringify(results, null, 2)));
