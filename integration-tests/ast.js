const { init } = require('../src/ast');

const ast = init({
    astUri: '',
    astAuthenticationUri: '',
    astAccessKeyId: '',
    astAccessKeySecret: '',
    astScansURI: '',
    astResultsURI: '',
    githubRepoToken: '',
    githubRepo: '',
    githubRepoUrl: '',
    githubBranch: '',
});

ast.getResultsByScanID('')
    .then(results => console.log(JSON.stringify(results, null, 2)));
