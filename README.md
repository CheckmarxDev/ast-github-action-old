# ast-github-action

Find security vulnerabilities in your GitHub repository with Checkmarx AST GitHub Action.

![](./resources/logo.svg)

In order to use this action in your repository just add the following into your workflow yaml file located in `.github/workflows/<file-name>.yaml`.
(For details about github workflows visit [here](https://docs.github.com/en/actions/configuring-and-managing-workflows/configuring-a-workflow))

```yml
name: Example workflow using Checkmarx AST
# Currently the events supported are: pull request and  push
on:  
  pull_request:
    branches:
      - master
jobs:
  checkmarx:
    runs-on: ubuntu-latest
    name: Checkmarx scan run
    steps:
    - name: Run scan
      uses: CheckmarxDev/ast-github-action@master
      with:
        github_repo_token: ${{ secrets.GITHUB_TOKEN }} # required
        ast_uri: ${{ secrets.AST_URI }} # required
        ast_access_key_id: ${{ secrets.AST_ACCESS_KEY_ID }} # required
        ast_access_key_secret: ${{ secrets.AST_ACCESS_KEY_SECRET }} # required
        action_scan_complete_timeout_secs: 200 # Optional, default to 200 - Set the timeout for waiting to the scan to complete 
```

The action output is `results` that contains the scan results in json format
