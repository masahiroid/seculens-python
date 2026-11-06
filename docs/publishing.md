# PyPI trusted publishing

SecuLens is published at https://pypi.org/project/seculens/ . The active trusted publisher uses the following GitHub configuration:

- PyPI project name: `seculens`
- GitHub owner: `masahiroid`
- GitHub repository: `seculens-python`
- Workflow filename: `publish.yml`
- Environment: `pypi`

Use https://pypi.org/manage/account/publishing/ and follow https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/ . No API token needs to be shared in chat. After configuration, run the Publish to PyPI workflow or publish a non-prerelease GitHub release. The workflow tests and audits the project, builds distribution files, validates them, and publishes through OIDC.

Verification: `pip index versions seculens`, install the published version into a fresh environment, check `seculens --version`, then scan the demonstration SBOM. The demonstration snapshot is not production vulnerability data.
