# adjust-cvss

Takes a SARIF file and a list of query id patterns as input and assigns custom [cvss scores](https://github.blog/changelog/2021-07-19-codeql-code-scanning-new-severity-levels-for-security-alerts/) (aka `security-severity`) to those queries. This allows to make specific queries less or more severe, which affects how they are displayed (`Low`, `High`, `Critical`, ...) and whether they cause pull request checks to fail.

# Example

The following example sets the cvss score of all queries to `1.2` except for the query with the id `java/xss`. Note that this only affects queries with a `security-severity` metadata field. Therefore, most code quality related queries are not affected:

```yaml
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v4
      with:
        languages: ${{ matrix.language }}
        build-mode: ${{ matrix.build-mode }}

    - name: Run manual build steps
      if: matrix.build-mode == 'manual'
      shell: bash
      run: |
        echo 'If you are using a "manual" build mode for one or more of the' \
          'languages you are analyzing, replace this with the commands to build' \
          'your code, for example:'
        echo '  make bootstrap'
        echo '  make release'
        exit 1

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v4
      with:
        output: sarif-results
        upload: failure-only

    - name: adjust-cvss
      uses: advanced-security/adjust-cvss@v0.0.1
      with:
        patterns: |
          **:1.2
          java/xss:9.9
        input: sarif-results/${{ matrix.language }}.sarif
        output: sarif-results/${{ matrix.language }}.sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: sarif-results/${{ matrix.language }}.sarif
```

Note how we provided `upload: failure-only` and `output: sarif-results` to the `analyze` action. That way we can filter the SARIF with the `adjust-cvss` action before uploading it via `upload-sarif`.

# Patterns

Each pattern line is of the form:
```
<id pattern>:<score pattern>
```

for example:
```
**:1.2                           # all queries shall have a cvss of `1.2`.
java/xss:9.9                     # the Java XSS query should have a score of `9.9`
java/**:5.4                      # all Java queries have a score of `5.4`
```
