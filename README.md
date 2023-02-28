# Code Credential Scanner

This script is intended to scan a large, diverse codebase for hard-coded credentials, or credentials present in 
configuration files. These represent a serious security issue, and can be extremely hard to detect and manage.

The specific focus of this script is to create a tool that can be used directly by dev teams in a CI/CD pipeline, to 
manage the remediation process for this issue by alerting the team when credentials are present in the code, so that 
the team can immediately fix issues as they arise. 

It is possible to apply to tool as a point-in-time scanner for this issue, but - since credentials are likely to 
work their way back into the codebase over time - we strongly advise integration of the script into the CI/CD 
process, automated build mechanism or whatever other regularly scheduled automated scanning process the team carries 
out.

The script is written with the following aims in mind:

- Be language agnostic, regular-expression based, and require no parsing, so that it works on any codebase
- Reduce false positives wherever possible, even at the (inevitable) cost of false negatives
- Provide multiple, straightforward methods for suppressing issues, compatible with other SAST tools
- Be concise, simple and performant

# Suppression comments

The script attempts to provide some compatibility with other popular SAST tools.

Text at or near the start of a file '# noqa file' will suppress reporting of any further issues in that file, as will
the text 'flake8: noqa'.

Text on an individual line of '# noqa' will suppress reporting of issues on that line.
Many other common suppression comments will also work; the current list is:

```
        # noinspection
        # noqa
        #noqa
        @SuppressWarnings
        DevSkim
        NOLINT
        NOSONAR
        checkmarx
        coverity
        fortify
        noinspection
        nosec
        safesql
        veracode
```

We also recommend the use of the comment '# noqa cred', to make it clear to team members that it is specifically the 
presence of a credential that is the reason for the false positive. Many of the tools referenced here (e.g. devskim) 
make use of specific error codes relating to tooling relevant to the language or platform in use, that serve the 
same purpose. It's possible for the same line of code to have multiple errors of different types.

We caution that it is extremely bad practice to suppress an alert from a SAST tool that is a true positive. It is 
good practice to periodically review the SAST/lint suppression comments in a codebase to ensure that no 'true 
positives' have been suppressed.

The '-nosuppress' command line flag causes the script to ignore all suppression comments. 
