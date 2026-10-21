# Security policy

## Supported reporting

Please do not file suspected vulnerabilities with exploit details in public issues. Contact the repository maintainers privately through the security reporting feature on the hosting platform, if enabled. Include the affected version, impact, and a minimal reproduction. This initial project has no guaranteed response SLA until maintainers publish one.

## Scope and safe use

ConduitGuard validates user-supplied data in an offline generic model. It does not connect to or change a network device. Do not use findings as a substitute for vendor-specific review, security testing, or change approval. Avoid sharing production configurations that contain sensitive topology or addresses.

## Maintainer checks

CI runs Python dependency vulnerability checks (`pip-audit`), npm's audit, and GitHub dependency review for pull requests. Review alerts and update pinned dependencies promptly. These checks do not guarantee that all vulnerabilities are detected.

The locked frontend toolchain currently includes `braces@3.0.3` transitively through the development-only `eslint-config-next` tree. GitHub tracks [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) as high severity and currently lists no patched version. The advisory is explicitly allow-listed so scans continue to fail on other high findings; the affected package is not part of the production runtime dependency tree. Revisit and remove this exception once upstream publishes a patched release.
