# Release Checklist

Use this checklist before tagging or publishing a release of `d3nengineer/stream-encryption-psr7`.

## Package Metadata

- Confirm `composer.json` package metadata is still accurate:
  - package name: `d3nengineer/stream-encryption-psr7`
  - description and keywords match the current stream-decorator package surface
  - license remains `MIT`
  - PHP requirement remains compatible with the codebase and test suite
- Run `composer validate --strict`.

## Local Verification

- Run `composer check`.
- If any PHP files outside `src/` or `tests/` are added later and should be linted in release gates, update `composer lint` and `.github/workflows/ci.yml` together.

## Documentation Consistency

- Confirm [README.md](../README.md) still matches the public API and keeps `StreamFactory` as the recommended entry point.
- Confirm [docs/usage.md](./usage.md) still matches actual payload semantics, lifecycle ownership, and exception boundaries.
- Confirm local verification commands documented in README still match `composer.json` scripts and CI steps.

## CI State

- Ensure the GitHub Actions workflow at `.github/workflows/ci.yml` is green for the supported PHP matrix.
- Confirm CI is still limited to metadata validation, PHP syntax linting, and PHPUnit unless the package intentionally adopts stronger gates.

## Versioning And Release Notes

- Choose the next version tag according to the changes included in the release.
- Prepare concise release notes or changelog entries if you publish them for this repository.
- Verify the release notes do not promise automation or support guarantees that the repository does not implement.

## Packagist Publication

- Ensure the target commit is pushed to the default remote before publishing.
- Create and push the release tag.
- If Packagist auto-update is configured, confirm it has ingested the new tag.
- If Packagist auto-update is not configured, trigger a manual package update in Packagist after pushing the tag.
