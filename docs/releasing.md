# Releasing

The version is raised **right before a release**, in one release commit on
`develop`. Between releases, `Cargo.toml` keeps the last released version and
changes are collected under `## [Unreleased]` in `CHANGELOG.md`.

## Branches

| Branch | Purpose |
| --- | --- |
| `develop` | Ongoing work; every change lands here first |
| `main` | Released state only; every release tag points to a commit on `main` |

## During development

Every user-visible change adds a line to `CHANGELOG.md` under
`## [Unreleased]`, in the matching group: `Added`, `Changed`, `Deprecated`,
`Removed`, `Fixed`, `Security`.

## Making a release

1. **Pick the version** from the unreleased changes ([SemVer](https://semver.org)):
   fixes only → patch (`0.1.1`), new features → minor (`0.2.0`), incompatible
   changes → major. Before 1.0.0, incompatible changes raise the minor version.
2. **Check that CI is green** on `develop`.
3. **Release commit on `develop`:**
   - `Cargo.toml`: set `version = "X.Y.Z"`, then run `cargo build` so
     `Cargo.lock` follows.
   - `CHANGELOG.md`: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add
     a new empty `## [Unreleased]` above it, and update the links at the end:
     ```text
     [Unreleased]: https://github.com/elkman/x509pretty/compare/vX.Y.Z...develop
     [X.Y.Z]: https://github.com/elkman/x509pretty/compare/vA.B.C...vX.Y.Z
     ```
     For the first release use `.../releases/tag/v0.1.0` as the `[0.1.0]` link.
   ```sh
   git commit -am "Release X.Y.Z"
   git push origin develop
   ```
4. **Bring `main` up to date** once CI is green for the release commit:
   ```sh
   git checkout main
   git merge --ff-only develop
   git push origin main
   git checkout develop
   ```
   A pull request from `develop` to `main` works as well.
5. **Tag and push:**
   ```sh
   git tag -a vX.Y.Z main -m "x509pretty X.Y.Z"
   git push origin vX.Y.Z
   ```

## What the release workflow does

`.github/workflows/release.yml` starts on every pushed tag `v*`:

1. **Check:** stops unless the tag equals `v` + the version in `Cargo.toml`
   and `CHANGELOG.md` has a section `## [X.Y.Z]`.
2. **Build:** binaries for Linux (static, musl), macOS and Windows, each for
   x86_64 and arm64, packed as `.tar.gz`/`.zip` with a `.sha256` file each.
3. **Publish:** a GitHub release named after the tag; its text is the
   `CHANGELOG.md` section of that version.

## If something fails

Fix the cause on `develop`, then move the tag to the fixed commit:

```sh
git push --delete origin vX.Y.Z
git tag -d vX.Y.Z
# commit the fix, bring main up to date (step 4), then tag again (step 5)
```

Delete a release that was already created under *Releases* on GitHub first.
Once binaries have been downloaded, prefer a new patch version over moving a
tag.

## Notes

- The Linux arm64 build runs on the `ubuntu-24.04-arm` runner, which is free
  only for public repositories.
- The workflow needs write access to create releases. It requests
  `contents: write` itself; if it still fails with a permission error, set
  *Settings → Actions → General → Workflow permissions* to *Read and write*.
