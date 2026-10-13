# Adding SafePush to CI

SafePush is currently a source repository, **not a published GitHub Action or npm package**. Do not copy an unverified Marketplace action that happens to use this name.

For a temporary source-based integration, check out the SafePush repository at a trusted, reviewed commit in a separate job, install its development tools, build and execute the CLI against an explicitly authorized project directory.

Before distributing this as a reusable GitHub Action, the project needs a versioned release, an installation lockfile, permissions review, and cross-platform testing. A GitHub Action cannot stop a secret from being pushed initially; retain GitHub's own secret scanning/push protection.
