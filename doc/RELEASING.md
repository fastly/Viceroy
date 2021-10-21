# Releasing Viceroy

Below are the steps needed to do a Viceroy release:

1. Make sure the Viceroy version has been bumped up to the current release
   version. You might need to bump the minor version (e.g. 0.2.0 to 0.3.0) if
   there are any semver breaking changes. Review the changes since the last
   release just to be sure.
1. Update the `Cargo.lock` files by running `cargo update --workspace` in the
   root directory and by going into the `test-fixtures` and
   `cli/tests/trap-test` folders and running the same command there.
1. Update `CHANGELOG.md` so that it contains all of the updates since the
   previous version as its own commit.
1. Push a branch in the form `release-x.y.z` where `x`, `y`, and `z` are the
   major, minor, and patch versions of Viceroy and have the tip of the branch
   contain the Changelog commit.
1. Run `make ci` locally to make sure that everything will pass before pushing
   the branch and opening up a PR.
1. Publish each crate in the workspace. Note that we must do this in order of
   dependencies. So,
  1. `cd lib && cargo publish`
  1. `cd cli && cargo publish`
1. When you get approval run `git tag vx.y.z HEAD && git push origin --tags` on
   the branch where `x`, `y`, and `z` again correspond to the Viceroy version
   to kick off the build for all of the artifacts.
1. When that is good and completes, push a commit to the branch that bumps
   Viceroy to the next patch version (so `z + 1`) and updates all the lockfiles
   again.
1. Get approval again and merge when CI passes.
