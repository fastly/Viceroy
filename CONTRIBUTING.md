# Contributing to Viceroy

First off thank you for wanting to contribute to making Viceroy better! We
appreciate you taking time to improve the Compute experience for developers
everywhere. There are many ways you can contribute that include but aren't
limited to documentation, opening issues, issue triage, and code contributions.
We'll cover some of the ways you can contribute below, but if you don't see
instructions for what you want to do, open up an issue and ask us!

## Table of Contents
1. Documentation
1. Feature Requests
1. Bugs
1. Issue Triage
1. Code Contributions

## Documentation

Was something in our documentation unclear? Does something have no documentation,
but should? This is a perfect way to make an easy contribution to Viceroy. If
you're not sure what the documentation should contain, please open up an issue!
We're happy to guide you with the correct information needed or if you already
know what needs to be done, open up a PR and we'll review it for you before
merging your changes.

## Feature Requests

Do you think there's something Viceroy should have that would make the
experience better? Feature requests are a great way to let us know. Before
opening up a feature request on the issue tracker first make sure that there is
no currently open issue asking for the same thing. If there's not, open up an
issue asking for what you want and the motivation behind the change.

## Bugs

Sometimes you run into issues and the code is not working properly. If you do
run into a bug and you can't figure it out or if you do figure out the bug, open
up an issue on the issue tracker. Just make sure it's not already an issue that
has been filed yet. If you do open up an issue let us know what you expected to
happen, what actually happened, what your operating system is, as well as a case
we can use to reproduce the issue if you have one!

## Issue Triage

Sometimes issues get stale and are no longer an issue, need to be updated, or
have been fixed by a PR and were never closed. While we try to stay on top of
issues and keep the backlog groomed, we are only human and can miss out on
things. If you find that an issue can be closed,

## Code Contributions

If you want to contribute code to Viceroy thank you! A few things before you do
get started adding a change and open up a PR

1. Make sure there's a tracking issue for your code change. We don't want you to
   do a lot of work only for us to reject the PR because it's a feature change
   we won't accept for instance.
1. Before opening your PR make sure you have tests and things working locally.
   You can run `make ci` in order to run the tests we run on CI which includes
   the test suite, `clippy`, and a `cargo fmt` check

It also helps to understand how we structure Viceroy. Under `cli` is the code
related to setting up and running the Viceroy CLI tool. This includes things
like argument parsing, setting up logging, and reading in options. It's fairly
small on purpose as most of the actual logic that runs Viceroy is found under
`lib`. This contains all the logic for how Viceroy works. You'll most likely
make changes here to fix an issue or add functionality!

Thanks again for contributing to Viceroy. We really do appreciate you wanting to
help out and make it better!
