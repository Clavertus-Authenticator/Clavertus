<div align="center">
    <a href="https://gitlab.ti.bfh.ch/bathesis-2024/clavertus">
        <img height="130px" src="./assets/logo.png" />
    </a>
    <h1 align="center">
        Clavertus
    </h1>
</div>

Clavertus is an open-source FIDO authenticator for Android that implements the Client to Authenticator Protocol (CTAP). 
It aims to provide a secure and straightforward authentication experience. 
Clavertus is particularly suited for individuals who prioritize privacy and want to maintain control over their data.

## APK

Get the latest version from the [Package Registry](https://gitlab.ti.bfh.ch/bathesis-2024/clavertus/-/packages/1799).

## Requirements

- Java 17
- Android API 31 or higher
- Detekt CLI

### Git Hooks

This project uses `pre-commit` to run formatting and linting checks before every commit. 
See here for installation instructions: [https://pre-commit.com/#install](https://pre-commit.com/#install). 
After installing `pre-commit`, run `pre-commit install` to install the hooks.

### Recommended Plugins

If you are using Android Studio, you can also install the `detekt` plugin to run the linter checks in the IDE.
You can also run the detekt checks from the command line using the detekt CLI: `gradle detektMain` and `gradle detektTest`.

## Name

Clavis + Apertus = Clavertus

- **Clavis**: Latin noun meaning "key," used both literally and figuratively to represent something that unlocks or opens.
- **Apertus**: The past participle of "aperire," meaning "to open." Used to describe something that is opened, from physical spaces to metaphorical ideas.