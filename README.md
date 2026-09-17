<div align="center">

# Protegrity AI Developer Edition
[![Version](https://img.shields.io/badge/version-1.2.0-green.svg?style=flat)](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition/blob/main/LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg?style=flat)](https://www.python.org/downloads/)
[![Java 11+](https://img.shields.io/badge/java-11+-blue.svg?style=flat)](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://www.linux.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![macOS](https://img.shields.io/badge/mac%20os-000000?style=flat&logo=macos&logoColor=F0F0F0)](https://www.apple.com/macos/)
[![PyPI 1.2.2](https://img.shields.io/pypi/v/protegrity-ai-developer-python.svg)](https://pypi.org/project/protegrity-ai-developer-python/)
[![Maven Central 1.1.0](https://img.shields.io/maven-central/v/com.protegrity/protegrity-ai-developer-edition.svg?style=flat)](https://search.maven.org/artifact/com.protegrity/protegrity-ai-developer-edition)
[![Service Health](https://img.shields.io/badge/service-health-brightgreen.svg?style=flat&logo=statuspage&logoColor=white)](https://www.protegrity.com/developers/status)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition)
</div>

Welcome to the `protegrity-ai-developer-edition` repository, part of the Protegrity AI Developer Edition suite. This repository provides a self-contained experimentation platform for discovering and protecting sensitive data using Protegrity’s Data Discovery, Semantic Guardrail, Anonymization, Synthetic Data, and Protection APIs. Use the online [Protegrity notebook](https://mybinder.org/v2/gh/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition/main?filepath=data-protection/samples/python/sample-app-protect-unprotect/getting-started-protection.ipynb) to quickly test tokenization. Use the packaged notebooks to test the Protegrity AI Developer Edition features.

## 🚀 Overview

This repository enables developers to:
- Rapidly set up a local environment using Docker Compose.
- Experiment with unstructured text classification, PII discovery, redaction, masking, and tokenization-like protection.
- Experiment with Anonymization to discover and redact sensitive data in datasets for use in training GenAI models or sharing with third parties.
- Experiment with Synthetic Data generation that mimics the properties of real data such as data types, ranges, correlations, and distributions without containing any actual personal information.
- Experiment with Semantic Guardrails to secure GenAI applications using messaging risk scoring, conversation risk scoring, and PII scanning.
- Integrate Protegrity APIs into GenAI and traditional applications.
- Use sample applications and data to understand integration workflows.

**Why This Matters**

AI is transforming every industry, but privacy can’t be an afterthought. Protegrity AI Developer Edition 1.2.0 makes enterprise-grade data discovery and data protection developer-friendly, so you can build secure, privacy-first solutions for both AI pipelines and traditional data workflows. Whether you’re protecting sensitive information in analytics pipelines, business applications, or next-generation AI, Protegrity AI Developer Edition empowers you to innovate confidently while keeping data safe.

Protegrity AI Developer Edition enables secure data and AI pipelines, including:

- **Privacy in conversational AI:** Sensitive chatbot inputs are protected before they reach generative AI models.

- **Prompt sanitization for LLMs:** Automated PII masking reduces risk during large language model prompt engineering and inference.

- **Experimentation with Jupyter notebooks:** Data scientists can prototype directly in Jupyter notebooks for agile experimentation.

- **Output redaction and leakage prevention:** Detect and protect sensitive data in model outputs before returning them to end users.

- **Privacy-enhanced AI training:** Sensitive fields in training datasets are de-identified to support compliant and secure AI development.

- **Synthetic data generation for privacy-preserving AI:** Automatically create realistic, anonymized datasets that mimic production data without exposing sensitive information, enabling safe model training and testing.

### Quick Links

- [Prerequisites](#prerequisites)
- [Preparing the system](#preparing-the-system)
- [Additional prerequisites for MacOS](#additional-prerequisites-for-macos)
- If your setup is ready, [run the samples](#running-the-sample-applications) to experience Protegrity AI Developer Edition.

### Repositories

Protegrity AI Developer Edition provides the files required and also the source code for customization. The following repositories are available:

-   [protegrity-ai-developer-edition](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition): This is the main repository with the files and samples required for experiencing Protegrity AI Developer Edition.
-   [protegrity-ai-developer-python](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-python): This is the repository with the source code for the Python module. Use the files in this repository only to customize and use the Python module.
-   [protegrity-ai-developer-java](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-java): This is the repository with the source code for the Java library. Use the files in this repository only to customize and use the Java library.


## 📦 Repository Structure

```text
.
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── binder/                              # Jupyter Binder configuration (repo2docker)
├── data-discovery/                      # Feature: classify and discover sensitive data
│   ├── sample-classification-bash-text.sh
│   ├── sample-classification-bash-tabular.sh
│   ├── sample-classification-python-text.py
│   ├── sample-classification-python-tabular.py
│   └── input.csv
├── data-protection/                     # Feature: protect and unprotect data (tokenization / encryption)
│   ├── samples/
│   │   ├── python/
│   │   │   ├── sample-app-protect-unprotect/   # Jupyter notebook for protect/unprotect demo
│   │   │   └── sample-app-protection.py        # CLI protect / unprotect script
│   │   └── java/                               # Full Maven project with .sh/.bat wrappers
│   │       └── sample-app-protection.sh
│   └── README.md
├── semantic-guardrail/                  # Feature: LLM prompt / response guardrails
│   ├── samples/
│   │   ├── python/
│   │   │   ├── sample-guardrail-python.py
│   │   │   └── sample-app-semantic-guardrails/  # Jupyter notebook
│   │   └── bash/
│   │       └── sample-guardrail-command.sh
│   ├── data/
│   ├── docker-compose.yml               # Scoped to classification + guardrail services
│   └── README.md
├── synthetic-data/                      # Feature: generate privacy-safe synthetic datasets
│   ├── samples/python/
│   │   └── sample-app-synthetic-data/          # Jupyter notebook
│   ├── data/
│   ├── docker-compose.yml               # Scoped to synthetic-data services
│   └── README.md
├── anonymization/                       # Feature: anonymize sensitive fields
│   ├── samples/python/
│   ├── data/
│   └── README.md
├── shared/                              # Cross-feature shared assets
│   ├── config.json                      # Shared API / service configuration
│   ├── requirements.txt                 # Python dependencies for notebook samples
│   └── data/
│       └── input.txt                    # Generic reference input
├── solutions/                           # End-to-end multi-feature solutions
│   ├── find-and-protect/                # Discovery + protection flow (Python & Java)
│   │   ├── sample-app-find-and-protect.py
│   │   └── sample-app-find-and-unprotect.py
│   ├── find-and-redact/                 # Discovery + redaction flow (Python & Java)
│   │   ├── sample-app-find-and-redact.py
│   │   └── sample-app-find.py
│   └── README.md
└── community-solutions/                 # Community-contributed solutions
    ├── Orchestrators-BankingPortalChatbot/
    ├── ai-chat/
    ├── protegrity-composio-integration/
    └── README.md
```

## 🧰 Features

AI Developer Edition is purpose-built for fast, frictionless exploration of Protegrity's core capabilities. The following features make it ideal for prototyping and integration:

### Platform Capabilities

- **Modular, Containerized Architecture**: Runs on Docker, making it easy to test, isolate, and iterate. Start only the services you need and use the sample applications without orchestration overhead.
- **Cross-platform**: Works on Linux, MacOS, and Windows.
- **Python Module**: An open-source Python module available through PyPI, providing APIs to protect, unprotect, and reprotect sensitive data in Python-based applications.
- **Java Library**: An open-source Java library distributed through Maven Central, providing APIs to protect, unprotect, and reprotect sensitive data in Java-based applications.
- **AI Developer Edition API Service**: A Protegrity-hosted service for interacting with protection and discovery endpoints without deploying infrastructure. This service enables rapid prototyping and requires free registration.
- **Sample Apps and Data**: Ready-to-run examples demonstrate real-world use cases, including finding sensitive data in unstructured text, finding and redacting, finding and protecting or unprotecting sensitive data, multi-turn conversations, and agent coordination patterns. Adjust behavior through `shared/config.json`.
- **Composable Docker Install**: Each feature ships its own `docker-compose.yml`, only the services required.
- **Debug UI**: Built-in debug interface for inspecting classification results, protection operations, and guardrail evaluations during development.
- **Seamless Dev-to-Team Edition Transition**: Port from Protegrity AI Developer Edition to Protegrity AI Team Edition with zero code changes. The bundled `pty-migrate` CLI checks readiness and provisions your PPC policy automatically.

### Core Data Protection Services

- **Data Discovery and Anonymization**: Identifies and classifies sensitive data using built-in and custom classifiers with confidence scoring. Discovers and redacts sensitive data in datasets for use in training GenAI models or sharing with third parties.
- **Redaction / Masking**: Replaces detected entities using configurable masking characters and entity mappings.
- **Data Protection (Tokenization-like)**: Protects and unprotects specific data elements using `sample-app-protection.py` and the combined find-and-protect sample.
- **Synthetic Data**: Analyzes a dataset and generates data that mimics the properties of real data, such as data types, ranges, correlations, and distributions, without containing any actual personal information. Enables safe model training and end-to-end agent workflow testing.
- **Semantic Guardrails**: A security guardrail engine for AI systems. Evaluates risks in GenAI systems such as chatbots, workflows, and agents through advanced semantic analytics and intent classification to detect potentially malicious messages. Provides message and conversation level risk scoring and PII scanning to prevent context poisoning and enforce governance in multi-agent systems.
- **Multi-turn Examples**: Use the curl and Python samples from the semantic guardrail directory.

> **Note**: This product is continuously improving. The features and capabilities mentioned here are either already available or will be available shortly.

For more details about key features, refer to the [Protegrity AI Developer Edition documentation](https://developer.docs.protegrity.com/docs/about_dev/).

### Feature version

The version number of the AI Developer Edition features are provided here for reference.
 
-   Data Discovery: 2.0.0
-   Semantic Guardrails: 1.1.1
-   Synthetic Data: 2.0.0
-   Anonymization: 2.0.0
-   Python SDK: 1.2.2
-   Java SDK: 1.1.0

## 🛠️ Getting Started

### Prerequisites

If the AI Developer Edition is already installed, then complete the following tasks:
- Back up any customized files.
- Stop any AI Developer Edition containers that are running using the `docker compose down --remove-orphans` command.
- Remove the `protegrity-ai-developer-python` module using the `pip uninstall protegrity-ai-developer-python` command.

Common for all components:
- [Git](https://git-scm.com/downloads)
- Container management software:
    - For Linux/Windows: [Docker](https://docs.docker.com/reference/cli/docker/)
    - For MacOS: [Docker Desktop](https://docs.docker.com/reference/cli/docker/) or Colima
- [Docker Compose > 2.30](https://docs.docker.com/compose/install/)

AI Pack for Data Discovery, Semantic Guardrail, Anonymization, and Synthetic Data:
- [Python >= 3.11](https://www.python.org/downloads/)
    > **Note**: Ensure that the python command on your system points to a supported python3 version, for example, Python 3.11 or later. You can verify this by running `python --version`.
- [pip](https://pip.pypa.io/en/stable/installation/)
- [Python Virtual Environment](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)

Data Protection for Python:
- [Python >= 3.11](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [Python Virtual Environment](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)

Data Protection for Java:
- [Java 11 or later](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
- [Maven 3.6+](https://maven.apache.org/download.cgi) or use the included Maven wrapper

For more information about the minimum requirements, refer to [Prerequisites](https://developer.docs.protegrity.com/docs/install/deved_prereq/).

### Preparing the system

Complete the steps provided here to use the samples provided with AI Developer Edition.

>   For MacOS, ensure that the [Additional prerequisites for MacOS](#additional-prerequisites-for-macos) steps are complete.

1.  Open a command prompt.
2.  Clone the git repository.
    ```
    git clone https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition.git
    ```
3.  Navigate to the `protegrity-ai-developer-edition` directory in the cloned location.

4.  Start the required services and obtain the necessary credentials.

    **AI Pack components where no API registration is required:**

    Start only the services you need. Each feature directory contains its own `docker-compose.yml`. Selectively spin up components without running the full stack. The dependent containers are large; downloads may take time. These components run locally using Docker containers. No API key or account registration is needed.

    - To start the Data Discovery services:
    ```
    cd data-discovery && docker compose up -d && cd ..
    ```
    - To start the Semantic Guardrail services (includes classification/data-discovery dependencies):
    ```
    cd semantic-guardrail && docker compose up -d && cd ..
    ```
    - To start the Synthetic Data services:
    ```
    cd synthetic-data && docker compose up -d && cd ..
    ```
    - To start the Anonymization services:
    ```
    cd anonymization && docker compose up -d && cd ..
    ```
    - Install Jupyter Lab to run the notebook samples provided.
    > **Note**: It is recommended to install and activate the Python virtual environment.
    ```
    pip install -r shared/requirements.txt
    ```

    **Data Protection components where API registration is required:**

    These components use the Protegrity-hosted API Service for tokenization, encryption, and protect/unprotect operations. You must register and obtain API credentials before running Data Protection samples.

    1. Install the `protegrity-ai-developer-python` module.
        > **Note**: It is recommended to install and activate the Python virtual environment before installing the module.
        ```
        pip install protegrity-ai-developer-python
        ```
        The installation completes and the success message is displayed. Alternatively, to build the module from source, refer to [Building the Python module from source](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-python?tab=readme-ov-file#build-the-protegrity-ai-developer-python-module).
    2. For Java samples, the `protegrity-ai-developer-java` module is automatically downloaded from Maven Central when you run a sample for the first time.
        Alternatively, to build the java library from source, refer to [Building the Java module from source](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-java?tab=readme-ov-file#build-the-protegrity-ai-developer-java-modules).

### Running the Sample Applications

The samples are organized into two categories:
- **AI Pack Samples with No API Registration Required**: Discover PII, Find and Redact, Data Discovery on Tabular Data, Semantic Guardrail, Anonymization, and Synthetic Data. These run locally against the AI Pack Docker containers.
    - [Data Discovery samples](https://developer.docs.protegrity.com/docs/prod_features/data_discovery/dd_using/)
    - [Semantic Guardrails samples](https://developer.docs.protegrity.com/docs/prod_features/sem_guard/sgr_using/)
    - [Synthetic Data samples](https://developer.docs.protegrity.com/docs/prod_features/synth_data/sd_using/)
    - [Anonymization samples](https://developer.docs.protegrity.com/docs/prod_features/anon/anon_using/)
- **Data Protection Samples with API Registration Required**: Find and Protect, Direct Protect or Unprotect from the CLI. These use the Protegrity-hosted API Service for tokenization, encryption, and protect/unprotect operations. Registration is also required for the online Jupyter notebook.
    - [Data Protection samples](https://developer.docs.protegrity.com/docs/prod_features/data_prot/prot_using/)

## AI Developer Edition in Agentic AI Workflows

AI agents go beyond simple chat. They plan tasks, call tools, take actions, and coordinate with other agents. As these agents move data across systems autonomously, the risk of exposing sensitive data increases. Protegrity AI Developer Edition helps you protect data at every step of an agentic AI workflow, ensuring sensitive information stays secure even as agents operate with broad privileges.

For more information about using Protegrity AI Developer Edition in agentic AI workflows, refer to the [Protegrity AI Developer Edition documentation](https://developer.docs.protegrity.com/).

## 🚚 Moving from Developer Edition to Team Edition

Once your application works against AI Developer Edition, you can move the same code to **Protegrity AI Team Edition** - a hosted, multi-user environment backed by your own Policy Provisioning Cluster (PPC) and Cloud Protect. The exact same Python and Java sample code keeps working: only the endpoint, the authentication mode, and where the policy lives change.

For more information about moving from Protegrity AI Developer Edition to Protegrity AI Team Edition, refer to the [Promoting to AI Team Edition](https://developer.docs.protegrity.com/docs/migration/).

### Additional prerequisites for MacOS

MacOS requires additional steps for Docker and for systems with Apple Silicon chips. Complete the following steps before using AI Developer Edition.

1.  Complete one of the following options to apply the settings.
    - For Colima:
        1. Open a command prompt.
        2. Run the following command.
            ```
            colima start --vm-type vz --vz-rosetta --memory 8
            ```
    - For Docker Desktop:
        1.  Open Docker Desktop.
        2.  Go to **Settings > General**.
        3.  Enable the following check boxes:
            -   **Use Virtualization framework**
            -   **Use Rosetta for x86_64/amd64 emulation on Apple Silicon**
        4.  Click **Apply & restart**.

2.  Update one of the following options for resolving certificate related errors.
    - For Colima:
        1.  Open a command prompt.
        2.  Navigate and open the following file.

            ```
            ~/.colima/default/colima.yaml
            ```
        3.  Update the following configuration in `colima.yaml` to add the path for obtaining the required images.

            Before update:
            ```
            docker: {}
            ```

            After update:
            ```
            docker:
                insecure-registries:
                    - ghcr.io
            ```
        4. Save and close the file.
        5. Stop colima.
            ```
            colima stop
            ```
        6. Close and start the command prompt.
        7. Start colima.
            ```
            colima start --vm-type vz --vz-rosetta --memory 8
            ```
    - For Docker Desktop:
        1.  Open Docker Desktop.
        2.  Click the gear or settings icon.
        3.  Click **Docker Engine** from the sidebar. The editor with your current Docker daemon configuration `daemon.json` opens.
        4.  Locate and add the `insecure-registries` key in the root JSON object. Ensure that you add a comma after the last value in the existing configuration.

            After update:
            ```
            {
                .
                .
                <existing configuration>,
                "insecure-registries": [
                    "ghcr.io",
                    "githubusercontent.com"
                ]
            }
            ```

        5.  Click **Apply & Restart** to save the changes and restart Docker Desktop.
        6.  Verify: After Docker restarts, run `docker info` in your terminal and confirm that the required registry is listed under **Insecure Registries**.

3.  Optional: If the *The requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8) and no specific platform was requested* error is displayed.

    1.  Start a command prompt.
    2.  Navigate and open the following file.

        ```
        ~/.docker/config.json
        ```
    3. Add the following parameter.
        ```
        "default-platform": "linux/amd64"
        ```
    4. Save and close the file.
    5. Some services are profile enabled, ensure to use the `--profile` flag while starting the services.
       - Run `docker compose up -d` from any feature directory (e.g., `semantic-guardrail/`) to start that feature's services.
       - Run `docker compose up -d` from the `synthetic-data/` directory to start the synthetic data services.

## 📄 Configuration

Edit `shared/config.json` to customize SDK behavior.
Keys:
- `named_entity_map`: Optional mappings (friendly labels) used during protect/mask. [Supported Classification Entities](https://developer.docs.protegrity.com/docs/addinfo/entities/)
- `method`: `redact` (remove) or `mask` (replace with masking char).
- `masking_char`: Character for masking (when `method` = mask).
- `classification_score_threshold`: Minimum confidence (default 0.6 if omitted).
- `endpoint_url`: Override classification endpoint (defaults internally to docker compose service `http://localhost:8580/...`).
- `enable_logging`, `log_level`.

Current example:
```json
{
    "masking_char": "#",
    "named_entity_map": {
        "PERSON": "PERSON",
        "LOCATION": "LOCATION",
        "SOCIAL_SECURITY_ID": "SSN",
        "PHONE_NUMBER": "PHONE",
        "AGE": "AGE",
        "USERNAME": "USERNAME"
    },
    "method": "redact"
}
```

### Docker Compose Services
Each feature directory contains its own `docker-compose.yml`:
- **`data-discovery/docker-compose.yml`**: Classification providers + Data Discovery services.
- **`semantic-guardrail/docker-compose.yml`**: Classification providers + Data Discovery + Semantic Guardrail services.
- **`synthetic-data/docker-compose.yml`**: PostgreSQL + Synthetic Data + Dask + MinIO services.
- **`anonymization/docker-compose.yml`**: Services required for anonymization notebook samples.

Restart a feature's stack after changes:
```
cd semantic-guardrail && docker compose down && docker compose up -d && cd ..
```

Check service logs:
```
cd semantic-guardrail && docker compose logs && cd ..
```

## 📚 Documentation

- The Protegrity AI Developer Edition documentation is available at https://developer.docs.protegrity.com/.
- For more API reference and tutorials, refer to the Developer Portal at https://www.protegrity.com/developers.
- For more information about Data Discovery, refer to the [Data Discovery documentation]( https://docs.protegrity.com/data-discovery/2.0.0/docs/).
- For more information about Semantic Guardrails, refer to the [Semantic Guardrails documentation]( https://docs.protegrity.com/sem_guardrail/1.1.1/docs/).
- For more information about Synthetic Data, refer to the [Synthetic Data documentation]( https://developer.docs.protegrity.com/docs/prod_features/synth_data/).
- For more information about Anonymization, refer to the [Protegrity AI Developer Edition documentation](https://developer.docs.protegrity.com/docs/prod_features/anon/).
- For more information about Application Protector Python, refer to the [Application Protector Python documentation]( https://docs.protegrity.com/protectors/10.0/docs/ap/ap_python/).
- For more information about Application Protector Java, refer to the [Application Protector Java documentation]( https://docs.protegrity.com/protectors/10.0/docs/ap/ap_java/).


## 📢 Community & Support

- Join the discussion on https://github.com/orgs/Protegrity-AI-Developer-Edition/discussions.
- Anonymous downloads supported; registration required for participation.
- Issues / feature requests: please include sample script name & log snippet.

## 📜 License

See [LICENSE](https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition/blob/main/LICENSE) for terms and conditions.
