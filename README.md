# Adversarial Payload Evolver

A Python-based Reinforcement Learning system for generating and mutating payloads to evade detection systems.

## Overview

This project implements an adversarial RL agent that applies aggressive mutations to PowerShell payloads, optimizing them through feedback from detection systems (VirusTotal). The system uses Reinforcement Learning (Q-learning) to learn which mutation techniques are most effective for evasion.

## Features

- **Reinforcement Learning Agent** with Q-learning and improved state representation.
- **Configurable Hyperparameters** via `config.json`.
- **10 Mutation Techniques** (Base64, reflection, variable renaming, etc.) - See [MUTATIONS_DOCUMENTATION.md](MUTATIONS_DOCUMENTATION.md).
- **VirusTotal Integration** for real detection feedback with proper rate limiting.
- **Structured Logging** to file and console for debugging and analysis.
- **Unit Tests** for all main modules.
- **Improved Error Handling** with comprehensive exception management.
- **Modular Codebase** for easy maintenance and extension.

## Installation

```bash
git clone https://github.com/r3ds3ctor/Adversarial_GANs.git
cd Adversarial_GANs
pip install -r requirements.txt
```

## Usage

1.  **Configure:**
    -   Rename `config.json.example` to `config.json`.
    -   Open `config.json` and paste your VirusTotal API key.
    -   You can also adjust the agent's hyperparameters and evolution parameters in this file.

2.  **Prepare Payloads:**
    -   Add your initial PowerShell payloads to `payloads.txt` (one per line).

3.  **Run the Evolution:**
    ```bash
    python main.py
    ```
    The generated payloads will be saved in the `fixed_mutations_output/` directory.

## Project Structure

```
├── main.py                       # Main script to run the evolution
├── agent.py                      # RL Agent implementation with improved state representation
├── mutations.py                  # Payload mutation functions (10 techniques)
├── virustotal.py                 # VirusTotal API interaction with error handling
├── config.json                   # Configuration file (API key, hyperparameters)
├── payloads.txt                  # Input payloads file
├── q_table.json                  # Learned Q-table (persisted state)
├── test_mutations.py             # Unit tests for mutations module
├── test_agent.py                 # Unit tests for agent module
├── test_virustotal.py            # Unit tests for VirusTotal module
├── MUTATIONS_DOCUMENTATION.md    # Detailed documentation of mutation techniques
├── fixed_mutations_output/       # Generated payload variants (ignored by git)
├── evolution_*.log               # Log files (one per execution)
└── README.md
```

## Testing

Run unit tests to verify functionality:

```bash
python -m pytest test_mutations.py test_agent.py test_virustotal.py -v
```

Or run individual test files:

```bash
python test_mutations.py
python test_agent.py
python test_virustotal.py
```

## Logging

The system generates detailed logs in `evolution_YYYYMMDD_HHMMSS.log` files. Logs include:
- Payload processing progress
- Mutation application results
- VirusTotal API interactions
- Q-learning updates
- Error messages and stack traces

## Recent Improvements

- ✅ Fixed validation bug in mutation application
- ✅ Increased rate limiting to 18 seconds (VirusTotal free tier compliance)
- ✅ Added structured logging to all modules
- ✅ Improved state representation with payload features
- ✅ Added comprehensive unit tests
- ✅ Enhanced error handling throughout
- ✅ Removed unused dependencies
- ✅ Added detailed mutation technique documentation


