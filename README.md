# AI-SSD Personal Repository
A personal repository of vulnerable code test cases.

This repository was created as part of the AI-SSD research project by the [Department of Computer Engineering at the Faculty of Sciences and Technology](https://www.uc.pt/fctuc/dei/), [University of Coimbra](https://www.uc.pt/) (Departamento de Engenharia Informática da Faculdade de Ciências e Tecnologia da Universidade de Coimbra).

## Purpose
This repository provides a collection of test cases designed to replicate and study various security vulnerabilities in software. It is intended for research and educational purposes only.

## How to use
All test cases are located in the ***"vulnerabilities/"*** directory. Each folder is named using the following convention: **[CVE-ID]_[CWE-TYPE]**

For example: 
> CVE-2021-1234_CWE-79


Each folder typically contains:

- **README.md** — Step-by-step instructions for executing the code and reproducing the vulnerability.
  
- **Source Code (.c)** — The vulnerable code and supporting files necessary for execution.

- **Dockerfile** — Used to build a containerized environment tailored to the specific vulnerability scenario.

**⚠️ WARNING: It is strongly recommended to run all test cases inside isolated containers or virtualized environments. These examples may contain active vulnerabilities and should never be run directly on a host system.**

## Authors and Contributors
- **Author** - Tiago Almeida
