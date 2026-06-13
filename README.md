<img src="https://cdn.prod.website-files.com/677c400686e724409a5a7409/6790ad949cf622dc8dcd9fe4_nextwork-logo-leather.svg" alt="NextWork" width="300" />

# Build a Custom REST API Fuzzer

**Project Link:** [View Project](https://learn.nextwork.org/projects/d3052eb1-8911-43bd-89bb-e81d9fed3a34)

**Author:** goodluck Oyebisi  
**Email:** goodluckoyebisi5@gmail.com

---

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/d3052eb1-8911-43bd-89bb-e81d9fed3a34_u2huvdvm)

## Building a Custom API Fuzzer from Scratch

### Project goals and motivation

I'm building an api fuzzer that will be able to discovers security vulnerabilities by bombarding endpoints with malicious inputs and classifying the resultsso I can learn how api security 

### Core dependencies and their roles

I installed all three packages needed : Flask, requests, PyYAML  which is used for : Flask  is a lightweight web framework. You will use it to build the deliberately vulnerable target API
Requests is a popular HTTP library. The fuzzer uses it to fire mutated requests at the target.
PyYAML parses YAML files. You will use it to read the OpenAPI specification that describes the target API's endpoints.

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/d3052eb1-8911-43bd-89bb-e81d9fed3a34_e1cxjkav)

## Designing a Deliberately Vulnerable Target API

### Purpose of the vulnerable API

In this step, I'm building a deliberately vulnerable Flask REST API with four endpoints, each containing a different planted security flaw. so that the fuzzer can discover the vulnerable Flask REST API endpoints


### Four planted vulnerabilities across four endpoints

The four vulnerabilities are GET /users/<user_id> (Crash on Bad Input Types) has POST /users (Missing Input Validation) has POST /search (Simulated SQL Injection) has GET /admin (Broken Access Control)

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/d3052eb1-8911-43bd-89bb-e81d9fed3a34_qi8258kr)

## Parsing OpenAPI Specs and Generating Mutation Payloads

### Spec parsing and mutation engine design

In this step, I'm building spec parser so that the fuzzer can check the endpoints

### Evaluating mutation strategy effectiveness

Strategy 1 (boundary/injection field mutation) will catch the most bugs because it directly targets SQL injection, XSS, and buffer overflow vulnerabilities field-by-field — which are the most prevalent and impactful flaws in APIs that accept user-controlled string inputs like /users, /search, and /admin.

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/d3052eb1-8911-43bd-89bb-e81d9fed3a34_plapv13n)

## Firing Requests and Classifying Vulnerabilities

### Request sender and response classifier architecture

In this step, I'm building a fuzzer that sends requests without understanding the responses is just a load tester.

### Severity categories and what they reveal

My fuzzer found only CRASH (server returned 500 instead of a graceful 400), meaning the API has zero input validation on path parameters — and with a 37% crash rate across 119 requests, that alone is a critical finding.

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/d3052eb1-8911-43bd-89bb-e81d9fed3a34_650twwgx)

## Detecting Authentication Bypass Vulnerabilities

### How the auth bypass classifier works

In this project extension, my classify_auth_bypass method checks and sends a request to a security-protected endpoint (like /admin) without any authorization token and flags broken access control if the server returns 200 OK instead of 401 Unauthorized or 403 Forbidden.

## Reflections and Key Takeaways

### Tools and concepts mastered

OpenAPI spec parsing, mutation-based fuzzing strategies (boundary values, type confusion, injection payloads, missing fields), HTTP response analysis for crash/auth-bypass detection, and the critical importance of input validation and proper error handling in API security.

### Time investment and challenges

This project took me approximately 40 min

### Looking ahead

I did this project today to learn how to automate api endpoint security check

---

*Built with [NextWork](https://learn.nextwork.org) - [View this project](https://learn.nextwork.org/projects/d3052eb1-8911-43bd-89bb-e81d9fed3a34)*
