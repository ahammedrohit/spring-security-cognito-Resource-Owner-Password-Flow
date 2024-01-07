
# Spring Boot Application with AWS Cognito Authentication

## Overview

This Spring Boot application (version 3.2.1) demonstrates a secure authentication flow using AWS Cognito. It involves the following steps:

## User Login:
* User enters username and password in the frontend.
* Frontend sends credentials to the backend.
* Backend Authentication with AWS Cognito:
**  Backend communicates with AWS Cognito to authenticate the user.
* If successful, Cognito returns authentication tokens (access and refresh tokens).
## Token Return:
* Backend sends the tokens back to the frontend.
# Token Storage (Frontend):
* Frontend securely stores the tokens (e.g., in local storage or cookies).
##  Subsequent Requests:
* For subsequent protected API calls, the frontend includes the access token in the Authorization header.
##  Backend Token Verification:
* Backend verifies the access token using JWKS (JSON Web Key Set) from AWS Cognito.
* If valid, the request is processed.
* If invalid, an appropriate error response is sent.

  
## Key Features:
* AWS Cognito Integration: Leverages AWS Cognito for user authentication and token management.
* Spring Security: Employs Spring Security to protect API endpoints and handle token verification.
* JWKS: Uses JWKS to validate access tokens from AWS Cognito.
* Clear Authentication Flow: Implements a well-defined authentication flow for a seamless user experience.
