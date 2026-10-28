## Project P — AI-Assisted Privileged Access Monitoring

Project P is an identity-security monitoring prototype that combines Okta System Log events, rule-based detection, and agentic AI concepts to help identify and investigate potentially suspicious identity and access activities.

The project integrates Okta, Python, FastAPI, LangGraph, and Google Gemini to transform identity events into prioritized findings and AI-generated investigation assessments for human review.

### Objectives
- Monitor identity and authentication events from an Okta development environment.
- Detect selected security-relevant activities using rule-based monitoring.
- Prioritize findings to support security investigation.
- Use an AI-assisted workflow to generate evidence-based assessments and recommendations.
- Explore how agentic AI can support Identity and Access Management (IAM) and Privileged Access Management (PAM).

### Architecture
```
<div align=center>
Okta Development Organization
↓
Okta System Log API
↓
Okta Client
↓
Rule-Based Monitoring
↓
Detection & Prioritization
↓
FastAPI Backend
↓
LangGraph Workflow
↓
Google Gemini
↓
Investigation Assessment
↓
Human Review
</div>
```
### Key Features
```
#### 1. Okta System Log Integration
- Retrieves identity and authentication events from an Okta development organization.
- Uses the Okta System Log API as the source of monitoring data.
- Processes real event data rather than relying exclusively on hardcoded investigation examples.

#### 2. Rule-Based Security Monitoring
The monitoring engine identifies and prioritizes selected event categories, including:
- Failed authentication: Events associated with unsuccessful sign-in attempts.
- Privilege changes: Events related to changes in access privileges.
- API token creation: Events associated with API token creation.
These detections provide an initial layer of monitoring before AI-assisted investigation.

#### 3. AI-Assisted Investigation
- Uses LangGraph to structure the investigation workflow.
- Integrates Google Gemini to generate investigation assessments.
- Produces evidence-based explanations and recommendations for human review.
The AI component supports analysis; it does not independently authorize or execute privileged actions.

#### 4. REST API Endpoints
<table>
  <tr>
    <th>Endpoint</th>
    <th>Purpose</th>
  </tr>

  <tr>
    <td>GET /monitor/events</td>
    <td>Retrieve monitored event data</td>
  </tr>

  <tr>
    <td>GET /monitor/findings</td>
    <td>Retrieve detected and prioritized findings</td>
  </tr>

  <tr>
    <td>GET /monitor/investigate</td>
    <td>Initiate an AI-assisted investigation</td>
  </tr>
</table>
```

### Technology Stack
<table>
  <tr>
    <th>Category</th>
    <th>Technologies</th>
  </tr>

  <tr>
    <td>Identity & Security</td>
    <td>Okta, IAM, System Log API</td>
  </tr>

  <tr>
    <td>Backend</td>
    <td>Python, FastAPI</td>
  </tr>

  <tr>
    <td>Monitoring</td>
    <td>Rule-based event detection and prioritization</td>
  </tr>

  <tr>
    <td>Agentic AI & LLM</td>
    <td>LangGraph, Google Gemini</td>
  </tr>

  <tr>
    <td>API Interface</td>
    <td>REST APIs</td>
  </tr>
</table>

### Workflow
```
1. Collect: Retrieve identity-related events from the Okta System Log API.
2. Detect: Evaluate events against configured monitoring rules.
3. Prioritize: Organize detected findings for investigation.
4. Investigate: Pass relevant finding details through the LangGraph workflow.
5. Assess: Use Google Gemini to generate an investigation assessment and recommendations.
6. Review: Present the results for human evaluation.
```

### Scope and Limitations
Project P is a learning and prototyping project focused on identity-event monitoring and AI-assisted investigation.

- Detection is limited to the event categories and rules implemented in the monitoring engine.
- AI-generated assessments may be incomplete or inaccurate and require human validation.
- The prototype does not automatically revoke access, disable accounts, or resolve security incidents.
- It does not independently establish whether every detected identity has privileged access.
- It is not intended to replace a production SIEM (Security Information and Event Management), PAM (Privileged Access Management) platform, or incident-response process.

#### Prerequisites
```
- Python 3.11 or a compatible Python version
- An Okta development organization
- An Okta API token with the permissions required to read System Log events
- Google Gemini API key
```

#### Clone the repository
```
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_PROJECT_DIRECTORY>
```

#### Configure environment variables
Create a .env file in the project root and configure the credentials required by the application.
```
OKTA_DOMAIN=your-okta-domain
OKTA_API_TOKEN=your-okta-api-token
GEMINI_API_KEY=your-google-gemini-api-key
```

#### Run the application
```
uvicorn main:app --reload
```
