# Project Architecture and Implementation Plan
## 1. Users, Teams, and Access Control

Multi-Tenancy and Roles: The system will be multi-tenant, allowing data segregation by team/organization. Each user belongs to a team, and their access is restricted to that team’s cases and data. We will implement Role-Based Access Control (RBAC), meaning user roles are scoped to their organization. For example, a user could be an Analyst in one team but have no access to another team’s data – the permissions are isolated per tenant. This avoids any cross-tenant data leakage by ensuring each organization’s environment is isolated.

Defined User Roles: We will define roles to mirror typical usage scenarios:
- Org Admin: Can manage the organization (invite users, etc.) and access all cases and files in their org.
- Case Lead: Owner/manager of one or more cases. They can see all files and results for cases they lead.
- Analyst: Can view and work on cases they are assigned to.
- Read-Only: Can view cases/data (if permitted) but cannot make changes. For external user or autidor.

These roles will be implemented in the IdProvider (Keycloak) and enforced in the application. A multi-tenant RBAC model will let us assign roles per tenant instead of globally. In our current plan, a user will likely belong to only one org.

Data Isolation: All data objects (cases, evidence, events) will carry a Tenant/Org ID attribute. The backend will always check this against the authenticated user’s org. This guarantees that even if a request is made for an object from another org, it will be denied. On the OpenSearch side, we will consider using separate indices per tenant or per case for stronger isolation. OpenSearch’s security plugin can map roles to index permissions, so we could have index naming like org1-case-* that only Org1’s roles can read. Keycloak roles will map to OpenSearch roles of the same name, as suggested by community guides.

Team Management: Initially, each user will be tied to one team (we won’t support multi-org users at first). We will provide an interface for an Org Admin to create a team (organization) and invite or add users to it. This might be done through Keycloak’s admin console or via our app using Keycloak’s API. Once a user is part of a team, all cases they create or access will be tagged with that team.

SSO Integration for Multi-Tenancy: By leveraging Keycloak, users will authenticate through a single login page, and upon success the issued token will include their team/org membership (for example, as a realm attribute or a group claim) and roles. Our application will decode the token to get user identity, org, and roles on each request. We’ll ensure the token’s org claim matches the resource’s org ID for every operation.

Org Administration: We will create a special section in the UI for Org Admins where they can manage users. This likely involves calling our backend which in turn uses Keycloak’s REST API or admin client to create users and assign roles. We plan to use Keycloak’s capabilities as much as possible, so our app becomes mostly an intermediary to apply our business logic (like ensuring the user’s org ID is set correctly).

By structuring users by organization and role, we satisfy the need to keep data accessible only to the right people. In summary, multi-tenant RBAC will be at the core of access control, with each tenant’s data siloed and roles defined per tenant to limit permissions appropriately.

## 2. Evidence Intake and Chain of Custody


Evidence Upload Process: Users can upload evidence files to the system by creating or selecting a case and then uploading files to that case. We will only accept raw evidence files (uncompressed) up to a size of ~1 GB each, at least initially. Accepting raw files means users should provide files in their original format (e.g., EVTX logs, binary .pf prefetch files, etc.). We will maintain an allowlist of file types/extensions that are expected (Windows event logs, registry hives, CSV logs, etc.) and block any executables or unusual file types that are not part of the forensic artifact list. If needed, we can verify file type by magic header as well.

Storage and Hashing: Upon upload, the file will be streamed to an object storage and a cryptographic hash (SHA-256 or better) of the file will be computed. This hash serves as the digital fingerprint of the evidence. It will be stored in our database and used to verify integrity later. We will log metadata such as upload timestamp, the user who uploaded, and the case it belongs to. The evidence file itself is write-once/read-many (WORM) by policy. Our application will never modify the original file, preserving its integrity.

Chain of Custody Logging: Maintaining a chain of custody is crucial. The system will automatically generate an audit trail entry for each significant action on an evidence file. This includes: when it was uploaded (time, by whom, from what IP if available), when it was processed by the parser, when it was indexed into OpenSearch. Each log will have the user, timestamp, and action. This chronological log of custody ensures we know “who had charge of the evidence at any given time” and what was done.

File Status Tracking: We will implement a status field for each evidence item to track its state in the pipeline. Possible states: UPLOADING (in progress), RECEIVED (stored and awaiting processing), PARSING (the parser worker is analyzing it), INGESTING (loading parsed data to OpenSearch), COMPLETE (fully ingested and available), or ERROR (if processing failed). The status will update as the Celery workflow moves along. Users will be able to see these statuses in the UI for each file, giving them transparency into where their evidence is in the process.

Retention Period: We will enforce a data retention policy as part of intake. Configuration will specify (e.g., 365 days) after which evidence and its derived data should be purged, unless the case is actively extended.After the chosen time, the system may automatically delete the evidence file and associated index data from OpenSearch. This will be made clear to users. All deletions will also be logged.

Security Measures for Intake: All uploads will be done via HTTPS (TLS 1.3) to protect evidence in transit. We’ll also implement scanning of metadata (like checking file header signatures) to ensure it matches the extension and expected format, any file that doesn’t match known artifact types could be rejected or flagged. While we won’t execute or open the files beyond parsing them with our tools, we remain cautious of malformed files that could exploit parser vulnerabilities. For that, we will in the future consider using protections like gVisor.

## 3. Parsing Scope and Timeline Model


Supported Artifact Types: The platform will accept all types of timeline based files. The scope includes: Windows Event Logs (EVTX), Prefetch files (.pf), SRUM, Shimcache, Amcache, Windows Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, etc.), browser history files (e.g., Chrome/Firefox SQLite databases), web proxy logs, DNS query logs, Linux system logs (such as journald or syslog files), web server logs (Apache/Nginx), cloud service logs (AWS CloudTrail, GCP audit logs, Azure logs). This is an ambitious list, but many of these are handled by existing libraries and tools.

Using log2timeline: We plan to integrate log2timeline to handle the heavy lifting of parsing whenever possible. Plaso can output results in various formats, including JSON or direct indexing into an OpenSearch/Elasticsearch database. In fact, Plaso’s psort tool has an OpenSearch output module that can send parsed events straight to an OpenSearch index.. We’ll verify if we can use that output mode (it requires the opensearchpy client and some config for index name, etc.).

Automatic Format Detection: We must see if Plaso handle automatic parser detection. If not we would have to implement the feature. 

Timeline Data Model: All parsed events will be converted into a unified timeline schema. At minimum, each event will have a timestamp (in UTC), a description/message, a source (which artifact it came from), and other fields like host, user, etc.

Integration into Celery Workflow: The parsing will happen asynchronously in worker processes. The workflow for a given file will be: (1) Celery task starts -> (2) update file status to PARSING -> (3) run the parser (Plaso or other) -> (4) on success, update status to INGESTING (if separate, or directly to COMPLETE if using direct output) -> (5) confirm data is in OpenSearch, update status to COMPLETE. If an error occurs at any step, catch it, log it, mark status ERROR.

Performance Considerations: Parsing can be time-consuming, especially for large files. Users will see the parsing status, but we should also consider splitting tasks if needed. For instance, if a user uploaded a 1GB CSV log, we might want to split it into multiple tasks.

Finally, we will document the time normalization clearly: everything in UTC. Consistency in time storage will prevent confusion when analysts collaborate in different time zones.

## 4. Workflows and User Experience


Case Lifecycle: The user experience is built around cases. A Case represents an investigation to which evidence files are attached. The typical workflow will be: an authorized user (Case Lead or Org Admin) creates a new case, providing basic info like case name, description, and maybe a case ID/reference. Once the case exists, team members (Case Lead, Analysts on that case) can begin uploading evidence to the case. The UI will have an “Add Evidence” button, which allows file selection and upload (multiple files allowed). Users will see an evidence list for the case, with each file’s name, size, hash, uploader, and current status.

Evidence Processing Flow: After upload, the user will observe the file going through states: e.g., "Uploading", “Received – parsing queued”, then “Parsing”, then “Ingesting”, then “Complete”. We will provide a progress indicator or at least a spinner and status text. For large files, parsing could take a long time, so we may also show logs or a percentage if we can get that. The user can continue using the app or come back later – the processing happens in background.

Viewing Results (Timeline Analysis): Once evidence is ingested (Complete), the user can switch to the Timeline view for that case. Rather than building a completely new UI for timeline analysis from scratch (which is complex), we will integrate OpenSearch Dashboards as the primary analysis interface. OpenSearch Dashboards (the Kibana-equivalent for OpenSearch) will be set up with index patterns for the case timelines. For example, when a case “Alpha” is created, we might create an index pattern case_alpha_* in Dashboards. The user can click a “Open Timeline Analysis” button in our web app, which either embeds the Dashboards in an iframe or opens a new browser tab to OpenSearch Dashboards pointed at the case’s index. Since we plan to have SSO integration, the user will not need to re-login – Keycloak will allow Dashboards access. In Dashboards, we can have pre-built visualizations or just let users use Discover to filter and search events.

User Interface Design: The web application will have a clean UI with a few main views:
 - Dashboard/Cases List: shows all cases the user has access to. From here they can create a new case or select an existing one.
 - Case Detail View: shows case info and the list of evidence items. This is where files can be uploaded and their statuses seen. We’ll also show maybe summary stats.
 - Timeline/Analysis View: this might simply link into OpenSearch Dashboards as described. 
 - Collaborative Features: Since data is team-based, multiple analysts might be looking at the timeline simultaneously. Using OpenSearch Dashboards means they could each apply filters independently, etc., without interfering with each other.

Handling Errors: If a file fails to parse (status goes to ERROR), the UI will reflect that and perhaps offer a retry button. The error details (from logs) might be surfaced in a minimal way, e.g., “Parse failed: invalid format” or a generic “An error occurred. Please check the file format or contact support.” We will not expose raw stack traces to the end user, but we will log them for developers/admins.


## 5. Security and Compliance

Security is paramount given the sensitive nature of digital evidence. We will implement several measures in line with ISO 27001 controls and general best practices:


Data Residency and Retention: All user data (uploaded evidence) resides on the designated on-premises server/storage. We will enforce the retention period as mentioned: by default, 365 days.

Transport Security (TLS 1.3): All network communication in the system will be secured with encryption. This includes:
 - The web app and API will be served over HTTPS with TLS 1.3 only, using strong cipher suites. We’ll obtain or generate certificates (for on-prem, likely a self-signed or enterprise CA certificate initially; we can also integrate Let’s Encrypt if the server is internet-accessible for convenience).
 - Internal components like OpenSearch and Keycloak will also communicate over TLS where applicable. OpenSearch nodes will have certificates for inter-node encryption and for the client (Dashboards) to node encryption. Keycloak can be run with HTTPS enabled.


Input Validation and File Type Restrictions: As mentioned, we will block certain file types from being uploaded. Executable files (.exe, .dll, scripts, etc.) will be rejected. Additionally, all files will be treated as untrusted, even if they are of allowed type. We won’t execute them except through our parsers. We may also run a quick antivirus scan on uploaded files as a precaution, especially if users might inadvertently upload infected files.

Sandboxed Parsing: To enhance security when data parsing, we could use a sandbox like gVisor. We must make performance tests to ckeck if it is light or very time consuming. 


Logging and Monitoring: All security-relevant events will be logged. This includes login attempts on the web app, any permission denials, uploads and downloads of evidence, and system errors. If someone tries to access a case they shouldn’t, we will log the denied request and the username/IP. We will review these logs periodically or integrate with a SIEM if available.

Access Control: Within the application, we enforce least privilege.

Secure Configuration: We will follow best practices for securing each component:
 - Keycloak: use secure passwords for admin, turn off any unnecessary open registration or public endpoints, set token lifespans appropriately. We’ll also configure Keycloak to require strong passwords for user accounts.
 - OpenSearch: enable its security plugin, disable demo accounts, use HTTPS for client and node communication, and keep it on a private network or localhost-only for access.
 - API: implement rate limiting to mitigate brute force or DoS, and use input validation on all API parameters. We will also ensure serialization is handled safely.

We will document everything as part of an “Information Security Management” approach:
 - A.8.2 (Information Classification): Case data is clearly sensitive, we treat all evidence as confidential. Only authorized team members access it.
 - A.9 (Access Control): As described, strong authentication via Keycloak and role-based access ensures only the right people access the right data.
 - A.10 (Cryptography): TLS for data in transit, in the future we will consider encrypting files on rest and implementing a key manager.
 - A.12.3 (Backup): We should consider backups of the data within retention period.
 - A.12.4 (Logging): We have extensive logging of actions, stored securely (not modifiable by normal users).
 - A.14 (System acquisition, development, maintenance): As developers, we’ll follow secure coding practices. The user specifically is asking for this plan, which shows security is built-in from design (secure by design).
 - A.13 (Communications security): Covered with TLS and network segregation.

Tamper Resistance: We might implement additional protections like checksums or digital signatures on evidence and logs.

6. Identity, Authorization, and Single Sign-On (SSO)

We have chosen Keycloak (an open-source Identity and Access Management solution) as the central authentication and authorization server. Keycloak will handle user identities, authentication (login), and issuing tokens that our services (API, OpenSearch) will trust. This provides a unified SSO experience and robust security features out-of-the-box.

Keycloak Setup: We will deploy a Keycloak server on-prem (via a container). The following configuration will be done in Keycloak:
Create a Realm to contain our users and roles.
Within the realm, define Clients for our applications:
- One client for our Web App/API.
- One client for OpenSearch Dashboards integration. OpenSearch’s security plugin acts as an OpenID Connect Relying Party. In the Keycloak realm we’ll create a client (e.g., opensearch-dashboards) that will represent OpenSearch Dashboards. We will configure this client with settings Keycloak requires.

Define the Roles in Keycloak that match our application roles: org-admin, case-lead, analyst, read-only.

Model the Team/Org membership. There are a couple of ways:
- We could use a separate realm per organization, but that gets complex to manage. Instead, we’ll use a single realm and use Groups to represent organizations/teams. For example, create a Group for each team (Team A, Team B). Users can be placed into a group corresponding to their org. We can also map a group membership into the token as a claim (so our app knows which org the user is in). Keycloak can include group membership in the JWT token. We might also encode the org in the username or a custom attribute.
 