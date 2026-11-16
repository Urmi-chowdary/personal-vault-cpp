# PersonaVault — Smart App Permission & Privacy Analyzer

PersonaVault is an expanded C++14 OOP web application for analysing app permission requests and managing privacy decisions. It combines a rule-based privacy engine, app inventory, consent management, safer-configuration recommendations, local persistence and an audit trail in a browser dashboard.

> **Project type:** College / educational prototype. The risk rules are illustrative and explainable. PersonaVault does not inspect installed apps, access a device's permission manager, or certify that an application is safe.

## 1. Run the website in VS Code (macOS / Linux)

Requirements: `g++`, `make`, and a terminal that supports POSIX sockets.

1. Extract the ZIP.
2. Open the `PersonaVault_Privacy_Analyzer` folder in VS Code.
3. Choose **Terminal → New Terminal**.
4. Compile the C++ backend:

```bash
make server
```

5. Start the local web server:

```bash
./sentinel_web
```

6. Open this URL in a browser:

```text
http://localhost:8080
```

Keep the terminal open while using the website. Press `Control + C` to stop it. If port 8080 is occupied, run `./sentinel_web 9000` and open `http://localhost:9000`.

## 2. Expanded website modules

### A. Overview dashboard
- Total registered applications.
- Total permissions tracked across the vault.
- Count of applications with medium-or-higher risk scores.
- Number of consent decisions.
- Application risk overview and recent audit activity.
- Quick navigation to all modules.

### B. Permission Analyzer
- Enter an application name and select its declared purpose.
- Select from 15 permission types.
- Analyse purpose mismatch, risky permission combinations and high sensitivity.
- View an explainable score from 0–100, risk category, rule findings and removal suggestions.
- Keep a short analysis history in the browser session.

### C. App Vault
- Register application profiles in the C++ backend.
- View all registered apps, their purposes, permission counts and risk scores.
- Open a report for an individual app.
- Apply the engine's suggested safer configuration.
- Remove an application from the inventory.
- Save and load application and consent data using local files.

### D. Consent Centre
- Select a registered app.
- Review its requested permissions and sensitivity levels.
- Record a simulated grant or deny decision for each permission.
- Review current consent state.

These are records inside the educational project. They do not change actual Android, iOS or computer operating-system permissions.

### E. Audit Trail
- View recent application registration and removal events.
- Track consent changes, safer-configuration actions, and save/load activity.
- Audit events are produced by the C++ `AuditLogger`.

### F. OOP Architecture
The website includes a short architecture explainer that maps the four OOP principles to the actual C++ source files.

## 3. Permission catalogue

The C++ catalogue currently contains 15 permission categories:

| Permission | Sensitivity (1–10) | Example of data involved |
|---|---:|---|
| Location | 8 | Location and movement |
| Contacts | 7 | Address book |
| Camera | 7 | Image capture |
| Microphone | 8 | Audio input |
| SMS | 9 | Text messages |
| Documents | 6 | Personal files |
| Calendar | 4 | Events and schedule |
| Storage | 3 | Device file storage |
| Bluetooth | 5 | Bluetooth connectivity |
| Call logs | 9 | Call history |
| Notifications | 3 | Notification access |
| Nearby devices | 6 | Nearby device discovery |
| Biometrics | 10 | Biometric identity data |
| Health data | 10 | Personal health information |
| Network state | 2 | Network connectivity details |

The sensitivity values and purpose mappings are simplified project rules, not official platform classifications.

## 4. C++ privacy engine

The backend evaluates an app using three pluggable rule classes:

- **PurposeRule:** checks whether each requested permission matches the app's declared purpose.
- **CombinationRule:** checks risky pairs such as contacts + location, call logs + contacts, health data + location, biometrics + documents, and nearby devices + location.
- **SensitivityRule:** identifies apps that request multiple highly sensitive data categories.

`RiskScorer` adds finding points, caps the score at 100, maps it to LOW / MEDIUM / HIGH / CRITICAL, and gathers suggested removals. The score is explainable because each finding contains a rule name, points, explanation and optional removal suggestions.

## 5. Where the four OOP principles are used

### 1. Encapsulation
**Files:** `include/AppClient.h`, `src/AppClient.cpp`, `include/DataAsset.h`, `src/DataAsset.cpp`

- `AppClient` keeps the app name, purpose and permission collection private.
- `DataAsset` keeps permission name and sensitivity private.
- Public methods such as `getName()`, `getPermissions()`, `addPermission()` and `removePermission()` provide controlled access.

**Why:** Other classes cannot directly modify internal fields. Permission additions pass through validation and duplicate checks.

### 2. Abstraction
**Files:** `include/Rule.h`, `include/PolicyEngine.h`

- `Rule` is an abstract base class.
- It declares pure virtual methods `name()` and `evaluate()`.
- `PolicyEngine` uses the base interface rather than depending on each rule's implementation.

**Why:** The engine can execute a general rule contract while hiding the details of each privacy check.

### 3. Inheritance
**Files:** `include/Rule.h`, `src/Rule.cpp`

- `PurposeRule`, `CombinationRule` and `SensitivityRule` inherit from `Rule`.
- Each derived class implements its own `name()` and `evaluate()` methods.

**Why:** Shared rule structure is defined once, and specialised checks extend it without duplicating the interface.

### 4. Polymorphism
**Files:** `include/PolicyEngine.h`, `src/PolicyEngine.cpp`, `src/Rule.cpp`

- `PolicyEngine` stores different rule objects in `std::vector<std::unique_ptr<Rule>>`.
- It calls `r->evaluate(app)` through a base-class pointer.
- At runtime, C++ dispatches to the matching derived implementation.

**Why:** A new rule can be added using `addRule()` without rewriting the engine's evaluation loop. The test suite includes a custom derived rule to demonstrate this.

## 6. Additional C++ concepts

| Concept | Where it appears |
|---|---|
| Composition | `SentinelService` owns the policy engine, scorer, audit logger, consent manager and file storage modules. |
| STL containers | `vector`, `map`, `string`, `unique_ptr` and algorithms are used throughout. |
| Exception handling | Invalid purposes, unknown permissions and missing app records raise exceptions handled by the HTTP layer. |
| File handling | `FileStorage` persists app profiles and consent decisions. |
| Separation of concerns | Models, rules, scoring, service logic, HTTP server and browser UI are separate modules. |
| Runtime polymorphism | `PolicyEngine` evaluates all child rule types through the abstract `Rule` interface. |

## 7. Project structure

```text
PersonaVault_Privacy_Analyzer/
├── include/
│   ├── AppClient.h
│   ├── AuditLogger.h
│   ├── ConsentManager.h
│   ├── DataAsset.h
│   ├── FileStorage.h
│   ├── MenuInterface.h
│   ├── PermissionRequest.h
│   ├── PolicyEngine.h
│   ├── ReportGenerator.h
│   ├── RiskScorer.h
│   ├── Rule.h
│   ├── SentinelService.h
│   ├── Utils.h
│   ├── WebServer.h
│   └── WebsiteRiskScanner.h
├── src/
│   ├── AppClient.cpp
│   ├── AuditLogger.cpp
│   ├── ConsentManager.cpp
│   ├── DataAsset.cpp
│   ├── FileStorage.cpp
│   ├── MenuInterface.cpp
│   ├── PermissionRequest.cpp
│   ├── PolicyEngine.cpp
│   ├── ReportGenerator.cpp
│   ├── RiskScorer.cpp
│   ├── Rule.cpp
│   ├── SentinelService.cpp
│   ├── WebServer.cpp
│   ├── WebsiteRiskScanner.cpp
│   ├── main.cpp
│   └── web_main.cpp
├── web/
│   └── index.html
├── tests/
│   └── test_sentinel.cpp
├── Makefile
└── README.md
```

## 8. Build and test

Build the website server:

```bash
make server
```

Build the console application:

```bash
make console
./sentinel
```

Run the automated C++ tests:

```bash
make test
```

Clean generated executables:

```bash
make clean
```

## 9. HTTP API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Serve the dashboard |
| GET | `/api/meta` | Return purpose and permission catalogue |
| POST | `/api/analyze` | Analyse a submitted permission set |
| GET | `/api/apps` | List registered apps and consent state |
| POST | `/api/apps` | Register an app |
| GET | `/api/report?app=...` | Return one app's findings and recommendations |
| POST | `/api/remove` | Remove an app |
| POST | `/api/consent` | Record a grant or deny decision |
| POST | `/api/revoke` | Revoke a stored consent decision |
| POST | `/api/safer` | Apply suggested permission removals |
| GET | `/api/audit` | Return recent audit entries |
| POST | `/api/save` | Save app and consent records |
| POST | `/api/load` | Load saved records |

## 10. Explanation for the professor

“PersonaVault is a C++-based Smart App Permission and Privacy Analyzer. The frontend is developed using HTML, CSS and JavaScript, while the core permission analysis, rule evaluation, risk scoring, consent management, audit logging and file persistence are implemented in C++. A user can analyse permissions, register applications, manage simulated consent decisions, review audit records and apply safer permission recommendations. We implemented encapsulation to protect application and permission data, abstraction through an abstract Rule class, inheritance through specialised rule classes, and runtime polymorphism through PolicyEngine. The modular architecture makes it possible to add new permission categories and privacy rules without rewriting the entire application.”

## 11. Limitations and future enhancements

- The user manually supplies the requested permissions; the prototype does not inspect installed applications.
- Consent decisions are simulated records and do not change operating-system permissions.
- The rule catalogue is educational and can be expanded or refined.
- The local HTTP server is intended for a classroom demonstration, not public internet deployment.
- Future work could include Android manifest import, richer report export, role-based access, database integration and platform-specific permission explanations.
