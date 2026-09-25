# Device Resource and Lifecycle Reads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #155 by adding read-only tools for the families `CLAUDE.md` lists as "in scope, simply unbuilt": Device Resources, Device Image Definitions, MNHA Clusters and RMA.

**Architecture:** Enum-dispatched tools keep the surface small where endpoints differ only by path suffix. That is one `list_sdc_device_config` with a `section` enum, not five tools, which follows how `list_sdc_resources` takes a `resource` enum. Client methods return verbatim JSON. Tool output goes through `finish_redacted` because none of these families has been observed on the lab tenant.

**Tech Stack:** Rust 1.89, rmcp, reqwest, serde/schemars, axum (test-only fake SDC).

**Spec:** GitHub issue fastrevmd-lab/rustsdcmcp#155; the `CLAUDE.md` scope section; `docs/sdc-api/security-director-cloud-apis-openapi3.json`.

**Depends on:** `2026-09-24-read-gaps-and-secret-redaction.md` being merged first. This plan uses its `finish_redacted` helper, and the tool counts below continue from its final 66.

## Global Constraints

- MSRV `1.89`.
- The CI command is the gate, not plain `cargo test`:
  `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --locked && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
- **Reads only.** No tool here is added to `WRITE_TOOLS`. Stage/deploy image, MNHA sync, and RMA activate/reactivate are out of scope. If they are ever wanted, they go through prepare → approve → apply.
- **Excluded on purpose:** `GET /api/v1/devices/{device_id}/rma/reactivation_config` returns `reactivation_config.config_contents`, a full bootstrap device configuration (credentials, outbound-ssh secrets). Do not expose it. Task 4 records the reason in `CLAUDE.md`.
- `KNOWN_TOOLS`, the count in `crates/rustsdcmcp/tests/tool_contract.rs`, and the README "**N MCP tools**: R bounded read tools" line all move in the same commit as each new tool.
- Every path identifier goes through `validate_atom`. Every list goes through `ListRequest::new(from, size, max_page_size)`.
- Sabotage each fix once, one at a time, and confirm the named test fails.
- One commit per task, each run through `codex exec review --commit <sha>`. No verdict means the gate did not run.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
- Branch: `feat/device-reads-155` from `origin/main`, after the #156 PR merges.

## Tool count ledger

| After task | New tools | `KNOWN_TOOLS.len()` | Reads |
|---|---|---:|---:|
| start (after #156) | — | 66 | 52 |
| 1 | `list_sdc_device_config`, `get_sdc_device_config_revision` | 68 | 54 |
| 2 | `list_sdc_image_definitions`, `get_sdc_image_job_status` | 70 | 56 |
| 3 | `get_sdc_mnha_sync_status`, `get_sdc_rma_state`, `get_sdc_rma_reactivation_status` | 73 | 59 |

## Spec facts used (verified 2026-09-24)

| Operation | Path | Query |
|---|---|---|
| GetDeviceConfigInterface | `/api/v1/devices/{device_uuid}/config/interfaces` | from, size, filter |
| GetDeviceConfigSubInterface | `/api/v1/devices/{device_uuid}/config/subinterfaces` | from, size, filter |
| GetDeviceInterfaceSubinterfaces | `/api/v1/devices/{device_uuid}/config/interfaces/{interface_name}/subinterfaces` | from, size, filter |
| GetDeviceConfigZones | `…/config/zones` | from, size, filter |
| GetDeviceConfigRI | `…/config/routing_instances` | from, size, filter |
| GetDeviceConfigIdpSensor | `…/config/idp_sensors` | from, size, filter |
| GetDeviceConfigRevisions | `…/config/latest_version` | — |
| ListDeviceImageDefinitions | `/api/v1/device_image_definitions` | from, size, … |
| GetStageImageStatus | `/api/v1/device_image_definitions/stage_image/{stage_image_id}` | — |
| GetDeployImageStatus | `/api/v1/device_image_definitions/deploy_image/{deploy_image_id}` | — |
| GetSyncMNHAStatus | `/api/v1/mnha_clusters/sync/{mnha_sync_id}` | — |
| GetRMADeviceStatus | `/api/v1/devices/{device_id}/rma/state` | — |
| GetReactivationStatus | `/api/v1/devices/rma/reactivate/{reactivation_id}` | — |

`filter` is not exposed (YAGNI). None of these response schemas declares a credential field; a spec scan on 2026-09-24 found none.

## File map

- Modify `crates/rustsdcmcp-core/src/models.rs`: add the `DeviceConfigSection` and `ImageJob` enums.
- Modify `crates/rustsdcmcp-core/src/lib.rs`: re-export both enums from the `pub use models::{…}` block.
- Modify `crates/rustsdcmcp-core/src/client.rs`: client methods and tests.
- Modify `crates/rustsdcmcp/src/server.rs`: arg structs, handlers, and `KNOWN_TOOLS`.
- Modify `crates/rustsdcmcp/tests/tool_contract.rs` and `README.md`: counts.
- Modify `CLAUDE.md`, `docs/sdc-api/README.md` and `CHANGELOG.md` in Task 4.

---

### Task 1: Device Resources — `list_sdc_device_config`, `get_sdc_device_config_revision`

**Interfaces:**
- Produces: `rustsdcmcp_core::DeviceConfigSection { Interfaces, Subinterfaces, Zones, RoutingInstances, IdpSensors }` (serde `snake_case`) with `fn segment(self) -> &'static str`, plus `SdcClient::list_device_config(device_uuid: &str, section: DeviceConfigSection, interface_name: Option<&str>, page: ListRequest, &ct)` and `SdcClient::get_device_config_revision(device_uuid: &str, &ct)`.

- [ ] **Step 1: Add the enum** to `models.rs` after `TargetType`:

```rust
/// One section of a device's configuration as SDC models it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceConfigSection {
    /// Physical and logical interfaces.
    Interfaces,
    /// Sub-interfaces; narrow to one parent with `interface_name`.
    Subinterfaces,
    /// Security zones.
    Zones,
    /// Routing instances.
    RoutingInstances,
    /// IDP sensor configuration.
    IdpSensors,
}

impl DeviceConfigSection {
    /// The path segment under `/api/v1/devices/{device_uuid}/config/`.
    #[must_use]
    pub const fn segment(self) -> &'static str {
        match self {
            Self::Interfaces => "interfaces",
            Self::Subinterfaces => "subinterfaces",
            Self::Zones => "zones",
            Self::RoutingInstances => "routing_instances",
            Self::IdpSensors => "idp_sensors",
        }
    }
}
```

Add `DeviceConfigSection` to the `pub use models::{…}` list in `lib.rs`.

- [ ] **Step 2: Write the failing client tests** in `client.rs` `mod tests`:

```rust
    #[tokio::test]
    async fn device_config_sections_map_to_their_config_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({"items": [], "count": 0}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 3, 100).expect("test page");
        for section in [
            DeviceConfigSection::Interfaces,
            DeviceConfigSection::Subinterfaces,
            DeviceConfigSection::Zones,
            DeviceConfigSection::RoutingInstances,
            DeviceConfigSection::IdpSensors,
        ] {
            sdc.list_device_config("d1", section, None, page(), &ct)
                .await
                .expect("list");
        }
        sdc.list_device_config("d1", DeviceConfigSection::Subinterfaces, Some("ge-0/0/1"), page(), &ct)
            .await
            .expect("per-interface list");
        sdc.get_device_config_revision("d1", &ct).await.expect("revision");
        let seen = seen.lock().expect("read").clone();
        assert_eq!(
            seen,
            vec![
                "/api/v1/devices/d1/config/interfaces?from=0&size=3",
                "/api/v1/devices/d1/config/subinterfaces?from=0&size=3",
                "/api/v1/devices/d1/config/zones?from=0&size=3",
                "/api/v1/devices/d1/config/routing_instances?from=0&size=3",
                "/api/v1/devices/d1/config/idp_sensors?from=0&size=3",
                "/api/v1/devices/d1/config/interfaces/ge-0%2F0%2F1/subinterfaces?from=0&size=3",
                "/api/v1/devices/d1/config/latest_version",
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn interface_name_is_refused_outside_the_subinterfaces_section() {
        let sdc = client(Url::parse("http://127.0.0.1:9/").expect("url"), 4096);
        let error = sdc
            .list_device_config(
                "d1",
                DeviceConfigSection::Zones,
                Some("ge-0/0/1"),
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("interface_name only narrows subinterfaces");
        assert!(matches!(error, SdcError::InvalidInput(_)));
    }
```

Add `DeviceConfigSection` to the test module's imports. `use super::*;` does not reach it, because `client.rs` imports from `crate::{…}`, so add it to that top-of-file `use crate::{…}` list.

- [ ] **Step 3: Run and confirm FAIL** with `cargo test -p rustsdcmcp-core --locked device_config interface_name_is_refused`. Expected: compile error, because the methods do not exist yet.

- [ ] **Step 4: Implement** after `list_config_versions`:

```rust
    /// List one section of a device's configuration as SDC models it.
    ///
    /// `interface_name` narrows `Subinterfaces` to one parent interface and is
    /// refused for any other section rather than silently ignored.
    pub async fn list_device_config(
        &self,
        device_uuid: &str,
        section: DeviceConfigSection,
        interface_name: Option<&str>,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        let Some(interface_name) = interface_name else {
            return self
                .list(
                    &["api", "v1", "devices", device_uuid, "config", section.segment()],
                    page,
                    cancellation,
                )
                .await;
        };
        if section != DeviceConfigSection::Subinterfaces {
            return Err(SdcError::InvalidInput(
                "interface_name is only valid with section=subinterfaces",
            ));
        }
        validate_atom("interface_name", interface_name)?;
        self.list(
            &[
                "api",
                "v1",
                "devices",
                device_uuid,
                "config",
                "interfaces",
                interface_name,
                "subinterfaces",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch the configuration revision status for one device.
    pub async fn get_device_config_revision(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(
            &["api", "v1", "devices", device_uuid, "config", "latest_version"],
            &[],
            cancellation,
        )
        .await
    }
```

- [ ] **Step 5: Run and confirm PASS.** Sabotage, one at a time: (a) change `"routing_instances"` to `"routing-instances"` in `segment()` and confirm the path test FAILS, then restore; (b) delete the `section != Subinterfaces` guard and confirm the refusal test FAILS, then restore.

- [ ] **Step 6: Add the tools.** Append `"list_sdc_device_config", "get_sdc_device_config_revision",` to `KNOWN_TOOLS` after `"list_sdc_config_versions",`. Import `DeviceConfigSection` in `server.rs`. Arg struct:

```rust
/// Arguments for listing one section of a device's configuration.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfigListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device UUID.
    pub device_uuid: String,
    /// Configuration section to list.
    pub section: DeviceConfigSection,
    /// Parent interface; valid only with `section=subinterfaces`.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}
```

Handlers (`get_sdc_device_config_revision` reuses the existing `DeviceArgs`):

```rust
    #[tool(
        name = "list_sdc_device_config",
        description = "List one section (interfaces, subinterfaces, zones, routing_instances, idp_sensors) of a device's configuration as SDC models it, with bounded pagination. Use to reconcile SDC's view against the device."
    )]
    async fn list_sdc_device_config(
        &self,
        Parameters(args): Parameters<DeviceConfigListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_device_config",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_device_config", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_device_config(
                        &args.device_uuid,
                        args.section,
                        args.interface_name.as_deref(),
                        page,
                        &cancellation,
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish_redacted(audit, result))
    }

    #[tool(
        name = "get_sdc_device_config_revision",
        description = "Get the configuration revision status SDC holds for one device."
    )]
    async fn get_sdc_device_config_revision(
        &self,
        Parameters(args): Parameters<DeviceArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_device_config_revision",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_device_config_revision", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client
                .get_device_config_revision(&args.device_uuid, &cancellation)
                .await,
        ))
    }
```

Set the count in `tool_contract.rs` to `68`, add `#155 added device config section and revision reads.` to its comment, and set the README to `**68 MCP tools**: 54 bounded read tools`.

- [ ] **Step 7: Run the full CI command.**
- [ ] **Step 8: Commit** `feat: read device config sections and revision (#155)` plus the trailer, then run the Codex gate.

---

### Task 2: Device image definitions — `list_sdc_image_definitions`, `get_sdc_image_job_status`

**Interfaces:**
- Produces: `rustsdcmcp_core::ImageJob { Stage, Deploy }` (serde `snake_case`), `SdcClient::list_image_definitions(page, &ct)`, and `SdcClient::get_image_job_status(job: ImageJob, job_id: &str, &ct)`.

- [ ] **Step 1: Add the enum** to `models.rs` after `DeviceConfigSection`, and re-export it from `lib.rs`:

```rust
/// Kind of asynchronous device-image job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImageJob {
    /// Image staged onto a device, not yet installed.
    Stage,
    /// Image deployed (installed) onto a device.
    Deploy,
}

impl ImageJob {
    /// The path segment under `/api/v1/device_image_definitions/`.
    #[must_use]
    pub const fn segment(self) -> &'static str {
        match self {
            Self::Stage => "stage_image",
            Self::Deploy => "deploy_image",
        }
    }
}
```

- [ ] **Step 2: Write the failing client test** (add `ImageJob` to the `use crate::{…}` list):

```rust
    #[tokio::test]
    async fn image_reads_use_the_definition_list_and_job_status_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        sdc.list_image_definitions(ListRequest::new(0, 2, 100).expect("page"), &ct)
            .await
            .expect("list");
        sdc.get_image_job_status(ImageJob::Stage, "s1", &ct).await.expect("stage");
        sdc.get_image_job_status(ImageJob::Deploy, "d1", &ct).await.expect("deploy");
        assert_eq!(
            seen.lock().expect("read").clone(),
            vec![
                "/api/v1/device_image_definitions?from=0&size=2",
                "/api/v1/device_image_definitions/stage_image/s1",
                "/api/v1/device_image_definitions/deploy_image/d1",
            ]
        );
        server.abort();
    }
```

- [ ] **Step 3: Run and confirm FAIL**, then implement:

```rust
    /// List device software image definitions with bounded pagination.
    pub async fn list_image_definitions(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "device_image_definitions"], page, cancellation)
            .await
    }

    /// Fetch the status of one image stage or deploy job.
    pub async fn get_image_job_status(
        &self,
        job: ImageJob,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "device_image_definitions", job.segment(), job_id],
            &[],
            cancellation,
        )
        .await
    }
```

- [ ] **Step 4: Run and confirm PASS.** Sabotage: swap the two `segment()` strings and confirm FAIL. Restore.

- [ ] **Step 5: Add the tools.** Append `"list_sdc_image_definitions", "get_sdc_image_job_status",` to `KNOWN_TOOLS` and import `ImageJob` in `server.rs`. `list_sdc_image_definitions` reuses `ListArgs`. New arg struct:

```rust
/// Arguments for one device-image job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageJobArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Whether the job stages or deploys an image.
    pub job: ImageJob,
    /// Job ID returned when the stage or deploy was started.
    pub job_id: String,
}
```

Handlers:

```rust
    #[tool(
        name = "list_sdc_image_definitions",
        description = "List device software image definitions with bounded pagination."
    )]
    async fn list_sdc_image_definitions(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_image_definitions",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_image_definitions", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self.client.list_image_definitions(page, &cancellation).await,
            Err(error) => Err(error),
        };
        Ok(finish_redacted(audit, result))
    }

    #[tool(
        name = "get_sdc_image_job_status",
        description = "Get the status of one device-image stage or deploy job. Read-only; this server cannot start one."
    )]
    async fn get_sdc_image_job_status(
        &self,
        Parameters(args): Parameters<ImageJobArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_image_job_status",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_image_job_status", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client
                .get_image_job_status(args.job, &args.job_id, &cancellation)
                .await,
        ))
    }
```

Set the count to `70`, add `#155 added image definition and job-status reads.` to the comment, and set the README to `**70 MCP tools**: 56 bounded read tools`.

- [ ] **Step 6: Run the full CI command.**
- [ ] **Step 7: Commit** `feat: read device image definitions and job status (#155)` plus the trailer, then run the Codex gate.

---

### Task 3: MNHA sync status and RMA status (3 tools)

**Interfaces:**
- Produces: `SdcClient::get_mnha_sync_status(mnha_sync_id, &ct)`, `get_rma_state(device_id, &ct)`, `get_rma_reactivation_status(reactivation_id, &ct)`.

- [ ] **Step 1: Write the failing client test**

```rust
    #[tokio::test]
    async fn mnha_and_rma_status_reads_use_their_spec_paths() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().expect("record").push(uri.to_string());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        sdc.get_mnha_sync_status("m1", &ct).await.expect("mnha");
        sdc.get_rma_state("dev1", &ct).await.expect("rma state");
        sdc.get_rma_reactivation_status("r1", &ct).await.expect("reactivation");
        assert_eq!(
            seen.lock().expect("read").clone(),
            vec![
                "/api/v1/mnha_clusters/sync/m1",
                "/api/v1/devices/dev1/rma/state",
                "/api/v1/devices/rma/reactivate/r1",
            ]
        );
        server.abort();
    }
```

- [ ] **Step 2: Run and confirm FAIL**, then implement:

```rust
    /// Fetch the status of one MNHA cluster sync job.
    pub async fn get_mnha_sync_status(
        &self,
        mnha_sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("mnha_sync_id", mnha_sync_id)?;
        self.get(&["api", "v1", "mnha_clusters", "sync", mnha_sync_id], &[], cancellation)
            .await
    }

    /// Fetch the RMA state of one device.
    ///
    /// The sibling `rma/reactivation_config` endpoint is deliberately not
    /// wrapped: it returns a full bootstrap configuration.
    pub async fn get_rma_state(
        &self,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_id", device_id)?;
        self.get(&["api", "v1", "devices", device_id, "rma", "state"], &[], cancellation)
            .await
    }

    /// Fetch the status of one RMA reactivation job.
    pub async fn get_rma_reactivation_status(
        &self,
        reactivation_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("reactivation_id", reactivation_id)?;
        self.get(
            &["api", "v1", "devices", "rma", "reactivate", reactivation_id],
            &[],
            cancellation,
        )
        .await
    }
```

- [ ] **Step 3: Run and confirm PASS.** Sabotage: drop `"state"` from `get_rma_state` and confirm FAIL. Restore.

- [ ] **Step 4: Add the tools.** Append `"get_sdc_mnha_sync_status", "get_sdc_rma_state", "get_sdc_rma_reactivation_status",` to `KNOWN_TOOLS`. Arg structs:

```rust
/// Arguments for one MNHA sync job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MnhaSyncArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// MNHA sync job ID.
    pub mnha_sync_id: String,
}

/// Arguments for one device's RMA state.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RmaDeviceArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device ID.
    pub device_id: String,
}

/// Arguments for one RMA reactivation job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RmaReactivationArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Reactivation job ID.
    pub reactivation_id: String,
}
```

Handlers:

```rust
    #[tool(
        name = "get_sdc_mnha_sync_status",
        description = "Get the status of one MNHA cluster sync job. Read-only; this server cannot start a sync."
    )]
    async fn get_sdc_mnha_sync_status(
        &self,
        Parameters(args): Parameters<MnhaSyncArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_mnha_sync_status",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_mnha_sync_status", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client
                .get_mnha_sync_status(&args.mnha_sync_id, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_rma_state",
        description = "Get the RMA state of one device, including missing resources blocking reactivation."
    )]
    async fn get_sdc_rma_state(
        &self,
        Parameters(args): Parameters<RmaDeviceArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_rma_state", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_rma_state", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client.get_rma_state(&args.device_id, &cancellation).await,
        ))
    }

    #[tool(
        name = "get_sdc_rma_reactivation_status",
        description = "Get the status of one RMA reactivation job."
    )]
    async fn get_sdc_rma_reactivation_status(
        &self,
        Parameters(args): Parameters<RmaReactivationArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_rma_reactivation_status",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "get_sdc_rma_reactivation_status", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client
                .get_rma_reactivation_status(&args.reactivation_id, &cancellation)
                .await,
        ))
    }
```

Set the count to `73`, add `#155 added MNHA sync and RMA status reads.` to the comment, and set the README to `**73 MCP tools**: 59 bounded read tools`.

- [ ] **Step 5: Run the full CI command.**
- [ ] **Step 6: Commit** `feat: read MNHA sync and RMA status (#155)` plus the trailer, then run the Codex gate.

---

### Task 4: Scope record, docs, live check

- [ ] **Step 1: Update `CLAUDE.md` "In scope, simply unbuilt".** Remove Device Resources, Image Definitions, MNHA and RMA from that list. Add this under **Out of scope — do not implement**:

```markdown
- **`GET /api/v1/devices/{device_id}/rma/reactivation_config`** — returns
  `config_contents`, a full bootstrap device configuration. A credential-bearing
  blob with no review value; the RMA state and reactivation-status reads cover
  the lifecycle question.
- **Image stage/deploy, MNHA sync, RMA activate/reactivate** stay unbuilt as
  writes. If needed, they go through prepare → approve → apply, never direct.
```

- [ ] **Step 2: Add a short "Device Resources" note to `docs/sdc-api/README.md`** listing the five sections, the `interface_name` path, and that `filter` is not exposed.
- [ ] **Step 3: Add a `CHANGELOG.md` Unreleased entry.** List the 7 tools, and add: "Tokens minted with explicit tool lists do not gain these tools."
- [ ] **Step 4: Run the full CI command, commit** `docs: record #155 scope and exclusions` plus the trailer, and run the Codex gate.
- [ ] **Step 5: Open the PR** with `Closes #155`. Under "Not verified", list: MNHA response shape (the lab has no cluster), RMA (no RMA in progress), and image jobs (no job IDs on lab).
- [ ] **Step 6: Live check on the test rig.** Start `test-labmode-sdc`. Pick a device UUID with `list_sdc_devices size=1`, then call `list_sdc_device_config` for all five sections and `get_sdc_device_config_revision`. Compare the zones and interfaces against the same vSRX through `rustjunosmcp` `get_junos_config`, and record differences in `docs/sdc-api/README.md` (#155's first acceptance criterion). Call `list_sdc_image_definitions size=5`. Stop the rig.
