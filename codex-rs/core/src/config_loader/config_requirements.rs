use codex_protocol::config_types::SandboxMode;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::SandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use std::fmt;

use crate::config::Constrained;
use crate::config::ConstraintError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementSource {
    MdmManagedPreferences { domain: String, key: String },
    SystemRequirementsToml { file: AbsolutePathBuf },
    LegacyManagedConfigTomlFromFile { file: AbsolutePathBuf },
    LegacyManagedConfigTomlFromMdm,
}

impl fmt::Display for RequirementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequirementSource::MdmManagedPreferences { domain, key } => {
                write!(f, "MDM managed preferences {domain}:{key}")
            }
            RequirementSource::SystemRequirementsToml { file } => {
                write!(f, "{}", file.as_path().display())
            }
            RequirementSource::LegacyManagedConfigTomlFromFile { file } => {
                write!(f, "{}", file.as_path().display())
            }
            RequirementSource::LegacyManagedConfigTomlFromMdm => {
                write!(f, "MDM managed_config.toml (legacy)")
            }
        }
    }
}

/// Normalized version of [`ConfigRequirementsToml`] after deserialization and
/// normalization.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigRequirements {
    pub approval_policy: Constrained<AskForApproval>,
    pub sandbox_policy: Constrained<SandboxPolicy>,
}

impl Default for ConfigRequirements {
    fn default() -> Self {
        Self {
            approval_policy: Constrained::allow_any_from_default(),
            sandbox_policy: Constrained::allow_any(SandboxPolicy::ReadOnly),
        }
    }
}

/// Base config deserialized from /etc/codex/requirements.toml or MDM.
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ConfigRequirementsToml {
    pub allowed_approval_policies: Option<Vec<AskForApproval>>,
    pub allowed_sandbox_modes: Option<Vec<SandboxModeRequirement>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProvenanceTrackingConfigRequirementsToml {
    pub inner: ConfigRequirementsToml,
    pub allowed_approval_policies_source: Option<RequirementSource>,
    pub allowed_sandbox_modes_source: Option<RequirementSource>,
}

impl ProvenanceTrackingConfigRequirementsToml {
    pub fn merge_unset_fields(
        &mut self,
        source: RequirementSource,
        mut other: ConfigRequirementsToml,
    ) {
        let source = Some(source);

        if self.inner.allowed_approval_policies.is_none() {
            if let Some(value) = other.allowed_approval_policies.take() {
                self.inner.allowed_approval_policies = Some(value);
                self.allowed_approval_policies_source = source.clone();
            }
        }

        if self.inner.allowed_sandbox_modes.is_none() {
            if let Some(value) = other.allowed_sandbox_modes.take() {
                self.inner.allowed_sandbox_modes = Some(value);
                self.allowed_sandbox_modes_source = source;
            }
        }
    }
}

impl From<ConfigRequirementsToml> for ProvenanceTrackingConfigRequirementsToml {
    fn from(inner: ConfigRequirementsToml) -> Self {
        Self {
            inner,
            ..Self::default()
        }
    }
}

/// Currently, `external-sandbox` is not supported in config.toml, but it is
/// supported through programmatic use.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum SandboxModeRequirement {
    #[serde(rename = "read-only")]
    ReadOnly,

    #[serde(rename = "workspace-write")]
    WorkspaceWrite,

    #[serde(rename = "danger-full-access")]
    DangerFullAccess,

    #[serde(rename = "external-sandbox")]
    ExternalSandbox,
}

impl From<SandboxMode> for SandboxModeRequirement {
    fn from(mode: SandboxMode) -> Self {
        match mode {
            SandboxMode::ReadOnly => SandboxModeRequirement::ReadOnly,
            SandboxMode::WorkspaceWrite => SandboxModeRequirement::WorkspaceWrite,
            SandboxMode::DangerFullAccess => SandboxModeRequirement::DangerFullAccess,
        }
    }
}

impl TryFrom<ProvenanceTrackingConfigRequirementsToml> for ConfigRequirements {
    type Error = ConstraintError;

    fn try_from(toml: ProvenanceTrackingConfigRequirementsToml) -> Result<Self, Self::Error> {
        let ProvenanceTrackingConfigRequirementsToml {
            inner:
                ConfigRequirementsToml {
                    allowed_approval_policies,
                    allowed_sandbox_modes,
                },
            allowed_approval_policies_source,
            allowed_sandbox_modes_source,
        } = toml;

        let approval_policy: Constrained<AskForApproval> = match allowed_approval_policies {
            Some(policies) => {
                let Some(initial_value) = policies.first().copied() else {
                    return Err(ConstraintError::empty_field("allowed_approval_policies"));
                };

                let allowed = format!("{policies:?}");
                let requirement_source = allowed_approval_policies_source;
                Constrained::new(initial_value, move |candidate| {
                    if policies.contains(candidate) {
                        Ok(())
                    } else {
                        Err(ConstraintError::invalid_value_for_field_with_source(
                            "approval_policy",
                            format!("{candidate:?}"),
                            allowed.clone(),
                            requirement_source.clone(),
                        ))
                    }
                })?
            }
            None => Constrained::allow_any_from_default(),
        };

        // TODO(gt): `ConfigRequirementsToml` should let the author specify the
        // default `SandboxPolicy`? Should do this for `AskForApproval` too?
        //
        // Currently, we force ReadOnly as the default policy because two of
        // the other variants (WorkspaceWrite, ExternalSandbox) require
        // additional parameters. Ultimately, we should expand the config
        // format to allow specifying those parameters.
        let default_sandbox_policy = SandboxPolicy::ReadOnly;
        let sandbox_policy: Constrained<SandboxPolicy> = match allowed_sandbox_modes {
            Some(modes) => {
                if !modes.contains(&SandboxModeRequirement::ReadOnly) {
                    return Err(ConstraintError::invalid_value_for_field_with_source(
                        "allowed_sandbox_modes",
                        format!("{modes:?}"),
                        "must include 'read-only' to allow any SandboxPolicy",
                        allowed_sandbox_modes_source,
                    ));
                };

                let allowed = format!("{modes:?}");
                let requirement_source = allowed_sandbox_modes_source;
                Constrained::new(default_sandbox_policy, move |candidate| {
                    let mode = match candidate {
                        SandboxPolicy::ReadOnly => SandboxModeRequirement::ReadOnly,
                        SandboxPolicy::WorkspaceWrite { .. } => {
                            SandboxModeRequirement::WorkspaceWrite
                        }
                        SandboxPolicy::DangerFullAccess => SandboxModeRequirement::DangerFullAccess,
                        SandboxPolicy::ExternalSandbox { .. } => {
                            SandboxModeRequirement::ExternalSandbox
                        }
                    };
                    if modes.contains(&mode) {
                        Ok(())
                    } else {
                        Err(ConstraintError::invalid_value_for_field_with_source(
                            "sandbox_mode",
                            format!("{mode:?}"),
                            allowed.clone(),
                            requirement_source.clone(),
                        ))
                    }
                })?
            }
            None => Constrained::allow_any(default_sandbox_policy),
        };
        Ok(ConfigRequirements {
            approval_policy,
            sandbox_policy,
        })
    }
}

impl TryFrom<ConfigRequirementsToml> for ConfigRequirements {
    type Error = ConstraintError;

    fn try_from(toml: ConfigRequirementsToml) -> Result<Self, Self::Error> {
        ProvenanceTrackingConfigRequirementsToml::from(toml).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RequirementSourceDisplay;
    use anyhow::Result;
    use codex_protocol::protocol::NetworkAccess;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use toml::from_str;

    #[test]
    fn merge_unset_fields_only_fills_missing_values() -> Result<()> {
        let source: ConfigRequirementsToml = from_str(
            r#"
                allowed_approval_policies = ["on-request"]
            "#,
        )?;

        let requirements_toml_file = if cfg!(windows) {
            "C:\\etc\\codex\\requirements.toml"
        } else {
            "/etc/codex/requirements.toml"
        };
        let requirements_toml_file = AbsolutePathBuf::from_absolute_path(requirements_toml_file)?;
        let source_location = RequirementSource::SystemRequirementsToml {
            file: requirements_toml_file,
        };

        let mut empty_target = ProvenanceTrackingConfigRequirementsToml::default();
        empty_target.merge_unset_fields(source_location.clone(), source.clone());
        assert_eq!(
            empty_target.inner.allowed_approval_policies,
            Some(vec![AskForApproval::OnRequest])
        );
        assert_eq!(
            empty_target.allowed_approval_policies_source,
            Some(source_location.clone())
        );

        let existing_source = RequirementSource::LegacyManagedConfigTomlFromMdm;
        let mut populated_target = ProvenanceTrackingConfigRequirementsToml::default();
        let populated_requirements: ConfigRequirementsToml = from_str(
            r#"
                allowed_approval_policies = ["never"]
            "#,
        )?;
        populated_target.merge_unset_fields(existing_source.clone(), populated_requirements);
        populated_target.merge_unset_fields(source_location.clone(), source);
        assert_eq!(
            populated_target.inner.allowed_approval_policies,
            Some(vec![AskForApproval::Never])
        );
        assert_eq!(
            populated_target.allowed_approval_policies_source,
            Some(existing_source)
        );
        Ok(())
    }

    #[test]
    fn constraint_error_includes_requirement_source() -> Result<()> {
        let source: ConfigRequirementsToml = from_str(
            r#"
                allowed_approval_policies = ["on-request"]
                allowed_sandbox_modes = ["read-only"]
            "#,
        )?;

        let requirements_toml_file = if cfg!(windows) {
            "C:\\etc\\codex\\requirements.toml"
        } else {
            "/etc/codex/requirements.toml"
        };
        let requirements_toml_file = AbsolutePathBuf::from_absolute_path(requirements_toml_file)?;
        let source_location = RequirementSource::SystemRequirementsToml {
            file: requirements_toml_file,
        };

        let mut target = ProvenanceTrackingConfigRequirementsToml::default();
        target.merge_unset_fields(source_location.clone(), source);
        let requirements = ConfigRequirements::try_from(target)?;

        assert_eq!(
            requirements.approval_policy.can_set(&AskForApproval::Never),
            Err(ConstraintError::InvalidValue {
                field_name: "approval_policy",
                candidate: "Never".into(),
                allowed: "[OnRequest]".into(),
                requirement_source: RequirementSourceDisplay(Some(source_location.clone())),
            })
        );
        assert_eq!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::DangerFullAccess),
            Err(ConstraintError::InvalidValue {
                field_name: "sandbox_mode",
                candidate: "DangerFullAccess".into(),
                allowed: "[ReadOnly]".into(),
                requirement_source: RequirementSourceDisplay(Some(source_location)),
            })
        );

        Ok(())
    }

    #[test]
    fn deserialize_allowed_approval_policies() -> Result<()> {
        let toml_str = r#"
            allowed_approval_policies = ["untrusted", "on-request"]
        "#;
        let config: ConfigRequirementsToml = from_str(toml_str)?;
        let requirements = ConfigRequirements::try_from(config)?;

        assert_eq!(
            requirements.approval_policy.value(),
            AskForApproval::UnlessTrusted,
            "currently, there is no way to specify the default value for approval policy in the toml, so it picks the first allowed value"
        );
        assert!(
            requirements
                .approval_policy
                .can_set(&AskForApproval::UnlessTrusted)
                .is_ok()
        );
        assert_eq!(
            requirements
                .approval_policy
                .can_set(&AskForApproval::OnFailure),
            Err(ConstraintError::InvalidValue {
                field_name: "approval_policy",
                candidate: "OnFailure".into(),
                allowed: "[UnlessTrusted, OnRequest]".into(),
                requirement_source: RequirementSourceDisplay(None),
            })
        );
        assert!(
            requirements
                .approval_policy
                .can_set(&AskForApproval::OnRequest)
                .is_ok()
        );
        assert_eq!(
            requirements.approval_policy.can_set(&AskForApproval::Never),
            Err(ConstraintError::InvalidValue {
                field_name: "approval_policy",
                candidate: "Never".into(),
                allowed: "[UnlessTrusted, OnRequest]".into(),
                requirement_source: RequirementSourceDisplay(None),
            })
        );
        assert!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::ReadOnly)
                .is_ok()
        );

        Ok(())
    }

    #[test]
    fn deserialize_allowed_sandbox_modes() -> Result<()> {
        let toml_str = r#"
            allowed_sandbox_modes = ["read-only", "workspace-write"]
        "#;
        let config: ConfigRequirementsToml = from_str(toml_str)?;
        let requirements = ConfigRequirements::try_from(config)?;

        let root = if cfg!(windows) { "C:\\repo" } else { "/repo" };
        assert!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::ReadOnly)
                .is_ok()
        );
        assert!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::WorkspaceWrite {
                    writable_roots: vec![AbsolutePathBuf::from_absolute_path(root)?],
                    network_access: false,
                    exclude_tmpdir_env_var: false,
                    exclude_slash_tmp: false,
                })
                .is_ok()
        );
        assert_eq!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::DangerFullAccess),
            Err(ConstraintError::InvalidValue {
                field_name: "sandbox_mode",
                candidate: "DangerFullAccess".into(),
                allowed: "[ReadOnly, WorkspaceWrite]".into(),
                requirement_source: RequirementSourceDisplay(None),
            })
        );
        assert_eq!(
            requirements
                .sandbox_policy
                .can_set(&SandboxPolicy::ExternalSandbox {
                    network_access: NetworkAccess::Restricted,
                }),
            Err(ConstraintError::InvalidValue {
                field_name: "sandbox_mode",
                candidate: "ExternalSandbox".into(),
                allowed: "[ReadOnly, WorkspaceWrite]".into(),
                requirement_source: RequirementSourceDisplay(None),
            })
        );

        Ok(())
    }
}
