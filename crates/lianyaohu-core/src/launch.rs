use crate::{Result, err};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_LAUNCH_SPEC_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaunchSpec {
    pub command: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
    pub sandbox_profile: String,
}

impl LaunchSpec {
    pub fn new(
        command: Vec<String>,
        cwd: impl Into<String>,
        environment: BTreeMap<String, String>,
        sandbox_profile: impl Into<String>,
    ) -> Self {
        Self {
            command,
            cwd: cwd.into(),
            environment,
            sandbox_profile: sandbox_profile.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.command.is_empty() {
            return Err(err("launch spec command is empty"));
        }
        if self.cwd.is_empty() {
            return Err(err("launch spec cwd is empty"));
        }
        if self.sandbox_profile.is_empty() {
            return Err(err("launch spec sandbox profile is empty"));
        }
        Ok(())
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let json = serde_json::to_vec(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn read_json(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_LAUNCH_SPEC_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LAUNCH_SPEC_BYTES {
            return Err(err("launch spec is too large"));
        }
        let spec = serde_json::from_slice::<Self>(&bytes)?;
        spec.validate()?;
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_spec_round_trips_json() {
        let spec = LaunchSpec::new(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            "/tmp",
            BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
            "(version 1)",
        );

        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(serde_json::from_str::<LaunchSpec>(&json).unwrap(), spec);
    }

    #[test]
    fn launch_spec_rejects_empty_command() {
        let spec = LaunchSpec::new(Vec::new(), "/tmp", BTreeMap::new(), "(version 1)");

        assert!(spec.validate().is_err());
    }
}
