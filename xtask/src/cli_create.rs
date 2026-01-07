use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn create_codemod(target_dir: Option<PathBuf>) -> Result<()> {
    // Get the workspace root
    let xtask_path = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| anyhow::anyhow!("Cannot find CARGO_MANIFEST_DIR"))?;

    let workspace_root = Path::new(&xtask_path).parent().unwrap();

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("codemod")
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .arg("--");
    cmd.arg("init");

    // If target_dir is specified, use it as the path and set it as current_dir
    // Otherwise, use "./" as the path
    if let Some(ref dir) = target_dir {
        cmd.arg(".").current_dir(dir);
    } else {
        cmd.arg("./");
    }

    cmd.arg("--name")
        .arg("my-codemod")
        .arg("--project-type")
        .arg("ast-grep-js")
        .arg("--package-manager")
        .arg("npm")
        .arg("--language")
        .arg("js")
        .arg("--author")
        .arg("Codemod")
        .arg("--description")
        .arg("migrations template")
        .arg("--license")
        .arg("MIT")
        .arg("--workspace")
        .arg("--github-action")
        .arg("--no-interactive")
        .arg("--force");

    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "codemod init failed with exit code: {:?}",
            status.code()
        ));
    }

    Ok(())
}
