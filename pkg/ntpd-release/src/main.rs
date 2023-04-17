use std::{io::Cursor, path::PathBuf};

use async_zip::tokio::read::seek::ZipFileReader;
use octocrab::{
    models::{
        repos::Object,
        workflows::{Run, WorkflowListArtifact},
    },
    params::repos::Reference,
    Page,
};
use serde::{Deserialize, Serialize};
use tokio::fs::{create_dir_all, OpenOptions};

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    github_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tag {
    object: Object,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str(&std::fs::read_to_string("./config.toml")?)?;
    let gh = octocrab::Octocrab::builder()
        .personal_token(config.github_token)
        .build()?;
    // octocrab::initialise(gh);
    println!("Retrieving tag from github");
    let repo = gh.repos("pendulum-project", "ntpd-rs");
    let res = repo.get_ref(&Reference::Tag("v0.3.1".into())).await?;
    let tag: Tag = match res.object {
        Object::Tag { url, .. } => gh.get(url.to_string(), None::<&()>).await?,
        _ => panic!("Could not get tag hash"),
    };
    let commit_hash = match tag.object {
        Object::Commit { sha, .. } => sha,
        _ => panic!("Could not get tag hash"),
    };

    println!("Got hash {}", commit_hash);
    println!("Retrieving workflow runs");

    let mut current_page = Some(
        gh.workflows("pendulum-project", "ntpd-rs")
            .list_runs("pkg.yaml")
            .send()
            .await?,
    );

    println!("Got first page of workflow runs");

    let run: Option<Run> = 'outer: loop {
        let Some(ref mut cp) = current_page else {
            println!("No new page of results found, stopping");
            break None
        };
        for r in cp.take_items() {
            if r.head_commit.id == commit_hash {
                break 'outer Some(r);
            }
        }

        println!("Getting next page of workflow runs");
        current_page = gh.get_page(&cp.next).await?;
    };

    if let Some(r) = run {
        println!(
            "Found run for commit {} - it is {}",
            r.head_commit.id, r.status
        );

        create_dir_all("tmp/artifacts").await?;
        create_dir_all("tmp/result").await?;

        let artifacts_url = r.artifacts_url.to_string().parse().unwrap();

        let artifacts: Page<WorkflowListArtifact> =
            gh.get_page(&Some(artifacts_url)).await?.unwrap();
        for artifact in artifacts {
            println!("Retrieving artifact {}", artifact.name);
            let mut res = gh._get(artifact.archive_download_url.to_string()).await?;
            while res.status().is_redirection() {
                if let Some(location) = res.headers().get("Location") {
                    res = gh._get(location.to_str()?.to_string()).await?;
                }
            }
            let bytes = hyper::body::to_bytes(res.into_body()).await?;
            if bytes.len() == 0 {
                println!("WARN: Retrieved empty artifact, skipping {}", artifact.name);
            } else {
                println!("Writing artifact {} to disk", artifact.name);
                tokio::fs::write(
                    format!("tmp/artifacts/{}.zip", artifact.name),
                    bytes.as_ref(),
                )
                .await?;
                let cursor = Cursor::new(bytes.as_ref());
                let mut zip = ZipFileReader::new(cursor).await?;
                println!("Extracting zip to tmp/result");
                for idx in 0..zip.file().entries().len() {
                    let entry = zip.file().entries().get(idx).unwrap().entry();

                    // we skip directory entries
                    if !entry.filename().ends_with('/') {
                        let target_path = PathBuf::from("tmp/result");
                        let filename = sanitize_file_path(entry.filename());
                        let target_path = target_path.join(filename.file_name().unwrap());

                        let mut entry_reader = zip.entry(idx).await?;
                        let mut writer = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&target_path)
                            .await
                            .expect("Failed to create extracted file");
                        tokio::io::copy(&mut entry_reader, &mut writer).await?;
                    }
                }
            }

            // let data = bytes.into_iter().collect::<Vec<u8>>();
        }
    }

    Ok(())
}

/// Returns a relative path without reserved names, redundant separators, ".", or "..".
fn sanitize_file_path(path: &str) -> PathBuf {
    // Replaces backwards slashes
    path.replace('\\', "/")
        // Sanitizes each component
        .split('/')
        .map(sanitize_filename::sanitize)
        .collect()
}
