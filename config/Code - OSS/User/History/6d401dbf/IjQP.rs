use common::messages::{AgentMessage, Message, ServerMessage};
use common::task::TaskResult;
use common::{error::AgentError, task::Task};
use failure::Error;
use local_encoding_ng::{Encoder, Encoding};
use sha2::Digest;
use std::sync::Arc;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

use crate::https::Connection;
use crate::storage::Storage;

#[allow(dead_code)]
pub struct TaskExecute<'a> {
    task: &'a Task,
    conn: &'a Connection,
    storage: &'a Storage,
}

impl<'a> TaskExecute<'a> {
    pub fn new(task: &'a Task, conn: &'a Connection, storage: &'a Storage) -> Self {
        TaskExecute {
            task,
            conn,
            storage,
        }
    }

    pub async fn update(self) -> Result<TaskExecute<'a>, AgentError> {
        if !self.storage.exists_dir(&self.task.uuid)? {
            self.storage.create_dir(&self.task.uuid)?;
        }

        for dep in self.task.deps.iter() {
            if !self.storage.exists_file(&self.task.uuid, &dep.name, &dep.hash)? {
                let message = Message::Agent(AgentMessage::DownloadRequest(dep.uuid.clone()));
                let data = match self.conn.post_message("download", &message).await? {
                    ServerMessage::DownloadResponse(data) => data,
                    sm => return Err(AgentError::ErrorMessage(format!("Invalid Server Message:")))
                };

                let mut hasher = sha2::Sha256::new();
                hasher.update(&data);
                let result = hasher.finalize();

                if result[..] != dep.hash {
                    return Err(AgentError::ErrorStaticMessage("Invalid hash"));
                }

                self.storage.create_file(&self.task.uuid, &dep.name, &data)?
            }
        }

        Ok(self)
    }

    pub async fn run(&self) -> Result<TaskResult, AgentError> {
        let (command, args) = self.task.argv.split_at(1);
        let timeout = if self.task.timeout == 0 {1} else {self.task.timeout};

        println!("Executing {} {:?}", command[0], args); // Should we log it?
        let current_dir = std::env::current_dir()?;

        let new_process = Command::new(&command[0])
            .args(args)
            .current_dir(&self.task.uuid)
            .stdout(Stdio::piped())
            .spawn();

        if new_process.is_err() {
            return Err(AgentError::ErrorStaticMessage("Failed to create child process").into());
        }

        let mut result: TaskResult = TaskResult::default();
        let mut stdout_buffer = String::new();
    
        let mut child_process = new_process.unwrap();
        let pid = child_process.id();
        log::info!("process pid {:?}", pid);
        let timeout_seconds = Duration::from_secs(timeout);
        let status_code = match child_process.wait_timeout(timeout_seconds).unwrap() {
            Some(status) => {
                let mut bytes: Vec<u8> = Vec::new();
    
                child_process
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
    
                stdout_buffer = Encoding::OEM.to_string(bytes.as_slice()).unwrap();
    
                status.code()
            }
            None => {
                child_process.kill().unwrap();
                child_process.wait().unwrap().code()
            }
        };
    
        result.retval = status_code.unwrap();
        result.stdout = stdout_buffer;
        result.uuid = self.task.uuid.clone();
    
        Ok(result)
    }
    pub fn async interrupt(&self)
}

#[allow(dead_code)]
pub fn execute_command(command: &str, args: &[String], timeout: u64) -> Result<TaskResult, Error> {
    println!("Executing {} {:?}", command, args); // Should we log it?

    let new_process = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .spawn();

    if new_process.is_err() {
        return Err(AgentError::ErrorStaticMessage("Failed to create child process").into());
    }

    let mut result: TaskResult = TaskResult::default();
    let mut stdout_buffer = String::new();

    let mut child_process = new_process.unwrap();
    let timeout_seconds = Duration::from_secs(timeout);
    let status_code = match child_process.wait_timeout(timeout_seconds).unwrap() {
        Some(status) => {
            let mut bytes: Vec<u8> = Vec::new();

            child_process
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();

            stdout_buffer = Encoding::OEM.to_string(bytes.as_slice()).unwrap();

            status.code()
        }
        None => {
            child_process.kill().unwrap();
            child_process.wait().unwrap().code()
        }
    };

    result.retval = status_code.unwrap();
    result.stdout = stdout_buffer;

    Ok(result)
}
