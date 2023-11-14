use super::schema::{agents, deps, history, tasks};
use common::hostinfo::HostInfo;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Queryable, Insertable, Selectable, Serialize)]
#[diesel(table_name = agents)]
pub struct AgentRow {
    pub uuid: String,
    pub os: String,
    pub platform: String,
    #[serde(skip_serializing)]
    pub selfkey: String,
    #[serde(skip_serializing)]
    pub peerkey: String,
    pub hostname: String,
    pub domain: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Queryable, Insertable, Selectable, Serialize)]
#[diesel(table_name = tasks)]
pub struct TaskRow {
    pub uuid: String,
    pub name: String,
    pub argv: String, // semicolon separated list
    pub deps: String, // semicolon separated list
    pub timeout: i32,
    pub pid: i32,
}

#[derive(Debug, Deserialize, Queryable, Insertable, Selectable, Serialize)]
#[diesel(table_name = deps)]
pub struct DepRow {
    pub uuid: String,
    pub hash: Vec<u8>,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Queryable, Insertable, Selectable)]
#[diesel(table_name = history)]
pub struct HistoryRow {
    pub id: Option<i32>,
    pub agent_id: String,
    pub task_id: String,
    pub timestamp: String,
    pub status: Option<i32>,
    pub result: Option<String>,
}

impl AgentRow {
    fn is_valid_host(&self, host: &HostInfo) -> bool {
        (self.domain.is_empty() | (self.domain.to_lowercase() == host.domain.to_lowercase()))
            & (self.hostname.is_empty()
                | (self.hostname.to_lowercase() == host.hostname.to_lowercase()))
    }

    pub fn check_host(&self, host: &HostInfo) -> Result<(), String> {
        if self.is_valid_host(host) {
            Ok(())
        } else {
            Err(format!(
                "Access denied: host does not match: {:?} != {:?}",
                (&self.hostname, &self.domain),
                (&host.hostname, &host.domain)
            ))
        }
    }
}
