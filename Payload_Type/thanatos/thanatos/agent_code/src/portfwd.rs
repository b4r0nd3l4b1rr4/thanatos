use crate::{AgentTask, mythic_success};

pub fn port_forward(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_success!(
        task.id,
        "portfwd delegates to redirect — use redirect command directly or check active jobs"
    ))
}
