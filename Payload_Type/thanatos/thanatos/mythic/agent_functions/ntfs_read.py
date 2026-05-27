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


class NtfsReadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                description="Action to perform: read_file, list_dir, show_deleted",
                choices=["read_file", "list_dir", "show_deleted"],
                default_value="list_dir",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="volume",
                cli_name="Volume",
                display_name="Volume",
                type=ParameterType.String,
                description="Volume to target (default: \\\\.\\C:)",
                default_value="\\\\.\\C:",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="directory",
                cli_name="Directory",
                display_name="Directory",
                type=ParameterType.String,
                description="Directory path (default: \\)",
                default_value="\\",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="filename",
                cli_name="Filename",
                display_name="Filename",
                type=ParameterType.String,
                description="Filename (required for read_file action)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        elif self.command_line:
            # Simple command line parsing
            parts = self.command_line.split()
            if len(parts) >= 1:
                self.add_arg("action", parts[0])
            if len(parts) >= 2:
                self.add_arg("directory", parts[1])
            if len(parts) >= 3:
                self.add_arg("filename", parts[2])


class NtfsReadCommand(CommandBase):
    cmd = "ntfs_read"
    needs_admin = True
    help_cmd = "ntfs_read [action] [directory] [filename]"
    description = "Read files and directories directly from NTFS MFT. Bypasses file system APIs. Requires admin."
    version = 1
    author = "OFSTeam (@Kudaes/MFTool)"
    argument_class = NtfsReadArguments
    attackmapping = ["T1005", "T1003.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        action = task.args.get_arg("action")
        directory = task.args.get_arg("directory")
        filename = task.args.get_arg("filename")

        if action == "read_file" and filename:
            task.display_params = f"{action}: {directory}\\{filename}"
        elif action == "list_dir":
            task.display_params = f"{action}: {directory}"
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
