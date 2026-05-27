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


class EclipseArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="binary_path",
                cli_name="BinaryPath",
                display_name="Binary Path",
                type=ParameterType.String,
                description="Path to binary to spawn with hijacked activation context",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="manifest",
                cli_name="Manifest",
                display_name="Activation Context Manifest",
                type=ParameterType.String,
                description="XML manifest for activation context (redirects DLL loading)",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)


class EclipseCommand(CommandBase):
    cmd = "actx_hijack"
    needs_admin = False
    help_cmd = "actx_hijack [binary_path] [manifest]"
    description = "Hijack process activation context to redirect DLL loading via custom manifest. Based on Eclipse by @Kudaes."
    version = 1
    author = "OFSTeam (@Kudaes/Eclipse)"
    argument_class = EclipseArguments
    attackmapping = ["T1574.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        binary_path = task.args.get_arg("binary_path")
        task.display_params = f"Hijack activation context: {binary_path}"
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
