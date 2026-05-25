from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class PortfwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bindhost",
                type=ParameterType.String,
                description="Bind host address",
                display_name="Bind host address",
                default_value="0.0.0.0",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="bindport",
                type=ParameterType.Number,
                description="Bind port",
                display_name="Bind port",
                default_value=8080,
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="connecthost",
                type=ParameterType.String,
                description="Connect host address",
                display_name="Connect host address",
                default_value="127.0.0.1",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
            CommandParameter(
                name="connectport",
                type=ParameterType.Number,
                description="Connect port",
                display_name="Connect port",
                default_value=80,
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                connection = self.command_line.split(":")
                if len(connection) == 4:
                    self.set_arg("bindhost", connection[0])
                    self.set_arg("bindport", int(connection[1]))
                    self.set_arg("connecthost", connection[2])
                    self.set_arg("connectport", int(connection[3]))
                elif len(connection) == 3:
                    self.set_arg("bindhost", "0.0.0.0")
                    self.set_arg("bindport", int(connection[0]))
                    self.set_arg("connecthost", connection[1])
                    self.set_arg("connectport", int(connection[2]))
                else:
                    raise Exception("Invalid format. Use bindhost:bindport:connecthost:connectport or bindport:connecthost:connectport")
        else:
            raise ValueError("No arguments provided")


class PortfwdCommand(CommandBase):
    cmd = "portfwd"
    needs_admin = False
    help_cmd = "portfwd -bindhost [host] -bindport [port] -connecthost [host] -connectport [port]"
    description = "Port forwarding alias for redirect. Sets up a TCP redirector on the machine."
    version = 1
    author = "@M_alphaaa"
    argument_class = PortfwdArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

        bindhost = taskData.args.get_arg("bindhost")
        bindport = taskData.args.get_arg("bindport")
        connecthost = taskData.args.get_arg("connecthost")
        connectport = taskData.args.get_arg("connectport")

        resp.DisplayParams = f"{bindhost}:{bindport} => {connecthost}:{connectport}"

        create_resp = await SendMythicRPCTaskCreate(
            MythicRPCTaskCreateMessage(
                TaskID=taskData.Task.ID,
                CommandName="redirect",
                Parameters=json.dumps({
                    "bindhost": bindhost,
                    "bindport": bindport,
                    "connecthost": connecthost,
                    "connectport": connectport,
                }),
                CallbackID=taskData.Callback.ID,
            )
        )

        if not create_resp.Success:
            resp.Success = False
            resp.TaskStatus = MythicStatus.Error
            resp.Stderr = create_resp.Error or "Failed to create redirect task"
        else:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"Forwarding {bindhost}:{bindport} => {connecthost}:{connectport} (via redirect)".encode(),
                )
            )

        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
