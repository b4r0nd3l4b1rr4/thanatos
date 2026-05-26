from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class C2InfoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class C2InfoCommand(CommandBase):
    cmd = "c2info"
    needs_admin = False
    help_cmd = "c2info"
    description = "Show current C2 configuration (callback host, interval, jitter, killdate)."
    version = 1
    author = "b4r0n"
    argument_class = C2InfoArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
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


class KilldateArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["get", "set"],
                description="Get or set the killdate.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="date",
                cli_name="date",
                display_name="Date",
                type=ParameterType.String,
                description="Date in YYYY-MM-DD format (required for set action).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must specify an action (get or set).")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            self.add_arg("action", parts[0])
            if len(parts) > 1:
                self.add_arg("date", parts[1])


class KilldateCommand(CommandBase):
    cmd = "killdate"
    needs_admin = False
    help_cmd = "killdate -action <get|set> [-date YYYY-MM-DD]"
    description = "Get or set the agent killdate."
    version = 1
    author = "b4r0n"
    argument_class = KilldateArguments
    attackmapping = []
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        action = taskData.args.get_arg("action")
        date_val = taskData.args.get_arg("date")
        if date_val:
            resp.DisplayParams = f"-action {action} -date {date_val}"
        else:
            resp.DisplayParams = f"-action {action}"
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
