# Sleep obfuscation via Shelter by @Kudaes (https://github.com/Kudaes/Shelter)
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class StealthSleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                default_value=5,
                description="Sleep interval in seconds",
                parameter_group_info=[ParameterGroupInfo(ui_position=1)],
            ),
            CommandParameter(
                name="encrypt_pe",
                type=ParameterType.Boolean,
                default_value=True,
                description="Encrypt PE in memory during sleep (requires evasion feature)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    self.add_arg("interval", int(self.command_line.strip()))
                except ValueError:
                    raise Exception("Interval must be a number")


class StealthSleepCommand(CommandBase):
    cmd = "stealth_sleep"
    needs_admin = False
    help_cmd = "stealth_sleep -interval <seconds> [-encrypt_pe true]"
    description = "Obfuscated sleep that encrypts the PE in memory during sleep interval (Shelter by @Kudaes)."
    version = 1
    author = "b4r0n"
    argument_class = StealthSleepArguments
    attackmapping = ["T1497.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        interval = taskData.args.get_arg("interval")
        resp.DisplayParams = f"-interval {interval}"
        return resp

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
