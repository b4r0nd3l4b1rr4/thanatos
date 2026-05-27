from mythic_container.MythicCommandBase import (
    TaskArguments,
    CommandBase,
    CommandAttributes,
    SupportedOS,
    CommandParameter,
    ParameterGroupInfo,
    ParameterType,
    MythicTask,
)
from mythic_container.MythicGoRPC import (
    SendMythicRPCResponseCreate,
    MythicRPCResponseCreateMessage,
)
from mythic_container.MythicRPC import MythicRPCFileCreate, MythicRPCFileSearch
from mythic_container.PayloadBuilder import PTTaskCreateTaskingMessageResponse


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
                description="Encrypt PE in memory during sleep (evasion feature only)",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
        else:
            pass

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class StealthSleepCommand(CommandBase):
    cmd = "stealth_sleep"
    needs_admin = False
    help_cmd = "stealth_sleep"
    description = "Obfuscated sleep that encrypts the PE image in memory during sleep (requires evasion feature)"
    version = 1
    author = "@B4r0n"
    argument_class = StealthSleepArguments
    attackmapping = ["T1497.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: MythicTask) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: MythicTask, response: any) -> MythicTask:
        pass


class NtfsReadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="volume",
                type=ParameterType.String,
                default_value="C",
                description="NTFS volume letter (e.g., C, D)",
                parameter_group_info=[ParameterGroupInfo(ui_position=1)],
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to read from NTFS",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
        else:
            pass

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class NtfsReadCommand(CommandBase):
    cmd = "ntfs_read"
    needs_admin = True
    help_cmd = "ntfs_read"
    description = "Read files directly from NTFS volume bypassing OS file handles (requires advanced_collection feature)"
    version = 1
    author = "@B4r0n"
    argument_class = NtfsReadArguments
    attackmapping = ["T1005", "T1003.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicTask) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: MythicTask, response: any) -> MythicTask:
        pass


class MinifilterEvadeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["enable", "disable"],
                description="Enable or disable minifilter evasion",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("action", self.command_line.strip())
        else:
            pass

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class MinifilterEvadeCommand(CommandBase):
    cmd = "minifilter_evade"
    needs_admin = True
    help_cmd = "minifilter_evade [enable|disable]"
    description = "Enable or disable minifilter driver evasion (requires minifilter_evasion feature)"
    version = 1
    author = "@B4r0n"
    argument_class = MinifilterEvadeArguments
    attackmapping = ["T1562.006"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: MythicTask) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: MythicTask, response: any) -> MythicTask:
        pass
